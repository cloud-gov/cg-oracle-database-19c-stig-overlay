// oraquery — a minimal, license-clean Oracle query tool that is a drop-in for the
// client binary InSpec's `oracledb_session` shells out to (pointed at via
// sqlplus_bin/sqlcl_bin). It exists to REPLACE sqlplus (Instant Client, OTN EULA —
// not redistributable in a public image) and sqlcl (whose CSV output breaks
// Ruby's stdlib CSV.parse in the resource). Because we control the output here,
// we emit exactly the clean CSV the resource's parse_csv_result expects.
//
// Driver: github.com/sijms/go-ora/v2 — pure Go, MIT, CGO_ENABLED=0, TCP/TCPS.
// Already vetted + shipped in the aws-broker RDS smoke test.
//
// Invocation contract (from cinc-auditor oracledb_session.rb command_builder):
//
//	<oraquery> user/password@host:port/service   (SQL text arrives on stdin,
//	                                               wrapped in set-options + EXIT)
//
// stdout: CSV — a header row then data rows, comma-delimited, quoted only when a
// field contains a comma/quote/newline (encoding/csv defaults). No banners.
// On error: non-zero exit + message on stderr (the resource treats non-zero /
// a leading "error" as a failed query).
//
// TLS is controlled by explicit environment intent, never inferred from the port
// (#16 / #20):
//
//	ORAQUERY_TLS=verify-ca (default) — TLS + server-certificate verification.
//	    Requires ORAQUERY_CA_BUNDLE (a PEM CA bundle, e.g. the AWS GovCloud RDS
//	    root CA). Fails closed if the bundle is missing/empty/invalid.
//	ORAQUERY_TLS=require            — TLS without verification (encrypt-only; not
//	    MITM-safe; not compliance evidence).
//	ORAQUERY_TLS=disable           — plaintext (local dev DB only; credential is
//	    sent in the clear).
//
// The PEM is loaded into an x509 pool and injected via OracleConnector.WithTLSConfig
// — NOT go-ora's "WALLET" url-option, which requires an Oracle wallet directory
// (cwallet.sso/ewallet.p12) and rejects a PEM bundle.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/csv"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	go_ora "github.com/sijms/go-ora/v2"
)

// connString parses the resource's `user/password@host:port/service` argument.
// Password may itself contain no '@' (Oracle creds rarely do; the resource does
// not quote it). We split on the LAST '@' to be safe.
var connRe = regexp.MustCompile(`^(.*?)/(.*)@([^:/]+):(\d+)/(.+)$`)

func fail(msg string) {
	// Leading "error" (any case) + non-zero is how the resource detects failure.
	fmt.Fprintln(os.Stderr, "error: "+msg)
	os.Exit(1)
}

// redactArgs masks the password in any user/pw@host connect string for logging.
func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if m := connRe.FindStringSubmatch(a); m != nil {
			out[i] = m[1] + "/***@" + m[3] + ":" + m[4] + "/" + m[5]
		} else {
			out[i] = a
		}
	}
	return out
}

// usage/args note: the resource calls `oraquery [-S] user/pw@host:port/service`
// (mirroring sqlplus) and pipes the SQL heredoc on stdin.

// extractQuery pulls the real SQL out of the heredoc the resource sends on stdin:
//
//	set sqlformat csv / SET FEEDBACK OFF / <the query>; / EXIT
//
// We drop SET* and EXIT lines and keep the rest, trimming a trailing ';'.
func extractQuery(r *bufio.Reader) string {
	var b strings.Builder
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		up := strings.ToUpper(trimmed)
		if up == "" || up == "EXIT" || strings.HasPrefix(up, "SET ") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	q := strings.TrimSpace(b.String())
	q = strings.TrimSuffix(q, ";")
	return q
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: oraquery user/password@host:port/service  (SQL on stdin)")
	}
	// The InSpec resource invokes us like sqlplus: `oraquery -S user/pw@host:port/svc`
	// (sqlplus path appends "-S"). Scan all args for the first one that matches the
	// connect-string shape; ignore flags like -S / -s / /nolog.
	var connArg string
	for _, a := range os.Args[1:] {
		if connRe.MatchString(a) {
			connArg = a
			break
		}
	}
	if connArg == "" {
		fail("no connect string (user/password@host:port/service) found in args: " + strings.Join(redactArgs(os.Args[1:]), " "))
	}
	m := connRe.FindStringSubmatch(connArg)
	user, pass, host, port, service := m[1], m[2], m[3], m[4], m[5]

	// TLS is driven by explicit intent (ORAQUERY_TLS), NOT by the port number.
	// This is the fix for #16/#20: a plaintext connection (which sends the DB
	// credential in the clear) must never happen implicitly just because the
	// port isn't 2484 — it requires an explicit, documented opt-in.
	plan, err := planTLS(
		os.Getenv("ORAQUERY_TLS"),
		os.Getenv("ORAQUERY_CA_BUNDLE"),
	)
	if err != nil {
		fail(err.Error())
	}
	url := go_ora.BuildUrl(host, mustAtoi(port), service, user, pass, plan.urlOptions)

	db, err := openDB(url, host, plan)
	if err != nil {
		fail("open: " + err.Error())
	}
	defer db.Close()

	query := extractQuery(bufio.NewReader(os.Stdin))
	if query == "" {
		fail("no query provided on stdin")
	}

	rows, err := db.Query(query)
	if err != nil {
		fail("query: " + err.Error())
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		fail("columns: " + err.Error())
	}

	w := csv.NewWriter(os.Stdout)
	// Header row — the resource lowercases headers itself (header_converters),
	// so case here is cosmetic; emit as the DB returns them.
	if err := w.Write(cols); err != nil {
		fail("write header: " + err.Error())
	}

	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			fail("scan: " + err.Error())
		}
		rec := make([]string, len(cols))
		for i, v := range vals {
			rec[i] = toStr(v)
		}
		if err := w.Write(rec); err != nil {
			fail("write row: " + err.Error())
		}
	}
	if err := rows.Err(); err != nil {
		fail("rows: " + err.Error())
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fail("flush: " + err.Error())
	}
}

func toStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

// tlsPlan is the outcome of resolving ORAQUERY_TLS: the go-ora url options plus,
// for the verifying path, a *tls.Config carrying the PEM-loaded root pool that
// must be injected via OracleConnector.WithTLSConfig (go-ora's WALLET option
// cannot consume a PEM — see planTLS).
type tlsPlan struct {
	urlOptions map[string]string
	tlsConfig  *tls.Config // nil unless a verified-TLS pool was built
}

// planTLS turns the explicit TLS intent (ORAQUERY_TLS) into a connection plan,
// failing closed rather than ever silently downgrading to a plaintext
// connection (#16 / #20).
//
// Modes (case-insensitive):
//
//	verify-ca (DEFAULT) — TLS with server-certificate verification. Requires a
//	    PEM CA bundle (ORAQUERY_CA_BUNDLE), e.g. the AWS GovCloud RDS root CA.
//	    The PEM is loaded into an x509 pool and returned as a *tls.Config for
//	    WithTLSConfig. Fails closed if the bundle is missing, unreadable, or
//	    contains no usable certificate.
//	require — TLS WITHOUT server-cert verification (SSL VERIFY=false). Encrypts
//	    the credential on the wire but does NOT authenticate the server, so it is
//	    NOT MITM-safe and NOT compliance evidence. Allowed only when explicitly
//	    requested.
//	disable — plaintext. Sends the DB credential in the clear. Must be requested
//	    explicitly; intended only for a local dev DB (e.g. gvenzl 23ai on 1521).
//
// An empty ORAQUERY_TLS defaults to verify-ca so the safe path is the default
// and the insecure paths are opt-in.
//
// NOTE on go-ora: the WALLET url-option is NOT used. It expects an Oracle wallet
// directory (cwallet.sso/ewallet.p12, magic-byte validated) and rejects a PEM.
// AWS RDS publishes its root CA only as a PEM, so we trust it via a *tls.Config
// RootCAs pool injected through WithTLSConfig instead.
func planTLS(tlsMode, caBundlePath string) (tlsPlan, error) {
	plan := tlsPlan{urlOptions: map[string]string{}}

	mode := strings.ToLower(strings.TrimSpace(tlsMode))
	if mode == "" {
		mode = "verify-ca"
	}

	switch mode {
	case "verify-ca":
		if strings.TrimSpace(caBundlePath) == "" {
			return tlsPlan{}, fmt.Errorf(
				"ORAQUERY_TLS=verify-ca requires ORAQUERY_CA_BUNDLE (path to a PEM CA bundle, " +
					"e.g. the AWS GovCloud RDS root CA); refusing to connect without server-certificate " +
					"verification (set ORAQUERY_TLS=require to skip verification, or " +
					"ORAQUERY_TLS=disable for a local plaintext dev DB)")
		}
		pool, err := loadCABundle(caBundlePath)
		if err != nil {
			return tlsPlan{}, err
		}
		plan.urlOptions["SSL"] = "true"
		// SSL VERIFY defaults to true in go-ora; set it explicitly so intent is clear.
		plan.urlOptions["SSL VERIFY"] = "true"
		// ServerName is set to the connect host at openDB time (we don't have it here).
		plan.tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			// InsecureSkipVerify stays false — the whole point of verify-ca.
		}
	case "require":
		// Encrypt-only: server identity is NOT verified. Insecure against MITM;
		// never valid as compliance evidence. Explicit opt-in only.
		plan.urlOptions["SSL"] = "true"
		plan.urlOptions["SSL VERIFY"] = "false"
	case "disable":
		// Plaintext — credential travels in the clear. Local dev only.
	default:
		return tlsPlan{}, fmt.Errorf("unknown ORAQUERY_TLS mode %q (want: verify-ca, require, or disable)", tlsMode)
	}

	return plan, nil
}

// loadCABundle reads a PEM CA bundle from disk into an x509 pool, failing closed
// if the file is unreadable or contains no usable certificate (so a truncated or
// wrong-format bundle can never silently produce an empty, everything-fails —
// or worse, everything-passes — trust set).
func loadCABundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ORAQUERY_CA_BUNDLE %q: %v", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ORAQUERY_CA_BUNDLE %q: no PEM certificates found (expected a CA bundle)", path)
	}
	return pool, nil
}

// openDB opens the go-ora connection, injecting the verified-TLS config (with the
// server name pinned to the connect host) when planTLS built one; otherwise it
// opens with the url options alone (require/disable paths).
func openDB(url, host string, plan tlsPlan) (*sql.DB, error) {
	if plan.tlsConfig == nil {
		return sql.Open("oracle", url)
	}
	cfg := plan.tlsConfig.Clone()
	cfg.ServerName = host
	connector := go_ora.NewConnector(url).(*go_ora.OracleConnector)
	connector.WithTLSConfig(cfg)
	return sql.OpenDB(connector), nil
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		fail("bad port: " + s)
	}
	return n
}
