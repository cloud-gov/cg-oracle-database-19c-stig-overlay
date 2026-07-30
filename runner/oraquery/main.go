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
package main

import (
	"bufio"
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

	// TCPS (2484) → SSL on; else plain TCP. The resource passes the port; the
	// caller selects 2484 for TLS. urlOptions lets us flip SSL by port.
	opts := map[string]string{}
	if port == "2484" {
		opts["SSL"] = "true"
		// server-cert verification is enforced by the CA/DN in the real (RDS)
		// run via wallet/urlOptions; local 23ai uses plain TCP (1521).
	}
	url := go_ora.BuildUrl(host, mustAtoi(port), service, user, pass, opts)

	db, err := sql.Open("oracle", url)
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

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		fail("bad port: " + s)
	}
	return n
}
