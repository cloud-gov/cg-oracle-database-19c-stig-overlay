package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestConnRe covers the connect-string regex the resource passes as
// user/password@host:port/service. Passwords may contain awkward characters;
// the regex splits on the LAST '@' and the FIRST ':'/'/' of the host section.
func TestConnRe(t *testing.T) {
	cases := []struct {
		name                            string
		in                              string
		match                           bool
		user, pass, host, port, service string
	}{
		{
			name:  "simple",
			in:    "system/devpw@oracle:1521/FREEPDB1",
			match: true,
			user:  "system", pass: "devpw", host: "oracle", port: "1521", service: "FREEPDB1",
		},
		{
			name:  "tcps port",
			in:    "master/s3cr3t@db.example.gov:2484/ORCL",
			match: true,
			user:  "master", pass: "s3cr3t", host: "db.example.gov", port: "2484", service: "ORCL",
		},
		{
			name:  "password with slash",
			in:    "u/p/w@h:1521/s",
			match: true,
			// user is non-greedy up to first '/', pass is greedy to last '@'.
			user: "u", pass: "p/w", host: "h", port: "1521", service: "s",
		},
		{
			name:  "service with slash-like suffix",
			in:    "u/p@h:1521/PDB1.sub.vcn",
			match: true,
			user:  "u", pass: "p", host: "h", port: "1521", service: "PDB1.sub.vcn",
		},
		{name: "missing port", in: "u/p@h/s", match: false},
		{name: "non-numeric port", in: "u/p@h:abc/s", match: false},
		{name: "flag not a conn string", in: "-S", match: false},
		{name: "empty", in: "", match: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := connRe.FindStringSubmatch(c.in)
			if c.match != (m != nil) {
				t.Fatalf("match = %v, want %v (in=%q)", m != nil, c.match, c.in)
			}
			if !c.match {
				return
			}
			got := struct{ user, pass, host, port, service string }{m[1], m[2], m[3], m[4], m[5]}
			want := struct{ user, pass, host, port, service string }{c.user, c.pass, c.host, c.port, c.service}
			if got != want {
				t.Errorf("parsed = %+v, want %+v", got, want)
			}
		})
	}
}

// TestRedactArgs ensures the password is masked while the rest of the connect
// string (and non-conn args) survive for logging.
func TestRedactArgs(t *testing.T) {
	in := []string{"-S", "system/devpw@oracle:1521/FREEPDB1", "--other"}
	got := redactArgs(in)
	want := []string{"-S", "system/***@oracle:1521/FREEPDB1", "--other"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("redactArgs = %v, want %v", got, want)
	}
	// The real password must not appear anywhere in the redacted output.
	if strings.Contains(strings.Join(got, " "), "devpw") {
		t.Error("redactArgs leaked the password")
	}
}

// TestExtractQuery covers stripping the SET*/EXIT scaffolding the InSpec
// resource wraps around the real SQL, and trimming a trailing ';'.
func TestExtractQuery(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "typical heredoc",
			in:   "set sqlformat csv\nSET FEEDBACK OFF\nSELECT limit FROM SYS.DBA_PROFILES;\nEXIT\n",
			want: "SELECT limit FROM SYS.DBA_PROFILES",
		},
		{
			name: "lowercase exit and mixed set",
			in:   "SET HEADING OFF\nselect 1 from dual;\nexit\n",
			want: "select 1 from dual",
		},
		{
			name: "multi-line query preserved",
			in:   "SET FEEDBACK OFF\nSELECT a,\n       b\nFROM t;\nEXIT\n",
			want: "SELECT a,\n       b\nFROM t",
		},
		{
			name: "no trailing semicolon",
			in:   "SELECT 1 FROM dual\nEXIT\n",
			want: "SELECT 1 FROM dual",
		},
		{
			name: "blank lines dropped",
			in:   "\n\nSELECT 1 FROM dual;\n\nEXIT\n",
			want: "SELECT 1 FROM dual",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractQuery(bufio.NewReader(strings.NewReader(c.in)))
			if got != c.want {
				t.Errorf("extractQuery =\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

// TestToStr covers the column-value stringification the CSV writer relies on,
// including the []byte case (go-ora often returns text/number columns as bytes)
// and nil (NULL) → empty string.
func TestToStr(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil is empty", nil, ""},
		{"bytes", []byte("UNLIMITED"), "UNLIMITED"},
		{"string", "DEFAULT", "DEFAULT"},
		{"int", 10, "10"},
		{"int64", int64(2484), "2484"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := toStr(c.in); got != c.want {
				t.Errorf("toStr(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestMustAtoi covers the valid path only. mustAtoi calls fail()→os.Exit on
// invalid input by design (a bad port is unrecoverable), which cannot be
// asserted in-process without exiting the test binary; the connRe regex already
// guarantees the port is all-digits before mustAtoi is reached.
func TestMustAtoi(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0", 0},
		{"1521", 1521},
		{"2484", 2484},
	}
	for _, c := range cases {
		if got := mustAtoi(c.in); got != c.want {
			t.Errorf("mustAtoi(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestPlanTLS covers the explicit-intent TLS logic (#16 / #20): the default is
// verified TLS, verify-ca fails closed without a CA bundle, the insecure paths
// are opt-in only, and TLS is never inferred from the port. It uses a self-signed
// fixture PEM written to a temp file (no real RDS CA is required for the unit test).
func TestPlanTLS(t *testing.T) {
	caPath := writeTestCABundle(t)

	t.Run("default (empty) is verify-ca and fails closed without a CA bundle", func(t *testing.T) {
		_, err := planTLS("", "")
		if err == nil {
			t.Fatal("expected fail-closed error when defaulting to verify-ca with no CA bundle, got nil")
		}
		if !strings.Contains(err.Error(), "ORAQUERY_CA_BUNDLE") {
			t.Errorf("error should mention the missing CA bundle, got: %v", err)
		}
	})

	t.Run("verify-ca with a valid PEM bundle sets verified TLS + builds a RootCAs pool", func(t *testing.T) {
		plan, err := planTLS("verify-ca", caPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if plan.urlOptions["SSL"] != "true" || plan.urlOptions["SSL VERIFY"] != "true" {
			t.Errorf("verify-ca url options = %v, want SSL=true SSL VERIFY=true", plan.urlOptions)
		}
		if _, ok := plan.urlOptions["WALLET"]; ok {
			t.Errorf("must NOT set go-ora WALLET option for a PEM bundle, got %v", plan.urlOptions)
		}
		if plan.tlsConfig == nil {
			t.Fatal("verify-ca must build a *tls.Config, got nil")
		}
		if plan.tlsConfig.InsecureSkipVerify {
			t.Error("verify-ca must NOT set InsecureSkipVerify")
		}
		if plan.tlsConfig.RootCAs == nil {
			t.Error("verify-ca must populate RootCAs from the PEM bundle")
		}
	})

	t.Run("verify-ca fails closed on a missing CA file", func(t *testing.T) {
		if _, err := planTLS("verify-ca", filepath.Join(t.TempDir(), "does-not-exist.pem")); err == nil {
			t.Fatal("expected fail-closed error for a missing CA bundle file, got nil")
		}
	})

	t.Run("verify-ca fails closed on a non-PEM / empty file", func(t *testing.T) {
		bogus := filepath.Join(t.TempDir(), "notpem.txt")
		if err := os.WriteFile(bogus, []byte("this is not a certificate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := planTLS("verify-ca", bogus); err == nil {
			t.Fatal("expected fail-closed error for a file with no PEM certs, got nil")
		}
	})

	t.Run("case-insensitive + trimmed mode", func(t *testing.T) {
		plan, err := planTLS("  Verify-CA  ", caPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if plan.urlOptions["SSL VERIFY"] != "true" || plan.tlsConfig == nil {
			t.Errorf("expected verified TLS for mixed-case/whitespace mode, got %v", plan.urlOptions)
		}
	})

	t.Run("require = encrypt-only, verification explicitly off, no pool, no CA needed", func(t *testing.T) {
		plan, err := planTLS("require", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if plan.urlOptions["SSL"] != "true" || plan.urlOptions["SSL VERIFY"] != "false" {
			t.Errorf("require url options = %v, want SSL=true SSL VERIFY=false", plan.urlOptions)
		}
		if plan.tlsConfig != nil {
			t.Errorf("require must not build a verifying tls.Config, got %v", plan.tlsConfig)
		}
	})

	t.Run("disable = plaintext, no SSL options, no pool", func(t *testing.T) {
		plan, err := planTLS("disable", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(plan.urlOptions) != 0 {
			t.Errorf("disable must emit no TLS url options, got %v", plan.urlOptions)
		}
		if plan.tlsConfig != nil {
			t.Errorf("disable must not build a tls.Config, got %v", plan.tlsConfig)
		}
	})

	t.Run("unknown mode fails closed", func(t *testing.T) {
		if _, err := planTLS("sortof", caPath); err == nil {
			t.Fatal("expected error for unknown TLS mode, got nil")
		}
	})
}

// writeTestCABundle generates a throwaway self-signed CA cert, writes it as PEM to
// a temp file, and returns the path. This lets the verify-ca path be unit-tested
// without a real AWS RDS CA bundle.
func writeTestCABundle(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "oraquery-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "test-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return path
}
