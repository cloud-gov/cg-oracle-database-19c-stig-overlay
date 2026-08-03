package main

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
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

// TestBuildConnOptions covers the explicit-intent TLS logic (#16 / #20): the
// default is verified TLS, verify-ca fails closed without a wallet, and the
// insecure paths are opt-in only. TLS is never inferred from the port.
func TestBuildConnOptions(t *testing.T) {
	t.Run("default (empty) is verify-ca and fails closed without wallet", func(t *testing.T) {
		_, err := buildConnOptions("", "")
		if err == nil {
			t.Fatal("expected fail-closed error when defaulting to verify-ca with no wallet, got nil")
		}
		if !strings.Contains(err.Error(), "ORAQUERY_WALLET") {
			t.Errorf("error should mention the missing wallet, got: %v", err)
		}
	})

	t.Run("verify-ca with wallet sets SSL + verify + wallet", func(t *testing.T) {
		opts, err := buildConnOptions("verify-ca", "/etc/oracle/rds-ca")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts["SSL"] != "true" || opts["SSL VERIFY"] != "true" || opts["WALLET"] != "/etc/oracle/rds-ca" {
			t.Errorf("verify-ca opts = %v, want SSL=true SSL VERIFY=true WALLET=/etc/oracle/rds-ca", opts)
		}
	})

	t.Run("case-insensitive + trimmed mode", func(t *testing.T) {
		opts, err := buildConnOptions("  Verify-CA  ", "/w")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts["SSL VERIFY"] != "true" {
			t.Errorf("expected verified TLS for mixed-case/whitespace mode, got %v", opts)
		}
	})

	t.Run("require = encrypt-only, verification explicitly off", func(t *testing.T) {
		opts, err := buildConnOptions("require", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts["SSL"] != "true" || opts["SSL VERIFY"] != "false" {
			t.Errorf("require opts = %v, want SSL=true SSL VERIFY=false", opts)
		}
		if _, ok := opts["WALLET"]; ok {
			t.Errorf("require without a wallet must not set WALLET, got %v", opts)
		}
	})

	t.Run("disable = plaintext, no SSL options at all", func(t *testing.T) {
		opts, err := buildConnOptions("disable", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(opts) != 0 {
			t.Errorf("disable must emit no TLS options, got %v", opts)
		}
	})

	t.Run("unknown mode fails closed", func(t *testing.T) {
		if _, err := buildConnOptions("sortof", "/w"); err == nil {
			t.Fatal("expected error for unknown TLS mode, got nil")
		}
	})
}
