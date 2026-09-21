#!/usr/bin/env bats
# Unit tests for the pure-shell helpers in db-connect.sh — the JSON escaper that
# guards the .meta.json sidecar and the report-label derivation helpers. These
# functions have no external dependency (bash + sed only), so the suite runs in
# the stock bats image with no Ruby/jq/DB. Run: `make test-bats` (see Makefile).
#
# Scope: _dbc_json_escape, _dbc_sanitize_label, db_instance_label, db_host_label.
# The VCAP parsers (_dbc_vcap_ruby / _dbc_vcap_jq) require Ruby/jq and a VCAP
# fixture and are exercised separately; they are out of scope here.

setup() {
  # Source ONLY the library. It is a sourced fragment (no shebang, no top-level
  # side effects), so pulling it into the test shell just defines the functions.
  # shellcheck disable=SC1091
  source "${BATS_TEST_DIRNAME}/db-connect.sh"
}

# --- _dbc_json_escape ------------------------------------------------------
# The sidecar is emitted via a heredoc that interpolates each value into a JSON
# "..." string literal. A raw double-quote or backslash would break the JSON, so
# every string field is passed through _dbc_json_escape first. These assert the
# escaper's raw output; the round-trip test below proves the result parses.

@test "json-escape: leaves an ordinary token untouched" {
  run _dbc_json_escape "test-oracle-tls"
  [ "$status" -eq 0 ]
  [ "$output" = "test-oracle-tls" ]
}

@test "json-escape: preserves a space (documented DB_INSTANCE_NAME case)" {
  run _dbc_json_escape "My Prod DB"
  [ "$output" = "My Prod DB" ]
}

@test "json-escape: escapes a double-quote" {
  run _dbc_json_escape 'we"ird'
  [ "$output" = 'we\"ird' ]
}

@test "json-escape: escapes a backslash" {
  run _dbc_json_escape 'we\ird'
  [ "$output" = 'we\\ird' ]
}

@test "json-escape: escapes backslash BEFORE quote (no double-escaping)" {
  # Input a\"b — the \" is a literal backslash then a literal quote. Correct
  # output escapes the backslash to \\ and the quote to \" → a\\\"b. A wrong
  # ordering (quote first) would corrupt the backslash it just added.
  run _dbc_json_escape 'a\"b'
  [ "$output" = 'a\\\"b' ]
}

@test "json-escape: empty string yields empty string" {
  run _dbc_json_escape ""
  [ "$status" -eq 0 ]
  [ "$output" = "" ]
}

@test "json-escape: round-trips a hostile value back through a JSON parser" {
  # The property that actually matters: whatever we escape must produce a VALID
  # JSON string literal that decodes back to the ORIGINAL value. Prove it with a
  # tiny pure-bash decoder of the escapes this function emits (\\ \" \t \n) — no
  # jq dependency in the test image. Covers quote+backslash together.
  local original='a"b\c'
  local escaped
  escaped="$(_dbc_json_escape "$original")"
  # Decode: \\ -> \, \" -> " (apply in the reverse-safe order via a marker).
  local decoded="$escaped"
  decoded="${decoded//\\\\/$'\x01'}"   # protect real backslashes
  decoded="${decoded//\\\"/\"}"        # \" -> "
  decoded="${decoded//$'\x01'/\\}"     # restore backslashes
  [ "$decoded" = "$original" ]
}

# --- _dbc_sanitize_label ---------------------------------------------------

@test "sanitize: lowercases and keeps the safe class [a-z0-9._-]" {
  run _dbc_sanitize_label "Test-Oracle_TLS.1"
  [ "$output" = "test-oracle_tls.1" ]
}

@test "sanitize: replaces unsafe chars with a hyphen" {
  run _dbc_sanitize_label 'My Prod DB'
  [ "$output" = "my-prod-db" ]
}

@test "sanitize: trims leading and trailing hyphens" {
  run _dbc_sanitize_label ' edge '
  [ "$output" = "edge" ]
}

@test "sanitize: empty input falls back to 'unknown'" {
  run _dbc_sanitize_label ""
  [ "$output" = "unknown" ]
}

# --- db_instance_label -----------------------------------------------------

@test "instance-label: uses DB_INSTANCE_NAME when set" {
  DB_INSTANCE_NAME="test-oracle-tls" DB_HOST="ignored.example.com" run db_instance_label
  [ "$output" = "test-oracle-tls" ]
}

@test "instance-label: sanitizes a human-set DB_INSTANCE_NAME" {
  DB_INSTANCE_NAME="My Prod DB" run db_instance_label
  [ "$output" = "my-prod-db" ]
}

@test "instance-label: falls back to the host's first DNS label" {
  DB_INSTANCE_NAME="" DB_HOST="cg-aws-broker-zzz.abc.us-gov-west-1.rds.amazonaws.com" run db_instance_label
  [ "$output" = "cg-aws-broker-zzz" ]
}

@test "instance-label: local dev host" {
  DB_INSTANCE_NAME="" DB_HOST="localhost" run db_instance_label
  [ "$output" = "localhost" ]
}

# --- db_host_label ---------------------------------------------------------

@test "host-label: takes the first DNS label of an RDS endpoint" {
  run db_host_label "cg-aws-broker-zzz.abc.us-gov-west-1.rds.amazonaws.com"
  [ "$output" = "cg-aws-broker-zzz" ]
}

@test "host-label: keeps an IPv4 literal WHOLE (first octet is not a discriminator)" {
  run db_host_label "10.0.0.5"
  [ "$output" = "10.0.0.5" ]
}

@test "host-label: keeps an IPv6 literal whole (sanitized to be path-safe)" {
  run db_host_label "2001:db8::1"
  [ "$output" = "2001-db8--1" ]
}

@test "host-label: a bare hostname is used as-is" {
  run db_host_label "localhost"
  [ "$output" = "localhost" ]
}
