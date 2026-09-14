# shellcheck shell=bash
# db-connect.sh — shared Oracle connection discovery for the runner scripts.
#
# SOURCED library (no shebang; the sourcing script owns `set` options). Source it,
# then call `resolve_db_connection`. Shared by run-validation.sh, db-query.sh, and
# both SQLcl runners (sqlcl/sqlcl-connect.sh and sqlcl-cf/entrypoint.sh) so the
# connection contract lives in ONE place and they can't drift.
#
# Contract: on success, exports DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE, DB_PORT,
# DB_INSTANCE_NAME and (when it chose one) ORAQUERY_TLS. Fails closed (non-zero +
# stderr) on a missing coordinate or an absent VCAP binding.
#
# Env inputs:
#   DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE   (required unless VCAP supplies them)
#   DB_PORT                                     (optional; see port defaulting below)
#   DB_INSTANCE_NAME                            (optional; report label; from VCAP instance_name)
#   VCAP_SERVICES                               (Cloud.gov; aws-rds binding, db_name ORCL)
#   ORAQUERY_TLS                                (optional; honored if already set)
#   LOG_PREFIX                                  (optional; log tag, default "db-connect")

_dbc_log() {
    printf '%s: %s\n' "${LOG_PREFIX:-db-connect}" "$*" >&2
}

# Prefer CINC's embedded Ruby, then any `ruby` on PATH; non-zero if none.
_dbc_ruby_bin() {
    if [ -x /opt/cinc-auditor/embedded/bin/ruby ]; then
        printf '%s' /opt/cinc-auditor/embedded/bin/ruby
        return 0
    fi
    if command -v ruby >/dev/null 2>&1; then
        printf '%s' ruby
        return 0
    fi
    return 1
}

# Emit the selected ORCL binding's coordinates as a single tab-separated line:
#   username <TAB> password <TAB> host <TAB> service <TAB> port <TAB> instance_name
# The instance_name is the CF service-instance name (a top-level field on the
# binding, e.g. "test-oracle-tls"); it is the human-facing per-instance
# discriminator used to label reports. TWO interpreters implement the SAME
# contract so the shared resolver works in every runner without drift: the CINC
# image ships Ruby; the Java-buildpack app on cflinuxfs4 ships no Ruby but has jq.
# Preference order (richest first): Ruby → jq.

_dbc_vcap_ruby() {
    "$1" <<'RUBY'
require 'json'

services = JSON.parse(ENV.fetch('VCAP_SERVICES'))
bindings = services.fetch('aws-rds')

binding = bindings.find do |b|
  creds = b.fetch('credentials')
  (creds['db_name'] || creds['name']) == 'ORCL'
end

if binding.nil?
  STDERR.puts 'db-connect: no aws-rds binding with db_name "ORCL" found in VCAP_SERVICES'
  exit 1
end

credentials = binding.fetch('credentials')

# instance_name / name are TOP-LEVEL binding fields (the CF service-instance
# name), not credentials fields — that is what an operator recognizes.
puts [
  credentials.fetch('username', ''),
  credentials.fetch('password', ''),
  credentials.fetch('host', ''),
  credentials['db_name'] || credentials.fetch('name', ''),
  credentials.fetch('port', ''),
  binding['instance_name'] || binding['name'] || '',
].join("\t")
RUBY
}

# jq fallback for platforms with NO Ruby (cflinuxfs4 + Java
# buildpack ships jq). Same contract/output as the Ruby parser, with the SAME
# selection semantics: of all aws-rds bindings whose credentials db_name (or name)
# is "ORCL", it emits the FIRST in array order — matching Ruby's `bindings.find`.
# jq handles JSON escaping correctly (passwords with quotes/backslashes), so no
# hand-rolled decoding. Fails closed (non-zero) if no ORCL binding is found,
# matching the Ruby behavior.
_dbc_vcap_jq() {
    # -e: exit non-zero if the final result is null/false (no ORCL match) → fail
    #     closed. -r: raw output (no JSON quoting). join("\t") emits the six decoded
    #     fields tab-separated — NOT @tsv, which TSV-escapes backslashes (doubling a
    #     `\` in a password). Credentials never contain a literal tab, and the caller
    #     reads back with IFS=$'\t', so join("\t") is the faithful, correct form.
    # `[.["aws-rds"][]?]` collects ALL aws-rds BINDING objects (the `[]?` tolerates a
    #     missing/empty aws-rds key → empty array → no match → -e fails, fail-closed),
    #     then `first(select(...))` picks the FIRST whose credentials db_name/name is
    #     ORCL — the direct jq analogue of Ruby's `bindings.find`. We keep the whole
    #     binding object (NOT just .credentials) so instance_name — a TOP-LEVEL
    #     binding field — survives to the output row. This is done INSIDE jq (not a
    #     shell `head -n1`) so the single result flows out without a truncated pipe,
    #     keeping jq's own exit status authoritative under the caller's pipefail.
    # Ruby emits credentials.db_name || name for the service field; the select filter
    #     already fixed that to "ORCL", so a literal "ORCL" is byte-identical here.
    # instance_name || name mirrors the Ruby fallback for the CF instance name.
    # Portability: every construct here works on jq 1.6 (the platform's version) and
    #     older. We deliberately AVOID `error("msg")` (the string-argument form, new in
    #     1.6); an unmatched query yields no output, and `-e` turns that into a non-zero
    #     exit. The human-readable "no ORCL binding" message is emitted by the bash
    #     caller (_dbc_parse_vcap) on a non-zero return, so no jq-version-sensitive
    #     error() call is needed.
    printf '%s' "${VCAP_SERVICES}" | "$1" -er '
        [ .["aws-rds"][]? ]
        | first(.[] | select((.credentials.db_name // .credentials.name) == "ORCL"))
        | [ (.credentials.username // ""),
            (.credentials.password // ""),
            (.credentials.host // ""),
            "ORCL",
            (.credentials.port // "" | tostring),
            (.instance_name // .name // "") ]
        | join("\t")
    '
}
# Fills any UNSET DB_* from the first aws-rds binding whose db_name (or name) is
# "ORCL" (and DB_INSTANCE_NAME from the binding's instance_name/name); explicit
# DB_* / DB_INSTANCE_NAME env vars win. Fails closed if VCAP_SERVICES is present
# but has no ORCL binding — never guesses another database. No-op without VCAP.
_dbc_parse_vcap() {
    [ -n "${VCAP_SERVICES:-}" ] || return 0

    local vcap_values ruby_bin jq_bin
    if ruby_bin="$(_dbc_ruby_bin)"; then
        _dbc_log "parsing VCAP_SERVICES with ${ruby_bin}"
        vcap_values="$(_dbc_vcap_ruby "$ruby_bin")" || return 1
    elif jq_bin="$(command -v jq)"; then
        # cflinuxfs4 + Java buildpack: no Ruby, but jq is present.
        _dbc_log "parsing VCAP_SERVICES with ${jq_bin}"
        vcap_values="$(_dbc_vcap_jq "$jq_bin")" || return 1
    else
        _dbc_log "VCAP_SERVICES provided, but no Ruby or jq interpreter is available to parse it"
        return 1
    fi

    local vcap_user vcap_password vcap_host vcap_service vcap_port vcap_instance
    IFS=$'\t' read -r vcap_user vcap_password vcap_host vcap_service vcap_port vcap_instance <<<"$vcap_values"

    DB_USER="${DB_USER:-$vcap_user}"
    DB_PASSWORD="${DB_PASSWORD:-$vcap_password}"
    DB_HOST="${DB_HOST:-$vcap_host}"
    DB_SERVICE="${DB_SERVICE:-$vcap_service}"
    DB_PORT="${DB_PORT:-$vcap_port}"
    # CF service-instance name (e.g. "test-oracle-tls"), the human-facing report
    # discriminator. An explicit DB_INSTANCE_NAME env var still wins.
    DB_INSTANCE_NAME="${DB_INSTANCE_NAME:-$vcap_instance}"
}

# Unmistakably-local dev targets. Mirrors oraquery's isLocalHost allowlist
# (main.go) — keep the two in sync. A compose service under another name (e.g.
# "oracle-db") is treated as remote and inherits the fail-closed verify-ca default.
_dbc_is_local() {
    case "$1" in
        localhost | 127.0.0.1 | ::1 | oracle) return 0 ;;
        *) return 1 ;;
    esac
}

# Default DB_PORT to match the TLS posture, NOT blindly to 1521: oraquery refuses
# TLS at the plaintext port 1521 (TCPS is 2484). An explicit DB_PORT always wins.
_dbc_default_port() {
    [ -z "${DB_PORT:-}" ] || return 0
    if _dbc_is_local "$DB_HOST"; then
        DB_PORT=1521
    else
        case "${ORAQUERY_TLS:-}" in
            disable) DB_PORT=1521 ;;
            *) DB_PORT=2484 ;;
        esac
    fi
}

# Choose a fail-closed TLS mode ONLY when unset: plaintext for a local target,
# else leave unset so oraquery applies its verify-ca default.
_dbc_default_tls() {
    [ -z "${ORAQUERY_TLS:-}" ] || return 0
    if _dbc_is_local "$DB_HOST"; then
        export ORAQUERY_TLS=disable
        _dbc_log "local target ${DB_HOST} → ORAQUERY_TLS=disable (plaintext, dev only)"
    fi
}

# Derive a stable, filesystem-safe discriminator token. On brokered Cloud.gov RDS
# every Oracle service is named "ORCL" (see the VCAP parser above), so the SERVICE
# name cannot tell two databases apart. The best discriminator is the CF
# service-INSTANCE name (DB_INSTANCE_NAME, e.g. "test-oracle-tls" → labeled report
# "ORCL-test-oracle-tls"). When that is unavailable (a local/ad-hoc run with no
# VCAP binding and no DB_INSTANCE_NAME set), fall back to the RDS endpoint's first
# DNS label. Prints the token on stdout; sanitized to [a-z0-9._-]; never empty.
db_instance_label() {
    local instance="${1:-${DB_INSTANCE_NAME:-}}"
    if [ -n "$instance" ]; then
        _dbc_sanitize_label "$instance"
    else
        db_host_label "${DB_HOST:-}"
    fi
}

# Lowercase + replace any char outside [a-z0-9._-] with '-', trim edge '-', guard
# against empty (→ "unknown"). Shared by db_instance_label and db_host_label so the
# two cannot drift on what a "safe token" is.
_dbc_sanitize_label() {
    local label
    label="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-')"
    label="${label#-}"
    label="${label%-}"
    printf '%s' "${label:-unknown}"
}

# Fallback discriminator: the RDS endpoint's first DNS label (the per-instance
# identifier, e.g. "cg-aws-broker-xxxx" in
# cg-aws-broker-xxxx.abc123.us-gov-west-1.rds.amazonaws.com). An IPv4/IPv6 literal
# is kept WHOLE (its first "label" is not a discriminator — 10.0.0.5 and 10.9.9.9
# both start with "10"). Prints the token on stdout.
db_host_label() {
    local host="${1:-${DB_HOST:-}}" label
    # An IPv4 literal has no meaningful "first DNS label" (taking it would collapse
    # 10.0.0.5 and 10.9.9.9 both to "10"), so keep the whole address. IPv6 (has a
    # ':') is likewise kept whole; sanitization makes it filesystem-safe.
    if printf '%s' "$host" | grep -Eq '^[0-9]+(\.[0-9]+){3}$' || case "$host" in *:*) true ;; *) false ;; esac; then
        label="$host"
    else
        # First DNS label — everything before the first '.'. For a bare hostname
        # this is the whole value.
        label="${host%%.*}"
        [ -n "$label" ] || label="$host"
    fi
    _dbc_sanitize_label "$label"
}

# Single entry point: fill DB_* from VCAP, require the coordinates, then choose TLS
# mode and port (order matters — the port default reads the TLS mode).
resolve_db_connection() {
    _dbc_parse_vcap || return 1

    : "${DB_USER:?DB_USER required}"
    : "${DB_PASSWORD:?DB_PASSWORD required}"
    : "${DB_HOST:?DB_HOST required}"
    : "${DB_SERVICE:?DB_SERVICE required}"

    _dbc_default_tls
    _dbc_default_port

    export DB_USER DB_PASSWORD DB_HOST DB_SERVICE DB_PORT DB_INSTANCE_NAME
}
