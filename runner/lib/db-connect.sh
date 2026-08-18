# shellcheck shell=bash
# db-connect.sh — shared Oracle connection discovery for the runner scripts.
#
# SOURCED library (no shebang; the sourcing script owns `set` options). Source it,
# then call `resolve_db_connection`. Shared by run-validation.sh, db-query.sh, and
# both SQLcl runners (sqlcl/sqlcl-connect.sh and sqlcl-cf/entrypoint.sh) so the
# connection contract lives in ONE place and they can't drift.
#
# Contract: on success, exports DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE, DB_PORT
# and (when it chose one) ORAQUERY_TLS. Fails closed (non-zero + stderr) on a
# missing coordinate or an absent VCAP binding.
#
# Env inputs:
#   DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE   (required unless VCAP supplies them)
#   DB_PORT                                     (optional; see port defaulting below)
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
#   username <TAB> password <TAB> host <TAB> service <TAB> port
# TWO interpreters implement the SAME contract so the shared resolver works in
# every runner without drift: the CINC image ships Ruby; the Java-buildpack app on
# cflinuxfs4 ships no Ruby but has jq. Preference order (richest first): Ruby → jq.

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

puts [
  credentials.fetch('username', ''),
  credentials.fetch('password', ''),
  credentials.fetch('host', ''),
  credentials['db_name'] || credentials.fetch('name', ''),
  credentials.fetch('port', ''),
].join("\t")
RUBY
}

# jq fallback for platforms with NO Ruby (cflinuxfs4 + Java
# buildpack ships jq). Same contract/output as the Ruby parser: selects the
# first aws-rds binding whose credentials db_name (or name) is "ORCL" and emits its
# five fields tab-separated. jq handles JSON escaping correctly (passwords with
# quotes/backslashes), so no hand-rolled decoding. Fails closed (non-zero) if no
# ORCL binding is found, matching the Ruby behavior.
_dbc_vcap_jq() {
    # -e: exit non-zero if the final result is null/false (no ORCL match) → fail
    #     closed. -r: raw output (no JSON quoting). join("\t") emits the five decoded
    #     fields tab-separated — NOT @tsv, which TSV-escapes backslashes (doubling a
    #     `\` in a password). Credentials never contain a literal tab, and the caller
    #     reads back with IFS=$'\t', so join("\t") is the faithful, correct form.
    # `.["aws-rds"] // empty` tolerates a missing aws-rds key (→ empty → -e fails).
    # Portability: every construct here works on jq 1.6 (the platform's version) and
    # older. We deliberately AVOID `error("msg")` (the string-argument form, new in
    # 1.6); instead an unmatched query yields `empty`, and `-e` turns that into a
    # non-zero exit. The human-readable "no ORCL binding" message is emitted by the
    # bash caller (_dbc_parse_vcap) on a non-zero return, so no jq-version-sensitive
    # error() call is needed.
    printf '%s' "${VCAP_SERVICES}" | "$1" -er '
        (.["aws-rds"] // empty)[]
        | .credentials
        | select((.db_name // .name) == "ORCL")
        | [ (.username // ""),
            (.password // ""),
            (.host // ""),
            "ORCL",
            (.port // "" | tostring) ]
        | join("\t")
    ' | head -n1
}
# Fills any UNSET DB_* from the first aws-rds binding whose db_name (or name) is
# "ORCL"; explicit DB_* env vars win. Fails closed if VCAP_SERVICES is present but
# has no ORCL binding — never guesses another database. No-op without VCAP.
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

    local vcap_user vcap_password vcap_host vcap_service vcap_port
    IFS=$'\t' read -r vcap_user vcap_password vcap_host vcap_service vcap_port <<<"$vcap_values"

    DB_USER="${DB_USER:-$vcap_user}"
    DB_PASSWORD="${DB_PASSWORD:-$vcap_password}"
    DB_HOST="${DB_HOST:-$vcap_host}"
    DB_SERVICE="${DB_SERVICE:-$vcap_service}"
    DB_PORT="${DB_PORT:-$vcap_port}"
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

    export DB_USER DB_PASSWORD DB_HOST DB_SERVICE DB_PORT
}
