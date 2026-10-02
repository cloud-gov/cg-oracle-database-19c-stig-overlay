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
#   VCAP_SERVICES                               (Cloud.gov; exactly one aws-rds binding, db_name ORCL)
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

# Emit the ORCL binding's coordinates as a single tab-separated line:
#   username <TAB> password <TAB> host <TAB> service <TAB> port <TAB> instance_name
# instance_name is the top-level CF service-instance field (e.g. "test-oracle-tls"),
# the human-facing per-instance report discriminator — NOT credentials.name.
#
# Two interpreters implement the SAME contract so the shared resolver works in
# every runner without drift: the CINC image ships Ruby; the cflinuxfs4
# Java-buildpack app ships no Ruby but has jq. Preference: Ruby → jq.
#
# Selection contract (issue #21): the runner supports exactly ONE aws-rds binding.
#   - MORE THAN ONE aws-rds binding → fail closed. We do NOT guess which database
#     to scan; on brokered Cloud.gov RDS every Oracle service is named "ORCL", so
#     the label cannot disambiguate them. A future multi-binding use case is out of
#     scope — that user adds selection then.
#   - Exactly ONE binding, and it is ORCL (credentials db_name/name == "ORCL")
#     → emit its coordinate row.
#   - Zero bindings, or the single binding is not ORCL → fail closed.
# The Ruby path signals ">1" with exit 3; the jq path emits one row per aws-rds
# binding and the caller counts. Either way the count DECISION and its messages
# live ONLY in the bash caller (_dbc_parse_vcap), so the interpreters cannot drift.

_dbc_vcap_ruby() {
    "$1" <<'RUBY'
require 'json'

services = JSON.parse(ENV.fetch('VCAP_SERVICES'))
bindings = services['aws-rds'] || []

# Support exactly one aws-rds binding; refuse to guess among several (issue #21).
exit 3 if bindings.length > 1

binding = bindings.first
exit 1 if binding.nil?  # no aws-rds binding at all

credentials = binding['credentials'] || {}
# The single binding must be the Oracle (ORCL) database, else fail closed.
exit 1 unless (credentials['db_name'] || credentials['name']) == 'ORCL'

puts [
  credentials.fetch('username', ''),
  credentials.fetch('password', ''),
  credentials.fetch('host', ''),
  credentials['db_name'] || credentials.fetch('name', ''),
  credentials.fetch('port', ''),
  binding['instance_name'] || binding['name'] || '',  # CF service-instance name
].join("\t")
RUBY
}

# jq fallback for the no-Ruby platform. Same contract; jq decodes JSON escapes
# (passwords with quotes/backslashes) natively. Deliberately avoids error("msg")
# (jq 1.6+) and -e: it emits one row per aws-rds binding and the caller counts,
# then the caller verifies the single row is ORCL.
_dbc_vcap_jq() {
    # -r + join("\t"): raw, tab-separated fields. NOT @tsv, which would escape a `\`
    #   in a password. Credentials hold no literal tab; the caller reads with IFS=\t.
    # [.["aws-rds"][]?]: all aws-rds bindings; the `[]?` tolerates a missing key
    #   (→ no rows → caller's fail-closed "no binding"). The WHOLE binding is kept
    #   so the top-level instance_name survives. NO ORCL filter here: the caller
    #   counts the rows first (>1 → fail) and checks the single row's service.
    printf '%s' "${VCAP_SERVICES}" | "$1" -r '
        [ .["aws-rds"][]? ]
        | .[]
        | [ (.credentials.username // ""),
            (.credentials.password // ""),
            (.credentials.host // ""),
            (.credentials.db_name // .credentials.name // ""),
            (.credentials.port // "" | tostring),
            (.instance_name // .name // "") ]
        | join("\t")
    '
}

# Fills any UNSET DB_* (and DB_INSTANCE_NAME) from the single ORCL aws-rds
# binding; explicit env vars win. Applies the selection contract described above
# for BOTH interpreters — the sole place the count/ORCL decision and its messages
# live. Fails closed on zero bindings, >1 bindings, or a single non-ORCL binding.
# No-op without VCAP.
_dbc_parse_vcap() {
    [ -n "${VCAP_SERVICES:-}" ] || return 0

    local vcap_values ruby_bin jq_bin rc
    if ruby_bin="$(_dbc_ruby_bin)"; then
        _dbc_log "parsing VCAP_SERVICES with ${ruby_bin}"
        vcap_values="$(_dbc_vcap_ruby "$ruby_bin")" || rc=$?
        if [ -n "${rc:-}" ]; then
            # exit 3 → more than one aws-rds binding; anything else → no ORCL binding.
            if [ "$rc" -eq 3 ]; then
                _dbc_multiple_bindings
            else
                _dbc_log 'no single aws-rds binding with db_name "ORCL" found in VCAP_SERVICES'
            fi
            return 1
        fi
    elif jq_bin="$(command -v jq)"; then
        _dbc_log "parsing VCAP_SERVICES with ${jq_bin}"
        vcap_values="$(_dbc_vcap_jq "$jq_bin")" || {
            _dbc_log "failed to parse VCAP_SERVICES with jq"
            return 1
        }
    else
        _dbc_log "VCAP_SERVICES provided, but no Ruby or jq interpreter is available to parse it"
        return 1
    fi

    # jq emits one row per aws-rds binding (the Ruby path already enforced the
    # count and ORCL check itself). Apply the same policy to the jq path: >1 row
    # → fail, 0 rows → fail, exactly 1 row whose service field is not ORCL → fail.
    local row_count=0
    [ -n "$vcap_values" ] && row_count="$(printf '%s\n' "$vcap_values" | grep -c '')"
    if [ "$row_count" -gt 1 ]; then
        _dbc_multiple_bindings
        return 1
    elif [ "$row_count" -eq 0 ]; then
        _dbc_log 'no single aws-rds binding with db_name "ORCL" found in VCAP_SERVICES'
        return 1
    fi

    local vcap_user vcap_password vcap_host vcap_service vcap_port vcap_instance
    IFS=$'\t' read -r vcap_user vcap_password vcap_host vcap_service vcap_port vcap_instance <<<"$vcap_values"

    # Ruby returns only when the single binding is ORCL; the jq path is unfiltered,
    # so enforce it here so both interpreters reject a single non-Oracle binding.
    if [ "$vcap_service" != "ORCL" ]; then
        _dbc_log 'no single aws-rds binding with db_name "ORCL" found in VCAP_SERVICES'
        return 1
    fi

    DB_USER="${DB_USER:-$vcap_user}"
    DB_PASSWORD="${DB_PASSWORD:-$vcap_password}"
    DB_HOST="${DB_HOST:-$vcap_host}"
    DB_SERVICE="${DB_SERVICE:-$vcap_service}"
    DB_PORT="${DB_PORT:-$vcap_port}"
    DB_INSTANCE_NAME="${DB_INSTANCE_NAME:-$vcap_instance}"
}

# The runner supports exactly one aws-rds binding; more than one is refused rather
# than guessed at (issue #21). A future multi-binding use case adds selection then.
_dbc_multiple_bindings() {
    _dbc_log 'more than one aws-rds binding found in VCAP_SERVICES; refusing to guess which database to scan.'
    _dbc_log 'bind the runner app to exactly one aws-rds (Oracle) service instance.'
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

# JSON-escape a single string value for safe interpolation into a JSON string
# literal. RFC 8259 defines named escapes only for backslash, double-quote,
# backspace (\b), form-feed (\f), newline (\n), carriage-return (\r), and tab
# (\t); every OTHER control character in U+0000–U+001F — notably vertical-tab
# (U+000B), which has NO named JSON escape — MUST be emitted as a \uXXXX escape.
# This covers the chars reachable via operator-set DB_INSTANCE_NAME or
# VCAP-sourced db_user. SCOPE: the remaining U+0000–U+001F control chars (and the
# whole >U+001F range, which is legal RAW inside a JSON string) are intentionally
# NOT folded — they are not reachable through those two fields, and a general C0
# catch-all is fiddly in pure sed. If a new caller ever feeds arbitrary bytes
# here, extend this to a full \u00XX fold rather than relying on the current set.
# Prints the escaped value on stdout WITHOUT surrounding
# quotes — the caller adds them. Uses GNU sed (both the CINC runner image and the
# cflinuxfs4 fallback path are Linux/GNU; the :a;N;$!ba newline-fold idiom is a
# GNU-ism and returns empty on BSD/macOS sed). Control-char patterns are written
# as LITERAL bytes via bash $'…' ANSI-C quoting rather than C-style escapes,
# because a minimal sed (e.g. busybox in the bats image) does not expand those in
# the pattern — only the literal byte matches portably. Order matters: escape
# backslash FIRST so it does not double-escape the backslashes introduced for the
# others; fold vertical-tab to \u000b before the named escapes run.
_dbc_json_escape() {
    printf '%s' "$1" \
      | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
            -e $'s/\v/\\\\u000b/g' \
            -e $'s/\t/\\\\t/g' -e $'s/\r/\\\\r/g' -e $'s/\f/\\\\f/g' \
            -e $'s/\b/\\\\b/g' \
      | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
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
