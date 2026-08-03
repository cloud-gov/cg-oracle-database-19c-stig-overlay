#!/usr/bin/env bash
# run-validation.sh (#7) — execute the Cloud.gov Oracle 19c STIG overlay profile
# against a target Oracle DB via CINC Auditor + oracledb_session (oraquery backend).
#
# Required env (injected at runtime, never baked into the image):
#   DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE
# Optional:
#   DB_PORT (default 1521; use 2484 for TCPS)
#
# TLS (see oraquery; #16 / #20): oraquery drives TLS from ORAQUERY_TLS, NOT from
# the port, and defaults to verified TLS (verify-ca), failing closed without a
# CA/wallet. To keep the LOCAL dev DB (gvenzl 23ai on plain 1521) working out of
# the box, this script defaults ORAQUERY_TLS=disable ONLY when it is unset AND
# the target is loopback/local; any other target keeps oraquery's safe default.
# For a real brokered RDS target you MUST set ORAQUERY_TLS=verify-ca and
# ORAQUERY_WALLET=<CA/wallet path> — plaintext against live RDS is refused.
#
# Fidelity: local runs target Oracle 23ai Free (gvenzl) — NOT 19c/SE2/RDS. This
# proves the check LOGIC runs; RDS/version-specific behavior is deferred to the
# live proof (aws-broker#558). Do not treat this output as compliance evidence.

set -euo pipefail

: "${DB_USER:?DB_USER required}"
: "${DB_PASSWORD:?DB_PASSWORD required}"
: "${DB_HOST:?DB_HOST required}"
: "${DB_SERVICE:?DB_SERVICE required}"
DB_PORT="${DB_PORT:-1521}"

# Local-dev convenience: only auto-select plaintext for an unmistakably local
# target when the operator has not chosen a TLS mode. Everything else inherits
# oraquery's fail-closed verify-ca default (#16 / #20).
if [ -z "${ORAQUERY_TLS:-}" ]; then
    case "$DB_HOST" in
        localhost | 127.0.0.1 | ::1 | oracle)
            export ORAQUERY_TLS=disable
            echo "run-validation: local target ${DB_HOST} → ORAQUERY_TLS=disable (plaintext, dev only)" >&2
            ;;
        *)
            : # leave unset → oraquery defaults to verify-ca (fails closed w/o wallet)
            ;;
    esac
fi

echo "run-validation: CINC Auditor $(cinc-auditor version 2>/dev/null || inspec version 2>/dev/null || echo '?')"
echo "run-validation: target ${DB_HOST}:${DB_PORT}/${DB_SERVICE} as ${DB_USER} (TLS mode: ${ORAQUERY_TLS:-verify-ca})"

# Inputs the overlay/baseline profile expects. oracledb_session shells out to the
# pure-Go wrapper via sqlplus_bin=oraquery.
cat >/tmp/inputs.yml <<EOF
user: '${DB_USER}'
password: '${DB_PASSWORD}'
host: '${DB_HOST}'
service: '${DB_SERVICE}'
port: ${DB_PORT}
sqlplus_bin: 'oraquery'
EOF

# CINC Auditor is invoked as `cinc-auditor` (falls back to `inspec` if aliased).
AUDITOR=cinc-auditor
command -v "$AUDITOR" >/dev/null 2>&1 || AUDITOR=inspec

"$AUDITOR" exec /profile \
    --input-file /tmp/inputs.yml \
    --reporter cli
