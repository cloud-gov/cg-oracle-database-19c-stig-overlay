#!/usr/bin/env bash
# run-validation.sh (#7) — execute the Cloud.gov Oracle 19c STIG overlay profile
# against a target Oracle DB via CINC Auditor + oracledb_session (oraquery backend).
#
# Required env (injected at runtime, never baked into the image):
#   DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE
# Optional:
#   DB_PORT (default 1521; use 2484 for TCPS)
#
# When VCAP_SERVICES is present, the first aws-rds binding whose credentials
# db_name (or name) is "ORCL" is used to fill any unset DB_* values; explicit
# DB_* env vars still take precedence. If no ORCL binding exists, the script
# fails closed rather than guessing another database.
#
# TLS (see oraquery; #16 / #20): oraquery drives TLS from ORAQUERY_TLS, NOT from
# the port, and defaults to verified TLS (verify-ca), failing closed without a
# PEM CA bundle (ORAQUERY_CA_BUNDLE). The runner image bakes the AWS GovCloud RDS
# root CA and defaults ORAQUERY_CA_BUNDLE to it (#23), so verified TLS to a live
# brokered RDS works out of the box on TCPS 2484. To keep the LOCAL dev DB (gvenzl
# 23ai on plain 1521) working, this script defaults ORAQUERY_TLS=disable ONLY when
# it is unset AND the target is loopback/local; any other target keeps oraquery's
# fail-closed verify-ca default. A TLS mode aimed at plaintext port 1521 is refused.
#
# Fidelity: local runs target Oracle 23ai Free (gvenzl) — NOT 19c/SE2/RDS. This
# proves the check LOGIC runs; RDS/version-specific behavior is deferred to the
# live proof (aws-broker#558). Do not treat this output as compliance evidence.

set -euo pipefail

export PATH="/opt/cinc-auditor/embedded/bin:/usr/local/bin:${PATH}"
RUBY_BIN=/opt/cinc-auditor/embedded/bin/ruby
[ -x "$RUBY_BIN" ] || RUBY_BIN=ruby
ORAQUERY_BIN=/usr/local/bin/oraquery

if [ -n "${VCAP_SERVICES:-}" ]; then
    command -v "$RUBY_BIN" >/dev/null 2>&1 || {
        echo "run-validation: VCAP_SERVICES provided, but ${RUBY_BIN} is not available to parse it" >&2
        exit 1
    }

    echo "run-validation: parsing VCAP_SERVICES with ${RUBY_BIN}"
    vcap_values="$($RUBY_BIN <<'RUBY'
require 'json'

services = JSON.parse(ENV.fetch('VCAP_SERVICES'))
bindings = services.fetch('aws-rds')

# Select the first aws-rds binding whose credentials db_name (or name) is ORCL,
# rather than blindly taking the first binding.
binding = bindings.find do |b|
  creds = b.fetch('credentials')
  (creds['db_name'] || creds['name']) == 'ORCL'
end

if binding.nil?
  STDERR.puts 'run-validation: no aws-rds binding with db_name "ORCL" found in VCAP_SERVICES'
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
)"
    IFS=$'\t' read -r vcap_user vcap_password vcap_host vcap_service vcap_port <<<"$vcap_values"

    DB_USER="${DB_USER:-$vcap_user}"
    DB_PASSWORD="${DB_PASSWORD:-$vcap_password}"
    DB_HOST="${DB_HOST:-$vcap_host}"
    DB_SERVICE="${DB_SERVICE:-$vcap_service}"
    DB_PORT="${DB_PORT:-$vcap_port}"
fi

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
            : # leave unset → oraquery defaults to verify-ca (fails closed w/o a PEM CA bundle)
            ;;
    esac
fi

echo "run-validation: CINC Auditor $(cinc-auditor version 2>/dev/null || inspec version 2>/dev/null || echo '?')"
echo "run-validation: target ${DB_HOST}:${DB_PORT}/${DB_SERVICE} as ${DB_USER} (TLS mode: ${ORAQUERY_TLS:-verify-ca})"

# Inputs the overlay/baseline profile expects. oracledb_session shells out to the
# pure-Go wrapper via sqlplus_bin.
cat >/tmp/inputs.yml <<EOF
user: '${DB_USER}'
password: '${DB_PASSWORD}'
host: '${DB_HOST}'
service: '${DB_SERVICE}'
port: ${DB_PORT}
sqlplus_bin: '${ORAQUERY_BIN}'
EOF

# CINC Auditor is invoked as `cinc-auditor` (falls back to `inspec` if aliased).
AUDITOR=cinc-auditor
command -v "$AUDITOR" >/dev/null 2>&1 || AUDITOR=inspec

"$AUDITOR" exec /profile \
    --input-file /tmp/inputs.yml \
    --reporter cli
