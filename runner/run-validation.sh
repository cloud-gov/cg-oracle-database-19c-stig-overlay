#!/usr/bin/env bash
# run-validation.sh (#7) — execute the Cloud.gov Oracle 19c STIG overlay profile
# against a target Oracle DB via CINC Auditor + oracledb_session (oraquery backend).
#
# Required env (injected at runtime, never baked into the image):
#   DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE
# Optional:
#   DB_PORT — defaulted by the shared helper to match the TLS posture: 1521
#     (plaintext) for a local dev target, 2484 (TCPS) for a remote target unless
#     ORAQUERY_TLS=disable was explicitly requested. An explicit DB_PORT wins.
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
#
# Options: --json also writes a timestamped JSON report to OUT_DIR (default /out);
# --controls "ID [ID...]" (or the CONTROLS env) runs only the named control(s).
# --skip-customer-controls (or SKIP_CUSTOMER_CONTROLS=1) skips customer-
#   responsibility controls; default runs all. See ../docs/RESPONSIBILITY.md.

set -euo pipefail

# Shared connection discovery (env/VCAP → DB_* + TLS mode). Sourced so this
# script and db-query.sh cannot drift on how they reach the database.
LOG_PREFIX=run-validation
export LOG_PREFIX  # consumed by the sourced lib/db-connect.sh (SC2034)
# shellcheck source=lib/db-connect.sh
. "$(dirname "$0")/lib/db-connect.sh"

# --- CLI args --------------------------------------------------------------
JSON_OUTPUT="${JSON_OUTPUT:-}"
CONTROLS="${CONTROLS:-}"
# Responsibility posture (see ../docs/RESPONSIBILITY.md). Default = run all;
# --skip-customer-controls / SKIP_CUSTOMER_CONTROLS sets the profile input below.
SKIP_CUSTOMER_CONTROLS="${SKIP_CUSTOMER_CONTROLS:-}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --json)
            JSON_OUTPUT=1
            ;;
        --skip-customer-controls)
            SKIP_CUSTOMER_CONTROLS=1
            ;;
        --all)
            SKIP_CUSTOMER_CONTROLS=0  # explicit alias for the default
            ;;
        --controls | --control)
            shift
            [ "$#" -gt 0 ] || { echo "run-validation: --controls requires a value" >&2; exit 2; }
            CONTROLS="${CONTROLS:+$CONTROLS }$1"
            ;;
        --controls=*)
            CONTROLS="${CONTROLS:+$CONTROLS }${1#--controls=}"
            ;;
        *)
            echo "run-validation: unknown argument '${1}'" >&2
            exit 2
            ;;
    esac
    shift
done

# Normalize to a strict true/false the profile input expects (default false).
case "${SKIP_CUSTOMER_CONTROLS}" in
    1 | true | TRUE | yes | YES) SKIP_CUSTOMER_CONTROLS=true ;;
    *) SKIP_CUSTOMER_CONTROLS=false ;;
esac

export PATH="/opt/cinc-auditor/embedded/bin:/usr/local/bin:${PATH}"
ORAQUERY_BIN=/usr/local/bin/oraquery

# Resolve DB_* (from env and, on Cloud.gov, VCAP_SERVICES) and the TLS mode.
# Fails closed on a missing coordinate or an absent ORCL binding.
resolve_db_connection

echo "run-validation: CINC Auditor $(cinc-auditor version 2>/dev/null || inspec version 2>/dev/null || echo '?')"
echo "run-validation: target ${DB_HOST}:${DB_PORT}/${DB_SERVICE} as ${DB_USER} (TLS mode: ${ORAQUERY_TLS:-verify-ca})"
if [ "$SKIP_CUSTOMER_CONTROLS" = true ]; then
    echo "run-validation: posture: PLATFORM-only (skipping customer-responsibility controls)" >&2
else
    echo "run-validation: posture: --all (running customer-responsibility controls too)" >&2
fi

# Inputs the overlay/baseline profile expects. oracledb_session shells out to the
# pure-Go wrapper via sqlplus_bin. skip_customer_responsibility_controls drives the
# responsibility gate in controls/baseline.rb.
#
# allowed_audit_users (SV-270510, AU-9): the overlay inspec.yml defaults this to
# the always-present RDSADMIN platform account. The broker-provisioned application
# user is per-instance (its name is not known until connect time), so append the
# connecting DB_USER here — it is an authorized audit-store grantee on a brokered
# RDS. This does NOT weaken the check: any OTHER grantee outside the list is still
# a finding. Site-authorized accounts (DBAs/auditors) can be added via an input
# file passed after this one on the CLI.
cat >/tmp/inputs.yml <<EOF
user: '${DB_USER}'
password: '${DB_PASSWORD}'
host: '${DB_HOST}'
service: '${DB_SERVICE}'
port: ${DB_PORT}
sqlplus_bin: '${ORAQUERY_BIN}'
skip_customer_responsibility_controls: ${SKIP_CUSTOMER_CONTROLS}
allowed_audit_users:
  - RDSADMIN
  - '${DB_USER}'
EOF

# CINC Auditor is invoked as `cinc-auditor` (falls back to `inspec` if aliased).
AUDITOR=cinc-auditor
command -v "$AUDITOR" >/dev/null 2>&1 || AUDITOR=inspec

# Profile source: the image's build-time-vendored copy at /profile by default;
# `make retest` overrides it with a read-only mount of the working tree so control
# edits are picked up without an image rebuild.
PROFILE_SOURCE="${PROFILE_SOURCE:-/profile}"

exec_args=(exec "$PROFILE_SOURCE" --input-file /tmp/inputs.yml)

# Always print the CLI report; with --json, also write a timestamped, labeled
# JSON report so local runs can be saved/compared. Exit status is unaffected.
reporter_args=(--reporter cli)

if [ -n "$JSON_OUTPUT" ]; then
    OUT_DIR="${OUT_DIR:-/out}"
    RUN_LABEL="${RUN_LABEL:-$DB_SERVICE}"
    RUN_LABEL="$(printf '%s' "$RUN_LABEL" | tr -c 'A-Za-z0-9._-' '_')"
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    JSON_PATH="${OUT_DIR}/validation-${RUN_LABEL}-${timestamp}.json"

    mkdir -p "$OUT_DIR" || {
        echo "run-validation: cannot create OUT_DIR ${OUT_DIR}" >&2
        exit 1
    }

    reporter_args+=(json:"$JSON_PATH")
    echo "run-validation: JSON report path: ${JSON_PATH}" >&2
    # Stable machine marker parsed by `make report-cloudgov` to fetch the exact
    # report over cf ssh. This is a CONTRACT — do not reword or drop it without
    # updating the sed in the Makefile's report-cloudgov recipe.
    printf 'JSON_REPORT_PATH=%s\n' "$JSON_PATH" >&2
fi

exec_args+=("${reporter_args[@]}")

if [ -n "$CONTROLS" ]; then
    # shellcheck disable=SC2206  # deliberate word-split: one CINC arg per control
    controls_list=($CONTROLS)
    exec_args+=(--controls "${controls_list[@]}")
    echo "run-validation: control filter → ${CONTROLS}" >&2
fi

# A read-only mounted profile still needs a writable dependency cache; keep that
# write off the mount. The baked /profile is already vendored and needs no cache.
if [ "$PROFILE_SOURCE" != "/profile" ]; then
    VENDOR_CACHE="${VENDOR_CACHE:-${HOME:-/home/scanner}/.inspec/cache}"
    mkdir -p "$VENDOR_CACHE"
    exec_args+=(--vendor-cache "$VENDOR_CACHE")
fi

echo "run-validation: profile ${PROFILE_SOURCE}"

"$AUDITOR" "${exec_args[@]}"
