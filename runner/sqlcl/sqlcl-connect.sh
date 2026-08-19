#!/usr/bin/env bash
# sqlcl-connect.sh — run Oracle SQLcl against the Cloud.gov (or local dev) Oracle DB,
# resolving the connection with the SAME discovery the STIG validation runner uses
# (lib/db-connect.sh: env + VCAP_SERVICES, fail-closed TLS). SQLcl is a full
# SQL*Plus/SQLcl interpreter, so unlike the pure-Go oraquery wrapper it CAN run the
# hardening/sql/*.sql scripts and provide a REPL.
#
# Usage:
#   sqlcl-connect.sh                                    # interactive REPL
#   sqlcl-connect.sh -f /opt/hardening/10_profiles.sql  # run a script, then exit
#   sqlcl-connect.sh @/opt/hardening/10_profiles.sql    # SQLcl-native @ form (same)
#
# TLS modes, credential handling, and script/exit behavior are documented in
# README.md. Two behaviors are non-obvious and load-bearing (see below): SQLcl has
# no `-f` flag (we translate it to `@`) and does not auto-exit at end-of-script, and
# a CONNECT from a separate SQLPATH/login.sql does NOT carry into a `@script` run
# (ORA-17008) — so we always CONNECT from the first line of the script we run.

set -euo pipefail

# Shared connection discovery (env/VCAP → DB_* + TLS mode). Sourced so this and the
# oraquery-based scripts cannot drift on how they reach the database.
LOG_PREFIX=sqlcl-connect
export LOG_PREFIX  # consumed by the sourced lib/db-connect.sh (SC2034)
# shellcheck source=../lib/db-connect.sh disable=SC1091
. "$(dirname "$0")/lib/db-connect.sh"

SQLCL_BIN="${SQLCL_BIN:-sql}"
# Baked truststore (PKCS12) + password. Non-secret: holds only public RDS CA certs.
RDS_TRUSTSTORE="${RDS_TRUSTSTORE:-/opt/sqlcl-run/rds-truststore.p12}"
RDS_TRUSTSTORE_PASS="${RDS_TRUSTSTORE_PASS:-changeit}"

command -v "$SQLCL_BIN" >/dev/null 2>&1 \
    || { echo "sqlcl-connect: SQLcl ('${SQLCL_BIN}') not found on PATH" >&2; exit 1; }

resolve_db_connection

TLS_MODE="${ORAQUERY_TLS:-verify-ca}"

# --- Build the SQLcl / JDBC connect string ---------------------------------
# SQLcl accepts an EZConnect string for plaintext and a full JDBC URL for TCPS.
# We choose based on the resolved, fail-closed TLS mode (never on the port alone).
case "$TLS_MODE" in
    disable)
        # Plaintext EZConnect: user/pass@host:port/service.
        CONNECT_ID="${DB_HOST}:${DB_PORT}/${DB_SERVICE}"
        ;;
    require)
        # Encrypt-only TLS (no server-cert verification) is NOT MITM-safe and NOT
        # valid compliance evidence — the "false-compliant" failure mode this runner
        # exists to prevent. Rather than warn-and-continue (a warning is easy to miss
        # in CI), fail closed: a compliance run must never proceed over an unverified
        # channel. Use verify-ca (the default) for real runs, or disable for a local
        # plaintext dev DB. If a future non-evidence use genuinely needs encrypt-only,
        # add it back deliberately then.
        echo "sqlcl-connect: ORAQUERY_TLS=require (encrypt-only, no certificate verification) is not permitted — not MITM-safe, not compliance evidence. Use verify-ca (default) or disable (local dev)." >&2
        exit 2
        ;;
    verify-ca)
        # Verified TLS on TCPS using the baked RDS CA truststore.
        [ -r "$RDS_TRUSTSTORE" ] || {
            echo "sqlcl-connect: ORAQUERY_TLS=verify-ca but truststore not readable: ${RDS_TRUSTSTORE}" >&2
            exit 1
        }
        CONNECT_ID="jdbc:oracle:thin:@tcps://${DB_HOST}:${DB_PORT}/${DB_SERVICE}"
        export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} \
-Djavax.net.ssl.trustStore=${RDS_TRUSTSTORE} \
-Djavax.net.ssl.trustStoreType=PKCS12 \
-Djavax.net.ssl.trustStorePassword=${RDS_TRUSTSTORE_PASS} \
-Doracle.net.ssl_server_dn_match=true"
        ;;
    *)
        echo "sqlcl-connect: unknown ORAQUERY_TLS='${TLS_MODE}' (want verify-ca|disable)" >&2
        exit 2
        ;;
esac

echo "sqlcl-connect: target ${DB_HOST}:${DB_PORT}/${DB_SERVICE} as ${DB_USER} (TLS mode: ${TLS_MODE})" >&2

# We NEVER put the password on argv (it would show in `ps`). We issue the CONNECT
# from a transient SQL file (mode 0600, in a 0700 temp dir removed on exit); the
# credential lives only there for the life of the process. We do NOT use a SQLPATH
# login.sql for this: with `sql /nolog @script`, a connect made from login.sql does
# not reliably carry into the @script session (observed ORA-17008 "Closed
# connection"). Issuing CONNECT as the first line of the SAME script we run is
# reliable, so both the REPL and batch paths connect from an explicit script.
#
# The password goes into a DOUBLE-QUOTED SQLcl connect literal. A literal `"` in the
# password would otherwise terminate that literal early — a malformed connect AND a
# credential leak, since SQLcl echoes the offending line to stderr. Doubling every
# `"` is the SQL-quoted-literal escape (a `""` inside a `"..."` literal is one `"`),
# so an RDS-generated password containing quotes connects correctly and never leaks.
escaped_password="${DB_PASSWORD//\"/\"\"}"
CONNECT_CMD="connect ${DB_USER}/\"${escaped_password}\"@${CONNECT_ID}"

umask 077
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

# --- Interactive REPL (no args) --------------------------------------------
# `-nologo` is NOT a valid SQLcl flag; the banner is harmless. Start `/nolog` and
# run a connect-only script so the session lands connected, then hand the prompt to
# the user. `@file` does NOT auto-exit, so control drops to the interactive prompt.
if [ "$#" -eq 0 ]; then
    repl_login="${work_dir}/connect.sql"
    printf '%s\n' "$CONNECT_CMD" > "$repl_login"
    echo "sqlcl-connect: starting interactive SQLcl REPL (type 'exit' to quit)" >&2
    exec "$SQLCL_BIN" /nolog "@$repl_login"
fi

# --- Script / batch run -----------------------------------------------------
# Normalize `-f <file>` (our alias; SQLcl has no -f) to SQLcl's native `@<file>`.
# SQLcl does NOT auto-exit at end-of-script, so we drive it through a tiny wrapper
# script that: CONNECTs, sets WHENEVER SQLERROR/OSERROR EXIT (so a failing statement
# returns a non-zero code instead of dropping to the prompt), runs the target with
# `@`, and EXITs. This keeps batch/`cf ssh` runs deterministic. Non-`-f` args are
# forwarded verbatim (advanced/native SQLcl usage — the caller then owns exit).
script_file=""
if [ "$1" = "-f" ] || [ "$1" = "--file" ]; then
    shift
    [ "$#" -gt 0 ] || { echo "sqlcl-connect: -f/--file requires a path" >&2; exit 2; }
    script_file="$1"
    shift
    [ "$#" -eq 0 ] || { echo "sqlcl-connect: -f/--file takes no further arguments (got: $*)" >&2; exit 2; }
elif [ "${1#@}" != "$1" ]; then
    # First arg is a native @file token.
    script_file="${1#@}"
    shift
    [ "$#" -eq 0 ] || { echo "sqlcl-connect: @<file> takes no further arguments (got: $*)" >&2; exit 2; }
fi

if [ -n "$script_file" ]; then
    [ -r "$script_file" ] || { echo "sqlcl-connect: script not readable: ${script_file}" >&2; exit 2; }
    driver="${work_dir}/run.sql"
    {
        printf '%s\n' "$CONNECT_CMD"
        printf 'WHENEVER SQLERROR EXIT SQL.SQLCODE\n'
        printf 'WHENEVER OSERROR EXIT FAILURE\n'
        printf '@%s\n' "$script_file"
        printf 'EXIT\n'
    } > "$driver"
    exec "$SQLCL_BIN" /nolog "@$driver"
fi

# No -f/@: forward the remaining args verbatim to SQLcl after connecting. We run a
# connect-only script first; SQLcl then processes the forwarded argv in the same
# session. The caller owns exit behavior for this advanced path.
fwd_login="${work_dir}/connect.sql"
printf '%s\n' "$CONNECT_CMD" > "$fwd_login"
exec "$SQLCL_BIN" /nolog "@$fwd_login" "$@"
