#!/usr/bin/env bash
# db-query.sh — run ad hoc SQL against the Cloud.gov (or local dev) Oracle DB
# using the same connection discovery and the same pure-Go client (oraquery) the
# STIG validation runner uses. It is a thin, honest wrapper: it resolves the
# connection from the environment (and, on Cloud.gov, from VCAP_SERVICES), builds
# the oraquery connect string, and streams oraquery's CSV straight through.
#
# Usage:
#   db-query.sh -c "SELECT 1 FROM dual"     # run a single statement
#   db-query.sh -f path/to/query.sql        # run each ';'-separated statement in a file
#   echo "SELECT 1 FROM dual" | db-query.sh # statement on stdin (no -c/-f)
#   ORAQUERY_TLS=disable db-query.sh -c ...  # override the TLS mode via the env var
#
# Exactly one of -c/--command or -f/--file may be given. With neither, SQL is
# read from stdin (a single statement). A trailing ';' on any statement is fine.
#
# PLAIN SQL ONLY — this is NOT a SQL*Plus/SQLcl replacement. oraquery executes
# each statement verbatim, so SQL*Plus directives (SET, PROMPT, WHENEVER, DEFINE,
# substitution variables, a bare '/', anonymous PL/SQL blocks) are NOT interpreted
# and will cause ORA-00900 or be mis-split by the ';' splitter. Scripts written
# for sqlplus/sqlcl (e.g. hardening/sql/*.sql) must be run with those tools (not
# shipped here — OTN EULA); pass their individual SELECTs via -c for ad hoc checks.
#
# On Cloud.gov, run it over cf ssh against the bound runner app, e.g.:
#   cf ssh cg-cinc-audit-oracle-runner \
#     -c "/usr/local/bin/db-query.sh -c 'SELECT banner FROM v\$version'"
# (mind shell quoting of $ and the connect string; single-quote the SQL).
#
# REPL: an interactive REPL is intentionally NOT provided. oraquery runs exactly
# one statement per process (it reads a statement on stdin, runs it, exits), so a
# true sqlplus-style session is not native here, and cf-service-connect does not
# yet tunnel Oracle for a local client. Tracked upstream:
#   https://github.com/cloud-gov/cf-service-connect/issues (Oracle support needed).
#
# Connection env & TLS: identical contract to run-validation.sh — see
# lib/db-connect.sh. Required: DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE (or an
# aws-rds "ORCL" binding in VCAP_SERVICES). TLS defaults to verify-ca for remote
# targets (needs ORAQUERY_CA_BUNDLE; the image bakes the RDS CA) and disable for
# local dev targets; override by setting ORAQUERY_TLS in the environment.
#
# Output: whatever oraquery emits — a CSV header row then data rows — passed
# through unmodified. Errors go to stderr; the exit status is oraquery's.

set -euo pipefail

# Shared connection discovery (env/VCAP → DB_* + TLS mode). Sourced so this
# script and run-validation.sh cannot drift on how they reach the database.
LOG_PREFIX=db-query
export LOG_PREFIX  # consumed by the sourced lib/db-connect.sh (SC2034)
# shellcheck source=lib/db-connect.sh disable=SC1091
. "$(dirname "$0")/lib/db-connect.sh"

ORAQUERY_BIN="${ORAQUERY_BIN:-/usr/local/bin/oraquery}"

# --- CLI args --------------------------------------------------------------
COMMAND=""
FILE=""
have_command=
have_file=

usage() {
    # Lines 2..42 of this file are the usage/contract block.
    sed -n '2,42s/^# \{0,1\}//p' "$0"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -c | --command)
            shift
            [ "$#" -gt 0 ] || { echo "db-query: -c/--command requires a value" >&2; exit 2; }
            COMMAND="$1"
            have_command=1
            ;;
        --command=*)
            COMMAND="${1#--command=}"
            have_command=1
            ;;
        -f | --file)
            shift
            [ "$#" -gt 0 ] || { echo "db-query: -f/--file requires a value" >&2; exit 2; }
            FILE="$1"
            have_file=1
            ;;
        --file=*)
            FILE="${1#--file=}"
            have_file=1
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "db-query: unknown argument '${1}'" >&2
            exit 2
            ;;
    esac
    shift
done

if [ -n "$have_command" ] && [ -n "$have_file" ]; then
    echo "db-query: -c/--command and -f/--file are mutually exclusive" >&2
    exit 2
fi

export PATH="/opt/cinc-auditor/embedded/bin:/usr/local/bin:${PATH}"
[ -x "$ORAQUERY_BIN" ] || { echo "db-query: oraquery not found at ${ORAQUERY_BIN}" >&2; exit 1; }

resolve_db_connection

# The password is embedded in the connect string (as the InSpec resource does);
# it is NEVER logged — the target line below omits it.
CONN="${DB_USER}/${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_SERVICE}"

echo "db-query: target ${DB_HOST}:${DB_PORT}/${DB_SERVICE} as ${DB_USER} (TLS mode: ${ORAQUERY_TLS:-verify-ca})" >&2

# oraquery is one-statement-per-process: it reads the statement from stdin, takes
# the connect string as an arg, and strips a trailing ';' itself.
run_statement() {
    local sql="$1"
    printf '%s\n' "$sql" | "$ORAQUERY_BIN" "$CONN"
}

# --- Gather the statement(s) ----------------------------------------------
if [ -n "$have_command" ]; then
    [ -n "${COMMAND//[[:space:]]/}" ] || { echo "db-query: -c/--command is empty" >&2; exit 2; }
    run_statement "$COMMAND"
    exit $?
fi

if [ -n "$have_file" ]; then
    [ -f "$FILE" ] || { echo "db-query: file not found: ${FILE}" >&2; exit 2; }
    # Split the file on ';' and run each statement (oraquery is one-per-process).
    # `read -d ';'` keeps newlines inside a statement; `|| [ -n "$stmt" ]` captures
    # a final statement with no trailing ';'. Simple ';' split, NOT a SQL parser —
    # a ';' inside a string literal or PL/SQL block would be mis-split.
    ran_any=
    rc=0
    file_sql="$(cat "$FILE")"
    while IFS= read -r -d ';' stmt || [ -n "$stmt" ]; do
        [ -n "${stmt//[[:space:]]/}" ] || continue
        ran_any=1
        # Do NOT let a failing statement abort or be swallowed: capture each
        # statement's exit code and remember the last non-zero one, so a partial
        # failure is reported (rc!=0) rather than masked by the final `exit 0`.
        stmt_rc=0
        run_statement "$stmt" || stmt_rc=$?
        if [ "$stmt_rc" -ne 0 ]; then
            rc=$stmt_rc
            echo "db-query: statement failed (exit ${stmt_rc}); continuing" >&2
        fi
    done <<<"$file_sql"
    [ -n "$ran_any" ] || { echo "db-query: no SQL statements found in ${FILE}" >&2; exit 2; }
    exit "$rc"
fi

# No -c/-f: read a single statement from stdin.
stdin_sql="$(cat)"
[ -n "${stdin_sql//[[:space:]]/}" ] || { echo "db-query: no SQL provided (use -c, -f, or pipe SQL on stdin)" >&2; exit 2; }
run_statement "$stdin_sql"
