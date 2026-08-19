#!/usr/bin/env bash
# entrypoint.sh — cf-ssh entrypoint for the Java-buildpack SQLcl runner. It is the
# buildpack-path analogue of the Docker image's ENTRYPOINT (sqlcl-connect.sh): it
# locates the VENDORED SQLcl launcher and the truststore built by .profile.d, then
# delegates to the SHARED sqlcl-connect.sh so connection discovery + TLS logic are
# identical to the Docker path (no drift). All the real work lives in the shared
# lib/db-connect.sh + sqlcl-connect.sh — this only wires buildpack-specific paths.
#
# Usage (over cf ssh) — the default cf ssh cwd is $HOME/app, so use $HOME/app paths
# (or ./entrypoint.sh from that cwd). Same argument surface as the Docker path:
#   cf ssh cg-sqlcl-oracle-cf -c '$HOME/app/entrypoint.sh -f $HOME/app/hardening/00_connectivity_check.sql'
#   cf ssh -t cg-sqlcl-oracle-cf -c '$HOME/app/entrypoint.sh'     # interactive REPL
set -euo pipefail

# App root: on a buildpack app, pushed files land under $HOME (…/app). Resolve
# relative to THIS script so it works regardless of cwd under cf ssh.
APP_ROOT="$(cd "$(dirname "$0")" && pwd)"

# --- Ensure JAVA_HOME points at the buildpack's JRE ------------------------
# The Java buildpack exports JAVA_HOME/PATH only for the START command, NOT for a
# `cf ssh ... -c` exec session (observed: JAVA_HOME empty, `java` not on PATH → SQLcl
# fell back to a system Java 8 and refused to run). Resolve it ourselves from the
# buildpack's installed JRE so SQLcl (and keytool) reliably get Java 17+. Honor a
# preset JAVA_HOME first; else find the buildpack `java` under the app dir.
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/java" ]; then
    _java_bin="$(find "${APP_ROOT}/.java-buildpack" "${HOME}/.java-buildpack" "${HOME}/.java" \
                     -type f -name java 2>/dev/null | head -n1 || true)"
    if [ -n "$_java_bin" ] && [ -x "$_java_bin" ]; then
        JAVA_HOME="$(cd "$(dirname "$_java_bin")/.." && pwd)"
        export JAVA_HOME
    else
        echo "entrypoint: could not locate a buildpack JRE (searched ${APP_ROOT}/.java-buildpack, ${HOME}/.java-buildpack, ${HOME}/.java)" >&2
        echo "entrypoint: SQLcl requires Java 11+; ensure the Java buildpack staged a JRE" >&2
        exit 1
    fi
fi
# Put the resolved JRE on PATH so SQLcl's bin/sql (and any `keytool`) find `java`.
export PATH="${JAVA_HOME}/bin:${PATH}"
# Cosmetic version banner — MUST NOT abort the run. `java -version | head` under
# `set -o pipefail` would make a SIGPIPE/head-close kill the script, so guard it.
_java_ver="$("${JAVA_HOME}/bin/java" -version 2>&1 | head -n1 || true)"
echo "entrypoint: using JAVA_HOME=${JAVA_HOME} (${_java_ver})" >&2

# --- Locate the vendored SQLcl launcher ------------------------------------
# The SQLcl distribution is vendored under vendor/sqlcl/ (see vendor/README.md).
# We do NOT bundle a JRE — the Java buildpack provides one; SQLcl's bin/sql picks
# up JAVA_HOME from the buildpack environment.
SQLCL_LAUNCHER="${APP_ROOT}/vendor/sqlcl/bin/sql"
if [ ! -x "$SQLCL_LAUNCHER" ]; then
    echo "entrypoint: vendored SQLcl launcher not found/executable at ${SQLCL_LAUNCHER}" >&2
    echo "entrypoint: vendor the SQLcl distribution under vendor/sqlcl/ before cf push (see vendor/README.md)" >&2
    exit 1
fi
export SQLCL_BIN="$SQLCL_LAUNCHER"

# --- Truststore: build on demand (authoritative) ---------------------------
# .profile.d builds this at container start, but a `cf ssh ... -c` exec session
# does NOT reliably source .profile.d, so build it here if it is missing. Uses the
# SHARED build-truststore.sh (single source of truth) rooted at the app dir. The
# script needs JAVA_HOME/keytool, which we resolved and exported above.
RDS_TRUSTSTORE="${RDS_TRUSTSTORE:-${APP_ROOT}/rds-truststore.p12}"
RDS_TRUSTSTORE_PASS="${RDS_TRUSTSTORE_PASS:-changeit}"
if [ ! -r "$RDS_TRUSTSTORE" ]; then
    echo "entrypoint: truststore ${RDS_TRUSTSTORE} missing — building it now" >&2
    RDS_TRUSTSTORE="$("${APP_ROOT}/build-truststore.sh" "${APP_ROOT}")"
fi
export RDS_TRUSTSTORE RDS_TRUSTSTORE_PASS

# --- Delegate to the SHARED connect wrapper (single source of truth) -------
exec "${APP_ROOT}/sqlcl-connect.sh" "$@"
