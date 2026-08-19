#!/usr/bin/env bash
# .profile.d/10-build-truststore.sh — best-effort truststore build at container
# START. The platform sources .profile.d/*.sh before the app's start command, so
# the long-running app has the truststore ready. It delegates to the shared
# build-truststore.sh (single source of truth) using the pushed app dir as root.
#
# NOTE: a `cf ssh ... -c` exec session does NOT reliably source .profile.d, so
# entrypoint.sh ALSO builds the truststore on demand if missing — this script is
# the start-path convenience, entrypoint.sh is authoritative.
set -euo pipefail

# On a buildpack container the pushed files (and this script) live under $HOME/app.
# Resolve the app dir from this script's own location so it is correct regardless.
APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if p12="$("${APP_ROOT}/build-truststore.sh" "${APP_ROOT}")"; then
  export RDS_TRUSTSTORE="$p12"
  export RDS_TRUSTSTORE_PASS="changeit"
fi
