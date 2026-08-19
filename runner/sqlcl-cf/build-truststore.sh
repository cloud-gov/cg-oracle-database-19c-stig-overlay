#!/usr/bin/env bash
# build-truststore.sh — build the PKCS12 truststore SQLcl's JDBC thin driver needs
# for verify-ca TLS, from the SAME public, checksum-verified RDS CA PEM the Docker
# path and oraquery use. Shared by BOTH invocation paths so they cannot drift:
#   - .profile.d/10-build-truststore.sh  (best-effort, at container start)
#   - entrypoint.sh                       (authoritative, on-demand if missing)
#
# The inputs are PUBLIC CA certs (no secrets); the PEM's integrity is
# checksum-verified so a tampered/truncated bundle fails CLOSED and the app refuses
# verify-ca. keytool comes from the buildpack JRE (Java 17+), resolved robustly
# because the buildpack does NOT export JAVA_HOME to `cf ssh` exec sessions.
#
# Usage: build-truststore.sh <app-root>
#   <app-root> is the dir holding certs/rds-govcloud-global-bundle.pem (i.e. the
#   pushed app dir, $HOME/app on a buildpack container).
#
# On success, prints the truststore path on stdout (nothing else) and exits 0. All
# diagnostics go to stderr. Idempotent: rebuilds each call (fast; ~10 CAs).
set -euo pipefail

APP_ROOT="${1:?usage: build-truststore.sh <app-root>}"
PEM_IN="${APP_ROOT}/certs/rds-govcloud-global-bundle.pem"
P12_OUT="${APP_ROOT}/rds-truststore.p12"
STORE_PASS="changeit"
# Same literal the Docker build verifies — a swapped/truncated file fails closed.
PEM_SHA256="bae59f78f2e2ba789e734cdcac78c13a0f0e99aa3f7bd49f1f37477c815b9b33"

log() { printf 'build-truststore: %s\n' "$*" >&2; }

# Resolve keytool from the buildpack JRE. Honor JAVA_HOME if it already points at a
# valid JRE; else find the buildpack `keytool` under the app dir (java_buildpack
# lays the JRE at <app>/.java-buildpack/**), then $HOME layouts, then PATH.
find_keytool() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/keytool" ]; then
    printf '%s' "${JAVA_HOME}/bin/keytool"; return 0
  fi
  local kt
  kt="$(find "${APP_ROOT}/.java-buildpack" "${HOME:-/home/vcap}/.java-buildpack" "${HOME:-/home/vcap}/.java" \
             -type f -name keytool 2>/dev/null | head -n1 || true)"
  if [ -n "$kt" ] && [ -x "$kt" ]; then printf '%s' "$kt"; return 0; fi
  command -v keytool 2>/dev/null && return 0
  return 1
}

KEYTOOL="$(find_keytool || true)"
[ -n "$KEYTOOL" ] && [ -x "$KEYTOOL" ] \
  || { log "keytool not found (JAVA_HOME=${JAVA_HOME:-unset}; searched ${APP_ROOT}/.java-buildpack, \$HOME/.java-buildpack, PATH)"; exit 1; }

[ -r "$PEM_IN" ] || { log "cannot read PEM bundle: ${PEM_IN}"; exit 1; }

# Fail closed on a tampered/truncated bundle before we trust any cert from it.
echo "${PEM_SHA256}  ${PEM_IN}" | sha256sum -c - >&2 \
  || { log "PEM checksum mismatch — refusing to build truststore"; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Split the multi-cert bundle: keytool -importcert imports only the FIRST cert.
awk -v dir="$work" '
  /-----BEGIN CERTIFICATE-----/ { n++ }
  n > 0 { print > sprintf("%s/cert-%02d.pem", dir, n) }
' "$PEM_IN"

rm -f "$P12_OUT"
count=0
for cert in "$work"/cert-*.pem; do
  [ -e "$cert" ] || { log "no certificates found in ${PEM_IN}"; exit 1; }
  "$KEYTOOL" -importcert -noprompt -trustcacerts \
    -alias "rds-ca-$(basename "$cert" .pem)" \
    -file "$cert" \
    -keystore "$P12_OUT" -storetype PKCS12 \
    -storepass "$STORE_PASS" >&2
  count=$((count + 1))
done

imported="$("$KEYTOOL" -list -keystore "$P12_OUT" -storetype PKCS12 -storepass "$STORE_PASS" 2>/dev/null \
  | grep -c 'trustedCertEntry' || true)"
[ "$imported" = "$count" ] && [ "$count" -gt 0 ] \
  || { log "import count mismatch (bundle=${count}, store=${imported})"; exit 1; }
log "imported ${imported} CA certificate(s) into ${P12_OUT}"

# The truststore path on stdout so callers can capture it.
printf '%s\n' "$P12_OUT"
