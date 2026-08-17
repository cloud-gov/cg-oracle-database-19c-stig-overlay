#!/usr/bin/env bash
# build-truststore.sh — convert the checksum-verified RDS CA PEM bundle into a
# PKCS12 Java truststore for SQLcl's JDBC thin driver (verify-ca / TCPS 2484).
#
# oraquery consumes the PEM directly; SQLcl (Java) needs a keystore, so this is the
# ONE place that conversion happens. Run at image BUILD time (see Dockerfile) so the
# result is reproducible and no per-start work is needed. The inputs are PUBLIC CA
# certs (no private keys); the output truststore is likewise non-secret.
#
# keytool -importcert imports only the FIRST certificate from a multi-cert PEM, so
# we split the bundle and import each cert under a unique alias.
#
# Usage: build-truststore.sh <pem-bundle-in> <p12-out> <store-pass>
set -euo pipefail

PEM_IN="${1:?usage: build-truststore.sh <pem-in> <p12-out> <store-pass>}"
P12_OUT="${2:?usage: build-truststore.sh <pem-in> <p12-out> <store-pass>}"
STORE_PASS="${3:?usage: build-truststore.sh <pem-in> <p12-out> <store-pass>}"

[ -r "$PEM_IN" ] || { echo "build-truststore: cannot read PEM bundle: ${PEM_IN}" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Split the bundle into one file per certificate (portable awk; no csplit dep).
awk -v dir="$work" '
  /-----BEGIN CERTIFICATE-----/ { n++ }
  n > 0 { print > sprintf("%s/cert-%02d.pem", dir, n) }
' "$PEM_IN"

count=0
rm -f "$P12_OUT"
for cert in "$work"/cert-*.pem; do
    [ -e "$cert" ] || { echo "build-truststore: no certificates found in ${PEM_IN}" >&2; exit 1; }
    keytool -importcert -noprompt -trustcacerts \
        -alias "rds-ca-$(basename "$cert" .pem)" \
        -file "$cert" \
        -keystore "$P12_OUT" -storetype PKCS12 \
        -storepass "$STORE_PASS"
    count=$((count + 1))
done

imported="$(keytool -list -keystore "$P12_OUT" -storetype PKCS12 -storepass "$STORE_PASS" 2>/dev/null \
    | grep -c 'trustedCertEntry' || true)"
echo "build-truststore: imported ${imported} CA certificate(s) into ${P12_OUT} (from ${count} in bundle)" >&2
[ "$imported" = "$count" ] && [ "$count" -gt 0 ] \
    || { echo "build-truststore: import count mismatch (bundle=${count}, store=${imported})" >&2; exit 1; }
