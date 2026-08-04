# Runner CA bundles

## `rds-govcloud-global-bundle.crt.bundle`

The **AWS GovCloud RDS CA bundle** — the trust anchor `oraquery` uses for verified
TLS (`ORAQUERY_TLS=verify-ca`) to a live brokered RDS-for-Oracle instance over
TCPS 2484 (#16 / #20 / #23). This is the single source of truth for the bundle's
provenance, contents, and rotation; the Dockerfile / `.gitignore` / runner README
just point here.

| | |
| --- | --- |
| Source | AWS RDS truststore `global-bundle.pem` (GovCloud): <https://truststore.pki.us-gov-west-1.rds.amazonaws.com/global/global-bundle.pem> |
| SHA-256 | `bae59f78f2e2ba789e734cdcac78c13a0f0e99aa3f7bd49f1f37477c815b9b33` |
| Contents | **10 certificates: 6 self-signed roots + 4 intermediates**, covering **both** GovCloud regions (`us-gov-west-1` and `us-gov-east-1`), RSA2048 / RSA4096 / ECC384 G1. No private keys. |

### Contents (decoded)

Roots (self-signed; long-lived, 2062 / 2121):

- `Amazon RDS us-gov-west-1 Root CA RSA2048 G1` (2062), `RSA4096 G1` (2121), `ECC384 G1` (2121)
- `Amazon RDS us-gov-east-1 Root CA RSA2048 G1` (2062), `RSA4096 G1` (2121), `ECC384 G1` (2121)

Intermediates (`CA:TRUE, pathlen:0`; **earliest expiry ~2027**):

- `Amazon RDS us-gov-west-1 RSA2048 G1` (Apr 2027), `RSA4096 G1` (Jan 2027)
- `Amazon RDS us-gov-east-1 RSA2048 G1` (Apr 2027), `RSA4096 G1` (Jan 2027)

This is AWS's full `global-bundle.pem` (roots **and** intermediates). Trust is
anchored on the self-signed roots; the intermediates are included as published by
AWS. AWS rotates the RDS **server** certificates automatically.

### Why it is committed

- It is a **public, non-secret** trust anchor (CA certs, no private keys) — so
  committing it does not violate the no-hardcoded-secrets policy.
- Committing (vs. fetching at build time) makes the image build **reproducible and
  auditable**, removes a build-time network dependency, and works behind a
  TLS-inspecting egress proxy (a build-time fetch fails there because the proxy
  re-signs the connection with a private CA).
- Integrity is **checksum-verified** in `runner/Dockerfile` (`sha256sum -c` against
  a literal in the `RUN`, not a `--build-arg`-overridable value), so a tampered or
  truncated file fails the build closed.

### Filename note

The `.crt.bundle` extension is deliberate: the pre-commit forbidden-files guard
blocks committed `*.pem` (which usually hold private keys). This file contains only
public CA certificates, so it is committed as `.crt.bundle`; the Dockerfile copies
it to a `.pem` path inside the image.

### Updating / rotation

The **roots** are good until 2062+, but the **intermediates expire in early 2027**,
so plan to refresh before then (and on the normal base-image rebuild cadence):

```bash
curl -fsSL https://truststore.pki.us-gov-west-1.rds.amazonaws.com/global/global-bundle.pem \
  -o runner/certs/rds-govcloud-global-bundle.crt.bundle
shasum -a 256 runner/certs/rds-govcloud-global-bundle.crt.bundle
# then update the inlined checksum in the runner/Dockerfile RUN step
```

Verify the new bundle contains no private keys before committing:

```bash
grep -c "PRIVATE KEY" runner/certs/rds-govcloud-global-bundle.crt.bundle   # must be 0
```
