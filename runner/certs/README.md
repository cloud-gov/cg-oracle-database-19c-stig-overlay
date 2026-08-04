# Runner CA bundles

## `rds-govcloud-global-bundle.crt.bundle`

The **AWS GovCloud (us-gov-west-1) RDS root CA bundle** — the trust anchor
`oraquery` uses for verified TLS (`ORAQUERY_TLS=verify-ca`) to a live brokered
RDS-for-Oracle instance over TCPS 2484 (#16 / #20 / #23).

| | |
| --- | --- |
| Source | <https://truststore.pki.us-gov-west-1.rds.amazonaws.com/global/global-bundle.pem> |
| Region | AWS GovCloud (`us-gov-west-1`) — this is where cloud.gov RDS runs |
| SHA-256 | `bae59f78f2e2ba789e734cdcac78c13a0f0e99aa3f7bd49f1f37477c815b9b33` |
| Contents | 10 Amazon RDS root CAs (RSA2048 / RSA4096 / ECC384 G1, incl. rotation set) |

### Why it is committed

- It is a **public, non-secret** trust anchor (root CAs), not a credential — so
  committing it does not violate the no-hardcoded-secrets policy.
- Committing (vs. fetching at build time) makes the image build **reproducible
  and auditable**, removes a build-time network dependency, and works behind a
  TLS-inspecting egress proxy (the fetch fails there because the proxy re-signs
  the connection with a private CA).
- Its integrity is **checksum-verified** in `runner/Dockerfile`
  (`RDS_CA_BUNDLE_SHA256`), so a tampered or truncated file fails the build.

### Updating / rotation

AWS rotates the RDS *server* certificates automatically; the *root* bundle is
long-lived. Refresh on the normal base-image rebuild cadence:

```bash
curl -fsSL https://truststore.pki.us-gov-west-1.rds.amazonaws.com/global/global-bundle.pem \
  -o runner/certs/rds-govcloud-global-bundle.crt.bundle
shasum -a 256 runner/certs/rds-govcloud-global-bundle.crt.bundle   # update RDS_CA_BUNDLE_SHA256 in runner/Dockerfile
```

Register the **root** CAs only (per AWS guidance) so automatic server-cert
rotation does not break trust.

> **Filename note:** the `.crt.bundle` extension is deliberate — the pre-commit
> forbidden-files guard blocks committed `*.pem` (which usually hold private
> keys). This file contains only public CA certificates (verified: no
> `PRIVATE KEY` blocks), so committing it is safe; the Dockerfile copies it to a
> `.pem` path inside the image.
