# SQLcl runner — **Cloud.gov (in-boundary)** via the Java buildpack

**Why this subdirectory exists:** this is the **only** supported way to run the SQLcl
interpreter (interactive queries + the `hardening/sql/*.sql` assessment scripts)
against a brokered Oracle DB **inside the Cloud.gov boundary**. SQLcl is pure Java, so
`cf push` through the platform Java buildpack runs it directly — no Docker image, no
registry, no registry credentials, no cross-arch build.

A Docker image is deliberately **not** used in-boundary: it would be a
public-registry-derived, non-`ubuntu-hardened` image and so must first be re-based on
`ubuntu-hardened` and onboarded to the mandatory container-scanning/hardening pipeline
(ECR/Grype/ClamAV/`usg`), which also collides with the Oracle OTN redistribution
restriction. The buildpack app avoids all of that: it pulls from no public registry
and — as a `cflinuxfs` buildpack app — is outside that pipeline's scope. It is also the
form a **customer** (who owns final DB hardening) can self-service `cf push` into their
own space.

> The Docker image in [`../sqlcl/`](../sqlcl/) is retained for **local 23ai dev testing
> only** (`make sqlcl-repl` / `make sqlcl-run`) — built locally, never pushed. It runs
> the same wrapper + SQL scripts, so local dev and this in-boundary runner cannot drift.

## No drift: shared logic is copied from the single sources at push time

The connection discovery and TLS logic are **not duplicated** here. `make
stage-sqlcl-cf` copies the canonical files into this dir just before `cf push`:

- `runner/lib/db-connect.sh`      → `lib/db-connect.sh`
- `runner/sqlcl/sqlcl-connect.sh` → `sqlcl-connect.sh`
- `hardening/sql/`                → `hardening/`
- `runner/certs/rds-govcloud-global-bundle.crt.bundle` → `certs/rds-govcloud-global-bundle.pem`

These staged copies are git-ignored (see `.gitignore`) so the single sources stay
authoritative. Only `manifest.yml`, `entrypoint.sh`, `build-truststore.sh`,
`.profile.d/`, and this README are committed.

## Verified SQLcl distribution

`make push-sqlcl-cf` downloads SQLcl 26.3.0 directly from Oracle and verifies
Oracle's published MD5 and SHA1 checksums before extracting it. A failed download,
checksum, archive, or version check stops before `cf push` and does not replace an
existing verified distribution.

```bash
# Download, verify, and extract without deploying:
make vendor-sqlcl-cf

# Offline development only (the normal path downloads directly from Oracle):
make vendor-sqlcl-cf SQLCL_CF_ARCHIVE_PATH="$PWD/sqlcl-26.3.0.260.1620.zip"
```

`vendor/sqlcl/` is git-ignored because the distribution is large and Oracle-licensed.
The pinned source and checksums are recorded in `vendor/README.md` and the Makefile.

## Deploy + run (Cloud.gov)

```bash
# Loads .env, authenticates with CF_DEPLOYER_USERNAME/CF_DEPLOYER_PASSWORD,
# stages shared files, downloads and verifies SQLcl, then pushes via the buildpack.
# Set both CF_ORG and CF_SPACE to target explicitly, or pre-target both with cf.
make push-sqlcl-cf

cf bind-service cg-sqlcl-oracle-cf <oracle-db>
cf restart cg-sqlcl-oracle-cf

# The default `cf ssh` working directory is $HOME/app, so invoke with $HOME/app
# paths (or `./entrypoint.sh` after `cd ~/app`).
# Run a SELECT-only assessment script (verify-ca on TCPS 2484; VCAP resolves ORCL):
cf ssh cg-sqlcl-oracle-cf -c '$HOME/app/entrypoint.sh -f $HOME/app/hardening/00_connectivity_check.sql'

# Interactive REPL (note -t for a TTY):
cf ssh -t cg-sqlcl-oracle-cf -c '$HOME/app/entrypoint.sh'
```

TLS modes (`ORAQUERY_TLS`), credential handling, and script/exit behavior are
identical to `runner/sqlcl/README.md` — that logic lives in the shared
`sqlcl-connect.sh` this app delegates to.

## Files

| Path | Purpose |
| --- | --- |
| `manifest.yml` | `cf push` config: Java buildpack (pinned) + pinned JRE 17, idle worker, no route. |
| `entrypoint.sh` | cf-ssh entrypoint: resolve+export JAVA_HOME (buildpack JRE), locate vendored SQLcl, ensure truststore, delegate to shared `sqlcl-connect.sh`. |
| `build-truststore.sh` | Shared truststore builder (PEM→PKCS12 via buildpack `keytool`); called by both `.profile.d` and `entrypoint.sh`. |
| `.profile.d/10-build-truststore.sh` | Best-effort truststore build at container start; delegates to `build-truststore.sh`. |
| `vendor/sqlcl/` | Vendored SQLcl distribution (git-ignored; see `vendor/README.md`). |
| `lib/`, `sqlcl-connect.sh`, `hardening/`, `certs/` | **Staged copies** of the single sources (git-ignored; produced by `make stage-sqlcl-cf`). |
