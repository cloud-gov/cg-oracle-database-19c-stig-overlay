# SQLcl runner via the Cloud.gov **Java buildpack** (no Docker image, no registry)

This is an alternative packaging of the same SQLcl runner in `runner/sqlcl/`, using
the Cloud.gov **Java buildpack** instead of a private Docker image. SQLcl is a
pure-Java CLI, so the buildpack's JRE runs it directly — there is **no Dockerfile,
no `buildx` cross-build, and no private registry / Docker Hub credentials** on the
Cloud.gov cell.

## Why this exists (vs. `runner/sqlcl/` Docker image)

The Docker path bakes SQLcl into a **derived image**, which triggers the Oracle OTN
EULA's redistribution restriction — forcing a **private** Docker Hub repo plus
`CF_DOCKER_USERNAME`/`CF_DOCKER_PASSWORD` on the cell (`Makefile` `push-sqlcl-*`).
The buildpack path pushes the vendored SQLcl distribution **into our own app
droplet** in a single Cloud.gov space and interacts over `cf ssh` — no registry
redistribution, no cross-arch build, no registry creds.

| Concern | Docker image (`runner/sqlcl/`) | Java buildpack (this dir) |
| --- | --- | --- |
| OTN redistribution | Derived image → must use a **private** registry | Push into own droplet; no registry redistribution |
| Registry creds on cell | `CF_DOCKER_USERNAME` + `CF_DOCKER_PASSWORD` | None |
| Cross-arch build | `docker buildx --platform linux/amd64` | Buildpack stages on the cell |
| JRE | Oracle base image | Java buildpack |
| Local dev REPL | `make sqlcl-repl` (compose) | Unchanged — keep using the Docker path locally |

> This buildpack path is **Cloud.gov-only**. Keep using the Docker path
> (`make sqlcl-repl` / `make sqlcl-run`) for local iteration against the compose
> 23ai DB — there is no need to vendor SQLcl for local use.

## No drift: shared logic is copied from the single sources at push time

The connection discovery and TLS logic are **not duplicated** here. `make
stage-sqlcl-cf` copies the canonical files into this dir just before `cf push`:

- `runner/lib/db-connect.sh`      → `lib/db-connect.sh`
- `runner/sqlcl/sqlcl-connect.sh` → `sqlcl-connect.sh`
- `hardening/sql/`                → `hardening/`
- `runner/certs/rds-govcloud-global-bundle.crt.bundle` → `certs/rds-govcloud-global-bundle.pem`

These staged copies are git-ignored (see `.gitignore`) so the single sources stay
authoritative. Only `manifest.yml`, `entrypoint.sh`, `.profile.d/`, and this README
are committed.

## One-time: vendor the SQLcl distribution

The OTN EULA governs **use**; you download SQLcl from Oracle and vendor it here (the
same discipline as the Docker path's pinned digest, applied to a zip).

```bash
# Download SQLcl (e.g. 26.2.1.0) from Oracle, verify its published SHA256, then:
unzip sqlcl-*.zip -d runner/sqlcl-cf/vendor/     # yields runner/sqlcl-cf/vendor/sqlcl/bin/sql
```

`vendor/sqlcl/` is git-ignored (large, license-restricted). Record the version +
verified checksum in `vendor/README.md`.

## Deploy + run (Cloud.gov)

```bash
# Stage shared files + push via the Java buildpack (see Makefile target):
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
