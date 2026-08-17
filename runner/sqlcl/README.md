# SQLcl runner — interactive REPL + runs the `hardening/sql/*.sql` scripts

`db-query.sh` (the pure-Go `oraquery` wrapper) is deliberately **plain SQL only**:
it runs one statement per process and does **not** interpret SQL\*Plus/SQLcl
directives (`SET`, `PROMPT`, `WHENEVER`, `DEFINE`, substitution variables, a bare
`/`, anonymous PL/SQL blocks). That makes it unsuitable for an interactive session
and for the `hardening/sql/*.sql` scripts, which are written for a full interpreter.

This image fills that gap using **Oracle SQLcl** (Java-based, free under the OTN
license) — a full SQL\*Plus/SQLcl interpreter that **can** run those scripts and
provides a REPL. It reuses the **same** connection discovery (`lib/db-connect.sh`:
env + `VCAP_SERVICES`) and the **same** fail-closed TLS posture as the CINC runner,
so the two cannot drift on how they reach the database.

## Why an overlay, not our own image

We do **not** build SQLcl or bundle a JRE. This is a **thin overlay** on Oracle's
official SQLcl image (`container-registry.oracle.com/database/sqlcl`) that adds only:

1. `lib/db-connect.sh` — the shared env/`VCAP_SERVICES` connection resolver.
2. `sqlcl-connect.sh` — the entrypoint: resolves `DB_*`, builds an EZConnect
   (plaintext) or JDBC `tcps://` (TLS) connect string, picks a fail-closed TLS
   mode, and starts either a REPL (no args) or runs a script (`-f`/`@`).
3. A PKCS12 **truststore** built at image-build time from the **same
   checksum-verified public RDS CA PEM** `oraquery` bakes, so verified TLS to a
   live brokered RDS works on TCPS 2484 without extra setup (SQLcl's JDBC thin
   driver needs a Java keystore, not a PEM — see `build-truststore.sh`).
4. The `hardening/sql/` scripts baked at `/opt/hardening` so `cf ssh … -f
   /opt/hardening/<x>.sql` works without mounting anything.

> **⚠️ OTN license.** SQLcl carries the Oracle OTN EULA — free to use, but
> redistribution is restricted. **Unlike** the CINC runner image, this derived
> image **MUST NOT** be pushed to a public registry (e.g. Docker Hub). Push it only
> to a private / Cloud.gov-internal target for `cf ssh` use.

> **Base image is pinned by digest.** The dependency policy forbids floating tags,
> so both the Dockerfile `BASE_IMAGE` ARG and the Makefile `SQLCL_BASE_IMAGE`
> default to a pinned digest:
> `container-registry.oracle.com/database/sqlcl@sha256:c039d51466cea7c76f1e3b3ae4b125e2a73381a884a548737cb65b26e6dd7db1`
> (SQLcl **26.2.1.0**, resolved 2026-08-17). To update: pull the tag, read the
> RepoDigest (`docker inspect <img> --format '{{index .RepoDigests 0}}'`), and
> replace the digest in both places.

## Local use (against the compose 23ai DB)

```bash
make db-up                                   # start Oracle 23ai Free (once)

# Interactive REPL:
make sqlcl-repl

# Run a hardening/assessment script (baked at /opt/hardening):
make sqlcl-run SQL=00_connectivity_check.sql
make sqlcl-run SQL=10_profiles.sql

make db-down                                 # stop the DB
```

Local runs set `ORAQUERY_TLS=disable` (plaintext 1521) automatically — the local
23ai DB is loopback-only. As with the CINC runner, **nothing a local 23ai run
produces is compliance evidence** (23ai ≠ 19c/SE2/RDS).

Equivalent raw `docker run` (what the Makefile does):

```bash
docker run --rm -it \
  --network cg-cinc-audit-oracle_default \
  -e DB_USER=system -e DB_PASSWORD=devpw_ChangeMe1 \
  -e DB_HOST=oracle -e DB_SERVICE=FREEPDB1 -e DB_PORT=1521 \
  -e ORAQUERY_TLS=disable \
  cg-sqlcl-oracle:local                       # REPL; append -f /opt/hardening/<x>.sql to run a script
```

## Cloud.gov (live brokered RDS) use

`cf push --docker-image` **pulls** from a registry the Cloud.gov cell can reach —
it does **not** upload your local image. Because the OTN license forbids public
redistribution, the image is stored in a **private** Docker Hub repo
(`pburkholder/cg-sqlcl-oracle`, set to Private) and the cell pulls it with
registry credentials.

```bash
# One-time: log in as the Docker Hub account that owns the private repo.
docker login

# Build (linux/amd64) + push to the PRIVATE Docker Hub repo, then cf push an idle
# app that pulls it. cf needs registry creds for the private pull:
export CF_DOCKER_PASSWORD='<dockerhub-access-token>'   # never commit; read from env by cf
make push-sqlcl-cloudgov CF_DOCKER_USERNAME='<dockerhub-user>'

cf bind-service cg-sqlcl-oracle <oracle-db>
cf restage cg-sqlcl-oracle

# Run a SELECT-only assessment script (VCAP resolves the ORCL binding; verify-ca on TCPS 2484):
cf ssh cg-sqlcl-oracle -c "/opt/sqlcl-run/sqlcl-connect.sh -f /opt/hardening/00_connectivity_check.sql"

# Interactive REPL (note -t for a TTY):
cf ssh -t cg-sqlcl-oracle -c "/opt/sqlcl-run/sqlcl-connect.sh"
```

> **OTN license:** the Docker Hub repo MUST be **Private**. This image bundles
> Oracle SQLcl, whose OTN EULA restricts redistribution — do not make the repo
> public.

Connection coordinates come from the `aws-rds` `ORCL` binding in `VCAP_SERVICES`,
exactly as for `run-validation.sh` / `db-query.sh`. For a remote target the TLS
mode defaults to **verify-ca** using the baked truststore; a plaintext/unverified
connection to a live RDS is refused (fail closed).

## TLS modes (`ORAQUERY_TLS`)

Same env var and fail-closed semantics as `oraquery`, mapped to SQLcl/JDBC:

| `ORAQUERY_TLS` | SQLcl connect | Use for |
| --- | --- | --- |
| `verify-ca` (**default** for remote) | JDBC `tcps://` + baked PKCS12 truststore, `ssl_server_dn_match=true` | Real brokered RDS (TCPS 2484). Only mode valid toward evidence. |
| `require` | JDBC `tcps://`, `ssl_server_dn_match=false` (encrypt-only, **no** cert verification) | Narrow debugging only. Not MITM-safe. |
| `disable` | EZConnect plaintext `host:port/service` | A **local** dev DB only (23ai on 1521). |

`lib/db-connect.sh` auto-selects `disable` only for a loopback/local target when
`ORAQUERY_TLS` is unset; any non-local target inherits the fail-closed `verify-ca`
default.

## Credential handling

The password is **never** placed on `argv` (it would show in `ps`). The wrapper
writes a transient SQL file (mode 0600, in a 0700 temp dir removed on exit) whose
**first line** is `connect user/"password"@…`, then runs it with `sql /nolog
@file`. The `connect` and the actual work live in the **same** script so the
connection reliably carries into the session — a connect made from a separate
`SQLPATH`/`login.sql` did **not** carry into a `@script` run (it produced
`ORA-17008: Closed connection`), so that approach is deliberately not used. The
`sqlcl-connect:` log line omits the password.

## Script argument (`-f` / `@`) and exit behavior

SQLcl has **no** `-f` flag and does **not** auto-exit at end-of-script (it would
drop to the `SQL>` prompt). The wrapper handles both:

- `-f <file>` is a convenience alias translated to SQLcl's native `@<file>`.
- For a script it generates a tiny driver that `connect`s, sets `WHENEVER SQLERROR
  EXIT SQL.SQLCODE` + `WHENEVER OSERROR EXIT FAILURE`, runs the target with `@`,
  then `EXIT`s — so batch / `cf ssh` runs terminate deterministically with a
  meaningful exit code instead of hanging at the prompt.
- Any other args (not `-f`/`@`) are forwarded verbatim to SQLcl after a
  connect-only script; the caller then owns exit behavior.

## Files

| Path | Purpose |
| --- | --- |
| `Dockerfile` | Thin overlay on the official OTN SQLcl image; bakes the truststore + scripts; runs non-root. |
| `sqlcl-connect.sh` | Entrypoint: resolve `DB_*`/TLS (shared lib), build connect string, REPL or run a script. |
| `build-truststore.sh` | Build-time PEM→PKCS12 conversion (per-cert import; the RDS bundle has 10 CAs). |
| `../lib/db-connect.sh` | Shared connection discovery — reused, not duplicated. Parses `VCAP_SERVICES` with CINC's embedded Ruby, else `ruby`, else `python3`, so the SAME resolver works in both the CINC runner (has Ruby) and the stock SQLcl image (has only python3) without drift. |
| `../certs/` | The checksum-verified public RDS CA bundle (single source of truth). |
