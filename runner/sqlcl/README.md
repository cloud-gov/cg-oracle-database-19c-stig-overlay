# SQLcl runner — **LOCAL 23ai testing only** (interactive REPL + `hardening/sql/*.sql`)

> **Scope:** This image is for **local development against the compose Oracle 23ai
> Free DB only** — one-off interactive queries and running the `hardening/sql/*.sql`
> assessment scripts while iterating. **It is built locally and never pushed.**
>
> **For Cloud.gov, use the Java-buildpack app** in [`../sqlcl-cf/`](../sqlcl-cf/)
> (`make push-sqlcl-cf`). The buildpack path is the only supported in-boundary
> runner — see [ADR-0002](../../docs/adr/0002-sqlcl-runner-docker-vs-java-buildpack.md).
> A Docker image cannot run in-boundary without being re-based on `ubuntu-hardened`
> and onboarded to the mandatory container-scanning pipeline (internal ADR-0007),
> which also collides with the Oracle OTN redistribution restriction. Keeping this
> image local-only sidesteps both.

`db-query.sh` (the pure-Go `oraquery` wrapper) is deliberately **plain SQL only**:
it runs one statement per process and does **not** interpret SQL\*Plus/SQLcl
directives (`SET`, `PROMPT`, `WHENEVER`, `DEFINE`, substitution variables, a bare
`/`, anonymous PL/SQL blocks). That makes it unsuitable for an interactive session
and for the `hardening/sql/*.sql` scripts, which are written for a full interpreter.

This image fills that gap **locally** using **Oracle SQLcl** (Java-based, free under
the OTN license) — a full SQL\*Plus/SQLcl interpreter that **can** run those scripts
and provides a REPL. It reuses the **same** connection discovery
(`lib/db-connect.sh`: env + `VCAP_SERVICES`) and the **same** fail-closed TLS posture
as the buildpack runner, so the local dev tool and the Cloud.gov runner cannot drift
on how they reach the database or run scripts.

## Why an overlay (built locally, never pushed)

We do **not** build SQLcl or bundle a JRE. This is a **thin overlay** on Oracle's
official SQLcl image (`container-registry.oracle.com/database/sqlcl`) that adds only:

1. `lib/db-connect.sh` — the shared env/`VCAP_SERVICES` connection resolver.
2. `sqlcl-connect.sh` — the entrypoint: resolves `DB_*`, builds an EZConnect
   (plaintext) or JDBC `tcps://` (TLS) connect string, picks a fail-closed TLS
   mode, and starts either a REPL (no args) or runs a script (`-f`/`@`).
3. A PKCS12 **truststore** built at image-build time (unused locally — the compose
   23ai DB is plaintext loopback — but kept so the overlay stays identical to what
   `sqlcl-connect.sh` expects).
4. The `hardening/sql/` scripts baked at `/opt/hardening`.

> **OTN license + hardening:** because this image bundles OTN-licensed SQLcl and is
> **not** built on `ubuntu-hardened`, it is **built locally and never pushed to any
> registry**. That keeps it clear of the OTN redistribution restriction AND the
> in-boundary container-scanning/hardening pipeline (internal ADR-0007). The Makefile
> has **no** push target for this image by design.

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

# Interactive REPL (one-off queries):
make sqlcl-repl

# Run a hardening/assessment script (baked at /opt/hardening):
make sqlcl-run SQL=00_connectivity_check.sql
make sqlcl-run SQL=10_profiles.sql

make db-down                                 # stop the DB
```

Local runs set `ORAQUERY_TLS=disable` (plaintext 1521) automatically — the local
23ai DB is loopback-only. **Nothing a local 23ai run produces is compliance
evidence** (23ai ≠ 19c/SE2/RDS); it only proves the scripts/wrapper work. Authoritative
pass/fail requires a live brokered GovCloud RDS run via the buildpack app.

Equivalent raw `docker run` (what the Makefile does):

```bash
docker run --rm -it \
  --network cg-cinc-audit-oracle_default \
  -e DB_USER=system -e DB_PASSWORD=devpw_ChangeMe1 \
  -e DB_HOST=oracle -e DB_SERVICE=FREEPDB1 -e DB_PORT=1521 \
  -e ORAQUERY_TLS=disable \
  cg-sqlcl-oracle:local                       # REPL; append -f /opt/hardening/<x>.sql to run a script
```

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
| `../lib/db-connect.sh` | Shared connection discovery — reused, not duplicated. Parses `VCAP_SERVICES` with CINC's embedded Ruby, else `ruby`, else `python3`, else `jq` (the buildpack runner's cflinuxfs path), so the SAME resolver works everywhere without drift. |
| `../certs/` | The checksum-verified public RDS CA bundle (single source of truth). |
