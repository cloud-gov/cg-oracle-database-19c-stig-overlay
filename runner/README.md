# STIG profile runner (#7)

Executes the Cloud.gov Oracle 19c STIG **overlay** InSpec profile against an Oracle database using **CINC Auditor** (Apache-2.0 FOSS distribution of InSpec) and a purpose-built pure-Go query client (**oraquery**). The runner uses concise CINC CLI output and CINC's normal exit codes. As controls are dispositioned ([#3](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/3)), this run produces the coverage report referenced by [#6](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/6) — static analysis of the profile proved unreliable, so we run it.

The same runner image is intended to double as the **Concourse InSpec runner** for the live-RDS scan ([aws-broker#558](https://github.com/cloud-gov/aws-broker/issues/558)).

## ⚠️ Fidelity — read before trusting any result

| Layer | What it proves |
| --- | --- |
| **This harness** (Oracle **23ai Free**, gvenzl) | The check LOGIC executes and is coherent; which controls are real vs. empty stubs; which error. |
| **NOT proven here** | 19c-specific, SE2-specific, or RDS-specific behavior. |
| **Live RDS proof** (aws-broker#558) | The only source of actual compliance evidence. |

Local runs target **Oracle 23ai Free** because there is no exact-19c gvenzl image and the Oracle EE image was dropped (aws-broker#545). Some controls will behave differently on 23ai than on 19c/SE2 — those are tagged `local-validation-inconclusive → defer to live RDS`, never silently passed.

**Nothing this harness produces is compliance evidence.**

## Run

The only prerequisite is **Docker** (with `docker compose`). From the repository root, use the top-level `Makefile`:

```bash
make verify   # profile loads + oraquery unit tests + runner image builds — no database needed
make run      # full end-to-end: start Oracle 23ai Free and exec the profile
make test-go  # oraquery unit tests only (go test in a Go container)
make clean    # tear down and remove local results/image
make help     # list all targets
```

`make run` returns non-zero when CINC Auditor reports findings (GNU Make reports a failed recipe as exit 2; the raw compose command returns CINC's exit, such as 100). That can be the expected result of a real STIG finding against the unhardened local 23ai DB, not a runner failure. Use the CLI output to distinguish findings from infrastructure errors.

Equivalent raw commands (what the Makefile runs), from the repository root:

```bash
docker compose -f runner/docker-compose.yml up --build --abort-on-container-exit
```

## What's here

| Path | Purpose |
| --- | --- |
| `oraquery/` | Pure-Go Oracle query client (go-ora, MIT). **Built from source** in the runner image — no prebuilt binary is committed (#11). Emits the clean CSV `oracledb_session` expects; replaces sqlplus (OTN EULA) and sqlcl (broken CSV). Unit-tested via `make test-go`. |
| `Dockerfile` | Multi-stage: builds `oraquery`, then layers it + the harness onto CINC Auditor; vendors the profile's git dependency at build time; runs non-root. |
| `run-validation.sh` | Runs the profile with concise CINC CLI output and CINC's normal exit code. |
| `docker-compose.yml` | gvenzl/oracle-free (23ai) + the runner. |

## Client binary / supply chain

`oraquery` is **built from source** during the image build (`CGO_ENABLED=0`), so no executable is committed to the repository — this satisfies the OpenSSF allstar binary-artifacts policy and closes the concern tracked in [#11](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/11).

The MITRE baseline profile is consumed via git `depends` + a committed `inspec.lock` (pinned fork ref), vendored at build time with `cinc-auditor vendor` — **not** a committed `vendor/` tree. See [ADR-0001](../docs/adr/0001-consume-mitre-baseline-via-fork-depends.md).

## JSON output

The runner intentionally does **not** emit JSON by default. Pipelines should use CINC Auditor's established CLI output and exit status. JSON reporting can be added later as an explicit option when iterating on controls or generating coverage matrices.

## Credentials

Connection coordinates are injected at runtime, never baked into the image.

- **Local / ad hoc runs:** provide `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_SERVICE`
  (and optionally `DB_PORT`, default `1521`) as environment variables.
- **Cloud.gov live-RDS runs:** bind the app to the brokered RDS service and read the
  coordinates from `VCAP_SERVICES` (label `aws-rds`): `host`, `port`, `username`,
  `password`, `db_name`. There is no separate secret store — the bound service *is*
  the source. The binding does **not** carry a TLS CA cert (see below). When
  `VCAP_SERVICES` is present, `run-validation.sh` parses the first `aws-rds` binding
  with CINC's embedded Ruby and fills missing `DB_*` values from
  `credentials.username`, `credentials.password`, `credentials.host`,
  `credentials.db_name`/`credentials.name`, and `credentials.port`. Explicit `DB_*`
  values still take precedence.

The runner passes `/usr/local/bin/oraquery` to the InSpec profile and prepends
`/opt/cinc-auditor/embedded/bin` to `PATH` so Cloud Foundry's default environment
does not need to provide Ruby or `oraquery`.

## TLS (encryption in transit) — `ORAQUERY_TLS` + `ORAQUERY_CA_BUNDLE`

`oraquery` decides TLS from **explicit intent**, never from the port number, and
**fails closed** rather than silently sending the DB credential in cleartext
(#16 / #20). Set `ORAQUERY_TLS`:

| `ORAQUERY_TLS` | Behavior | Use for |
| --- | --- | --- |
| `verify-ca` (**default**) | TLS **with** server-certificate verification. Requires `ORAQUERY_CA_BUNDLE=<PEM path>`; fails closed if unset/empty/invalid. | Real brokered RDS. The only mode valid toward compliance evidence. |
| `require` | TLS **without** verification (encrypt-only). NOT MITM-safe; NOT compliance evidence. | Narrow debugging only. |
| `disable` | Plaintext — credential sent in the clear. | A **local** dev DB only (e.g. gvenzl 23ai on 1521). |

`ORAQUERY_CA_BUNDLE` is a **PEM CA bundle** (the naming matches `AWS_CA_BUNDLE` /
`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`). `oraquery` loads it into an x509 pool and
injects it via go-ora's `WithTLSConfig`. Note this is **not** go-ora's `WALLET`
option: that expects an Oracle wallet directory (`cwallet.sso`/`ewallet.p12`) and
rejects a PEM. AWS RDS publishes its root CA only as a PEM.

For the live-RDS Cloud.gov run: connect over **TCPS 2484** and set
`ORAQUERY_TLS=verify-ca`. The runner image **bakes** the AWS GovCloud RDS CA
bundle at `/opt/certs/rds-govcloud-global-bundle.pem` (source committed at
`runner/certs/rds-govcloud-global-bundle.crt.bundle`, checksum-verified in the
Dockerfile) and defaults `ORAQUERY_CA_BUNDLE` to it, so verified TLS works without
extra configuration. That bundle is a public (non-secret) trust anchor baked in
because the `aws-rds` binding does not carry it. A plaintext/unverified connection
to live RDS is refused by default.

> See **[`runner/certs/README.md`](certs/README.md)** for the bundle's provenance,
> contents, checksum, expiry, and the rotation runbook (single source of truth).

A TLS mode (`verify-ca`/`require`) aimed at the plaintext port **1521** is refused
(fail closed): verified TLS is served on **2484**, so a live run must target 2484.
An insecure mode (`require`/`disable`) against a non-local host emits a loud stderr
warning so it is visible in CI logs.

`run-validation.sh` auto-selects `ORAQUERY_TLS=disable` **only** when the target
host is loopback/local and no mode was set, so the local `make run` path keeps
working out of the box; any non-local target inherits the fail-closed
`verify-ca` default.

> **Local-dev note:** the "local host" allowlist is deliberately small —
> `localhost`, `127.0.0.1`, `::1`, and the compose service name `oracle`. A
> docker-compose Oracle service under a *different* name (e.g. `oracle-db` or
> `db`) is treated as remote and will inherit the fail-closed `verify-ca` default;
> set `ORAQUERY_TLS=disable` explicitly for such a local service.
