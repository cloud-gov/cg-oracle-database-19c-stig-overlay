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
make test-ruby # oracledb_session CSV parser stopgap specs only (rspec in the CINC image)
make clean    # tear down and remove local results/image
make help     # list all targets
```

`make run` returns non-zero when CINC Auditor reports findings (GNU Make reports a failed recipe as exit 2; the raw compose command returns CINC's exit, such as 100). That can be the expected result of a real STIG finding against the unhardened local 23ai DB, not a runner failure. Use the CLI output to distinguish findings from infrastructure errors.

### Fast local control iteration

To iterate on controls **without** restarting the database each change, keep the DB up and re-run the profile against it. `retest` mounts the working tree **read-only** and execs it, so edits under `controls/` are picked up immediately — no image rebuild:

```bash
make db-up     # start Oracle 23ai Free once, leave it running (waits until healthy)
make retest    # edit controls/, re-run in seconds — repeat as needed
make db-down   # stop and remove the DB when finished
```

For the fastest loop, restrict the run to the control(s) you're editing — CINC
then skips loading and executing everything else:

```bash
make retest CONTROL=SV-270495                 # one control
make retest CONTROLS="SV-270495 SV-270496"    # several
```

(Equivalently, the runner accepts `--controls "ID [ID...]"` or a `CONTROLS` env
var directly.)

The baseline `depends` is resolved from the committed `inspec.lock` (managed in-repo — run `make vendor` if you change the dependency). Because the profile dir is mounted read-only, CINC's dependency cache is directed to a writable path inside the container (`VENDOR_CACHE`, default the scanner user's `~/.inspec/cache`), so nothing is written back into your working tree.

Equivalent raw commands (what the Makefile runs), from the repository root:

```bash
docker compose -f runner/docker-compose.yml up --build --abort-on-container-exit
```

For a real brokered RDS instance on Cloud.gov, push the idle validation app, bind the Oracle service, restage so `VCAP_SERVICES` is available, then run validation over SSH:

```bash
make push-cloudgov
cf bind-service cg-cinc-audit-oracle-runner <oracle-db>
cf restage cg-cinc-audit-oracle-runner
cf ssh cg-cinc-audit-oracle-runner -c /usr/local/bin/run-validation.sh
```

## What's here

| Path | Purpose |
| --- | --- |
| `oraquery/` | Pure-Go Oracle query client (go-ora, MIT). **Built from source** in the runner image — no prebuilt binary is committed (#11). Emits standard RFC 4180 CSV; replaces sqlplus (OTN EULA) and sqlcl (broken CSV). Unit-tested via `make test-go`. |
| `../libraries/oracledb_session_patch.rb` | Downstream stopgap that prepends a corrected `parse_csv_result` onto the vendored `oracledb_session` resource. The upstream resource only supports single-column results (multi-column `.column()` returns `nil`); fixed upstream in [inspec/inspec#7997](https://github.com/inspec/inspec/pull/7997). Tracking: [#32](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/32). Remove once the runner image ships a CINC Auditor including the upstream fix. |
| `../spec/oracledb_session_patch_spec.rb` | Unit specs for the stopgap (run via `make test-ruby`, no DB). Mirrors the upstream PR's fixtures — multi-column, single-column back-compat, quoted-comma value, empty result — so a CINC bump that changes the resource gives fast local feedback instead of a silent wrong parse. Also carries a **"remove me" guard** that asserts the buggy `gsub`-before-`CSV.parse` pattern is still present in the vendored resource; it fails loudly once [inspec/inspec#7997](https://github.com/inspec/inspec/pull/7997) lands, signalling the revert tracked in [#35](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/35) (delete the library, this spec, and the Dockerfile `COPY libraries` line). |
| `Dockerfile` | Multi-stage: builds `oraquery`, then layers it + the harness onto CINC Auditor; vendors the profile's git dependency at build time; runs non-root. |
| `run-validation.sh` | Runs the profile with concise CINC CLI output and CINC's normal exit code. |
| `docker-compose.yml` | gvenzl/oracle-free (23ai) + the runner. |

## Client binary / supply chain

`oraquery` is **built from source** during the image build (`CGO_ENABLED=0`), so no executable is committed to the repository — this satisfies the OpenSSF allstar binary-artifacts policy and closes the concern tracked in [#11](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/11).

The MITRE baseline profile is consumed via git `depends` + a committed `inspec.lock` (pinned fork ref), vendored at build time with `cinc-auditor vendor` — **not** a committed `vendor/` tree. See [ADR-0001](../docs/adr/0001-consume-mitre-baseline-via-fork-depends.md).

## JSON output

By default the runner emits only the CINC Auditor CLI report and CINC's exit
status. Pass `--json` (or set `JSON_OUTPUT=1`) to **additionally** write a
machine-readable JSON report for iteration or coverage analysis. The CLI report
is still printed and the exit status is unchanged.

The JSON report is written to `${OUT_DIR:-/out}` with a timestamped, labeled
filename so multiple runs are distinguishable:

```
${OUT_DIR:-/out}/validation-<label>-<UTC-timestamp>.json
# e.g. /out/validation-FREEPDB1-20260807T195624Z.json
```

- `OUT_DIR` — output directory (default `/out`).
- `RUN_LABEL` — label token (default: the DB service name); sanitized to
  `[A-Za-z0-9._-]`.

For local 23ai iteration, `make report-local` runs `retest` with `--json` and
mounts `$(RESULTS_DIR)` (default `./out`) at the container's `/out`, so reports
land directly on the host — no copy step:

```bash
make db-up
make report-local          # → out/validation-FREEPDB1-<ts>.json
make report-local RESULTS_DIR=reports
make report-local CONTROL=SV-270495    # report on a single control
```

## Credentials

Connection coordinates are injected at runtime, never baked into the image.

- **Local / ad hoc runs:** provide `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_SERVICE`
  (and optionally `DB_PORT`, default `1521`) as environment variables.
- **Cloud.gov live-RDS runs:** bind the app to the brokered RDS service and read the
  coordinates from `VCAP_SERVICES` (label `aws-rds`): `host`, `port`, `username`,
  `password`, `db_name`. There is no separate secret store — the bound service *is*
  the source. The binding does **not** carry a TLS CA cert (see below). When
  `VCAP_SERVICES` is present, `run-validation.sh` selects the first `aws-rds`
  binding whose credentials `db_name` (or `name`) is `ORCL` and fills missing
  `DB_*` values from `credentials.username`, `credentials.password`,
  `credentials.host`, `credentials.db_name`/`credentials.name`, and
  `credentials.port` (parsed with CINC's embedded Ruby). If no `ORCL` binding
  exists it fails closed rather than guessing another database. Explicit `DB_*`
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
