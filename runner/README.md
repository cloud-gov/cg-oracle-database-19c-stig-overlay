# STIG profile runner (#7)

Executes the Cloud.gov Oracle 19c STIG **overlay** InSpec profile against an Oracle
database using **CINC Auditor** (Apache-2.0 FOSS distribution of InSpec) and a
purpose-built pure-Go query client (**oraquery**). The runner uses concise CINC
CLI output and CINC's normal exit codes. As controls are dispositioned
([#3](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/3)),
this run produces the coverage report referenced by
[#6](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/6) —
static analysis of the profile proved unreliable, so we run it.

The same runner image is intended to double as the **Concourse InSpec runner** for
the live-RDS scan ([aws-broker#558](https://github.com/cloud-gov/aws-broker/issues/558)).

## ⚠️ Fidelity — read before trusting any result

| Layer | What it proves |
|-------|----------------|
| **This harness** (Oracle **23ai Free**, gvenzl) | The check LOGIC executes and is coherent; which controls are real vs. empty stubs; which error. |
| **NOT proven here** | 19c-specific, SE2-specific, or RDS-specific behavior. |
| **Live RDS proof** (aws-broker#558) | The only source of actual compliance evidence. |

Local runs target **Oracle 23ai Free** because there is no exact-19c gvenzl image
and the Oracle EE image was dropped (aws-broker#545). Some controls will behave
differently on 23ai than on 19c/SE2 — those are tagged
`local-validation-inconclusive → defer to live RDS`, never silently passed.

**Nothing this harness produces is compliance evidence.**

## Run

The only prerequisite is **Docker** (with `docker compose`). From the repository
root, use the top-level `Makefile`:

```bash
make verify   # profile loads + oraquery unit tests + runner image builds — no database needed
make run      # full end-to-end: start Oracle 23ai Free and exec the profile
make test-go  # oraquery unit tests only (go test in a Go container)
make clean    # tear down and remove local results/image
make help     # list all targets
```

`make run` returns non-zero when CINC Auditor reports findings (GNU Make reports a
failed recipe as exit 2; the raw compose command returns CINC's exit, such as 100).
That can be the expected result of a real STIG finding against the unhardened local
23ai DB, not a runner failure. Use the CLI output to distinguish findings from
infrastructure errors.

Equivalent raw commands (what the Makefile runs), from the repository root:

```bash
docker compose -f runner/docker-compose.yml up --build --abort-on-container-exit
```

## What's here

| Path | Purpose |
|------|---------|
| `oraquery/` | Pure-Go Oracle query client (go-ora, MIT). **Built from source** in the runner image — no prebuilt binary is committed (#11). Emits the clean CSV `oracledb_session` expects; replaces sqlplus (OTN EULA) and sqlcl (broken CSV). Unit-tested via `make test-go`. |
| `Dockerfile` | Multi-stage: builds `oraquery`, then layers it + the harness onto CINC Auditor; vendors the profile's git dependency at build time; runs non-root. |
| `run-validation.sh` | Runs the profile with concise CINC CLI output and CINC's normal exit code. |
| `docker-compose.yml` | gvenzl/oracle-free (23ai) + the runner. |

## Client binary / supply chain

`oraquery` is **built from source** during the image build (`CGO_ENABLED=0`), so no
executable is committed to the repository — this satisfies the OpenSSF allstar
binary-artifacts policy and closes the concern tracked in
[#11](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/11).

The MITRE baseline profile is consumed via git `depends` + a committed `inspec.lock`
(pinned fork ref), vendored at build time with `cinc-auditor vendor` — **not** a
committed `vendor/` tree. See
[ADR-0001](../docs/adr/0001-consume-mitre-baseline-via-fork-depends.md).

## JSON output

The runner intentionally does **not** emit JSON by default. Pipelines should use
CINC Auditor's established CLI output and exit status. JSON reporting can be added
later as an explicit option when iterating on controls or generating coverage
matrices.

## Credentials

Injected at runtime via env (`DB_USER`/`DB_PASSWORD`/`DB_HOST`/`DB_SERVICE`/`DB_PORT`),
never baked into the image. For the live-RDS Concourse run, use the master cred from
the secret store and TCPS port 2484 with enforced cert validation.
