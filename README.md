# cg-oracle-database-19c-stig-overlay

Out-of-band **DISA Oracle Database 19c STIG** hardening + assessment material for the STIG-hardened Oracle 19c offering brokered by [`cloud-gov/aws-broker`](https://github.com/cloud-gov/aws-broker).

> **Status: work in progress — not a compliance attestation.** This repo contains a **draft** control→layer map, a set of SQL hardening/assessment scripts, an **InSpec/CINC overlay** that consumes the cloud-gov MITRE baseline, and a containerized runner. The overlay `include_controls` **all** baseline controls and applies **in-overlay overrides** (in-place N/A dispositions and manual/compensating-control determinations).
>
> Live validation runs against a brokered GovCloud RDS instance **have** occurred during development, but **no run has yet been accepted as formal compliance evidence** — the WS15 evidence run is tracked in [`aws-broker#558`](https://github.com/cloud-gov/aws-broker/issues/558) (open).
>
> **Pre-production cleanup:** much of the in-repo PR/issue references and development scaffolding will be **removed before this repo goes to production**, and the ADRs under `docs/adr/` may be **consolidated to drop decisions that are no longer relevant**. Development-phase tracking links here are not intended to be permanent fixtures.

## What this is (and is not)

The `aws-broker` **provisions and configures** a hardened Amazon RDS Oracle SE2 19c instance. This repo is the **separate place** where its database-layer STIG posture is meant to be hardened and validated — the broker deliberately never runs InSpec/CINC against itself (separation of duties).

The [`docs/RESPONSIBILITY.md`](docs/RESPONSIBILITY.md) document defines the **platform-vs-customer** responsibility model that determines which controls the platform satisfies and which the tenant must apply.

**Key Contents**:

- `control-layers.yml` — a draft control→implementation-layer map (`set_by` / `verified_by`).
- `controls/overlay.rb` — the InSpec/CINC overlay: `include_controls` all baseline controls, plus about 57 in-place overrides -- the exact number may change during development.
- `hardening/sql/` — assessment-first, mostly-idempotent SQL for the database layer, plus rollback scripts.
- `runner/` — a containerized CINC Auditor runner (`run-validation.sh`, the pure-Go `oraquery` client, local 23ai compose harness, and a Cloud.gov SQLcl app).
- `libraries/` + `spec/` — an `oracledb_session` CSV stopgap and its unit tests (temporary; removed once CINC ships the upstream fix — tracked in [#35](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/35)).

**Not yet committed (planned / tracked):**

- A consumer that reads `control-layers.yml` to classify a live run — tracked in [#40](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/40).
- A validation run **accepted as compliance evidence** — the WS15 live proof, tracked in [`aws-broker#558`](https://github.com/cloud-gov/aws-broker/issues/558).

## Quickstart

Docker runs for local validation in development:

```sh
make verify   # profile loads + unit tests pass + runner image builds (NO database)
make check    # static profile validation only (cinc-auditor check)
make run      # full end-to-end against a local Oracle 23ai Free DB
```

`make help` lists all targets. A local 23ai run is **development signal only**, never compliance evidence (see [`runner/README.md`](runner/README.md)).

The actual Cloud.gov validation is done by running:

```sh
make push-cloudgov   # Push an idle Docker image app to Cloud.gov for cf ssh validation runs
make report-cloudgov # Run validation --json on Cloud.gov (cf ssh) and copy the JSON report into $(RESULTS_DIR)/
```

### Run postures

The runner supports two postures, gated by [`docs/RESPONSIBILITY.md`](docs/RESPONSIBILITY.md):

- **`--skip-customer-controls`** (platform-only) — skips (does not fail) customer-responsibility controls the tenant owns.
- **`--all`** — also runs customer-responsibility controls (asserts the tenant hardening has been applied).

## Layout

| Path | Purpose |
| --- | --- |
| `inspec.yml` | Profile metadata + inputs. `depends` on the cloud-gov fork of the MITRE baseline (`cloudgov` branch); does **not** vendor it. |
| `controls/overlay.rb` | The overlay itself: `include_controls` all baseline controls, applies in-place overrides (N/A dispositions for OS/host/listener checks unreachable on managed RDS; manual/compensating-control determinations), and skips customer-responsibility controls on a platform-only run. |
| `control-layers.yml` | **Draft** control → implementation-layer map (`set_by` / `verified_by`). Classifies controls so a future brokered-RDS run can report inherited / not-applicable / parameter-group controls correctly instead of failing them. Currently **93 explicit entries plus 3 pattern-based default rules**; `status: draft` and `benchmark_version: unverified` pending a cited DISA release. No consumer reads it yet (resolver tracked in [#40](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/40)). |
| `hardening/sql/` | Assessment-first, mostly-idempotent, **non-SYS** (RDS master-user model) SQL: connectivity, inventory, profile limits, **sample-account** lockout, unified audit policies, plus detect-first PUBLIC-grant and network assessments and a validation summary. Parameter-level controls (e.g. `audit_trail`) are set by the broker's RDS parameter group, **not** by these scripts (they remain SQL-_verifiable_). See [`hardening/sql/README.md`](hardening/sql/README.md) for per-script scope and caveats. |
| `hardening/sql/rollback/` | Reversal for the reversible hardening scripts (`10`, `30`; `20` is only partially reversible). |
| `runner/` | Containerized CINC Auditor runner: `run-validation.sh`, the pure-Go `oraquery` client, `db-query.sh`, the local 23ai `docker-compose.yml`, and the Cloud.gov SQLcl buildpack app (`sqlcl-cf/`). See [`runner/README.md`](runner/README.md). |
| `rds-inputs.yml` | Scan-time input file for a brokered RDS run (allowlists, audit users, verify-function names). Non-secret metadata; connection credentials are supplied at scan time, never committed. |
| `libraries/` + `spec/` | `oracledb_session_patch.rb` — a CSV-parsing stopgap for the `oracledb_session` resource — and its rspec unit tests. Temporary; reverted once CINC ships the upstream fix ([#35](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/35)). |
| `docs/RESPONSIBILITY.md` | The platform-vs-customer responsibility model and how each run posture behaves. **Read this first.** |
| `docs/adr/` | Architecture Decision Records (MADR). See [ADR-0001](docs/adr/0001-consume-mitre-baseline-via-fork-depends.md) for the baseline-dependency strategy. |
| `profile/` | Placeholder for additional InSpec/CINC profile material. |
| `Makefile` | One-command bootstrap/verify (`make verify`, `make check`, `make run`) — the entry point for a new contributor. |

## Scope on managed RDS (honest limits)

- **SE2 offering.** The brokered engine is Oracle **Standard Edition 2** + License Included. SE2 lacks EE-only features (native TDE, Fine-Grained Auditing, VPD, Label Security, Partitioning). At-rest encryption is RDS-KMS (AES-256) and auditing is standard/unified — accepted as ISSO deviations with compensating controls. The broker's Oracle feature-branch docs (`docs/oracle19c/licensing.md`, `limitations.md`, etc.) live on [`aws-broker@feat/oracle-19c-stig-brokered-rds`](https://github.com/cloud-gov/aws-broker/tree/feat/oracle-19c-stig-brokered-rds/docs/oracle19c) and are **not on `aws-broker` `main`**; re-point this link when the Oracle work lands on `main`.
- **RDS master user, not SYS.** All SQL assumes the RDS master (no `SYS`/`SYSDBA`); RDS-incompatible statements skip with a reason rather than error.
- **OS/listener/host controls are AWS-inherited or not applicable** on managed RDS (no OS/listener/file access). `control-layers.yml` classifies these by pattern (e.g. `tnslsnr`, `lsnrctl`, `/etc/oratab`) and the overlay marks the corresponding baseline controls N/A in place, so they are tagged rather than misleadingly failed.
- **Local / offline runs are development signal only**, never compliance evidence. Live runs against a real brokered GovCloud RDS instance **have** occurred during development, but **none has been accepted as compliance evidence yet** — the formal WS15 evidence run is tracked in [`aws-broker#558`](https://github.com/cloud-gov/aws-broker/issues/558).

## Related

- **Broker Oracle docs** (on the unmerged feature branch, not on `main`): [`aws-broker@feat/oracle-19c-stig-brokered-rds` → `docs/oracle19c/`](https://github.com/cloud-gov/aws-broker/tree/feat/oracle-19c-stig-brokered-rds/docs/oracle19c). (The original dev PR, [aws-broker#537](https://github.com/cloud-gov/aws-broker/pull/537), was **closed unmerged**.)
- **Broker epic** (closed): [cloud-gov/aws-broker#519](https://github.com/cloud-gov/aws-broker/issues/519).
- **TLS via option groups** (in-transit encryption, **merged** 2026-08-06): [cloud-gov/aws-broker#564](https://github.com/cloud-gov/aws-broker/pull/564).
- **Platform dependency for TLS-only** (open TCPS 2484 / deny 1521, **merged** 2026-08-13): [cloud-gov/terraform-provision#2351](https://github.com/cloud-gov/terraform-provision/pull/2351).
- **WS15 live compliance-evidence run** (open): [cloud-gov/aws-broker#558](https://github.com/cloud-gov/aws-broker/issues/558).
