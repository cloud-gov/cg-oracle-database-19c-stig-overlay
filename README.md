# cg-oracle-database-19c-stig-overlay

Out-of-band **DISA Oracle Database 19c STIG** hardening + assessment material for the
STIG-hardened Oracle 19c offering brokered by
[`cloud-gov/aws-broker`](https://github.com/cloud-gov/aws-broker) (epic
[cloud-gov/aws-broker#519](https://github.com/cloud-gov/aws-broker/issues/519)).

> **Status: work in progress — not a compliance attestation.**
> This repo currently contains a **draft** control→layer map and a set of SQL
> hardening/assessment scripts. There is **no committed InSpec/CINC profile yet**
> (see [#3](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/3)),
> and **no STIG evidence has been generated against a live brokered instance.**
> Do not read anything here as "STIG compliant."

## What this is (and is not)

The `aws-broker` **provisions and configures** a hardened Amazon RDS Oracle SE2 19c
instance. This repo is the **separate place** where its database-layer STIG posture
is meant to be hardened and validated — the broker deliberately never runs
InSpec/CINC against itself (separation of duties).

**Committed today:**

- `control-layers.yml` — a draft control→implementation-layer map.
- `hardening/sql/` — assessment-first, mostly-idempotent SQL for the database layer,
  plus rollback scripts.

**Not yet committed (planned / tracked):**

- An InSpec/CINC profile (`oracledb_session`-based) and the runnable 19c controls,
  and a `port` input — tracked in
  [#3](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/3).
- A consumer that reads `control-layers.yml` to classify a live run.
- Any live-instance validation run (compliance evidence).

## Layout

| Path | Purpose |
|------|---------|
| `control-layers.yml` | **Draft** control → implementation-layer map (`set_by` / `verified_by`). On managed RDS many controls are AWS-inherited, set by an RDS parameter/option group, or OS/listener-level (not applicable). This classifies controls so a future brokered-RDS run can report inherited / not-applicable / parameter-group controls correctly instead of failing them. Currently **13 explicitly-mapped controls plus 3 pattern-based default rules**; `status: draft` and `benchmark_version: unverified` pending a cited DISA release. No consumer reads it yet. |
| `hardening/sql/` | Assessment-first, mostly-idempotent, **non-SYS** (RDS master-user model) SQL: connectivity, inventory, profile limits, **sample-account** lockout, unified audit policies, plus detect-first PUBLIC-grant and network assessments and a validation summary. Parameter-level controls (e.g. `audit_trail`) are set by the broker's RDS parameter group, **not** by these scripts (they remain SQL-*verifiable*). See [`hardening/sql/README.md`](hardening/sql/README.md) for per-script scope and caveats. |
| `hardening/sql/rollback/` | Reversal for the reversible hardening scripts (`10`, `30`; `20` is only partially reversible). |
| `profile/` | Placeholder for the InSpec/CINC profile — **not yet implemented** (#3). |

## Scope on managed RDS (honest limits)

- **SE2 offering.** The brokered engine is Oracle **Standard Edition 2** + License
  Included. SE2 lacks EE-only features (native TDE, Fine-Grained Auditing, VPD,
  Label Security, Partitioning). At-rest encryption is RDS-KMS (AES-256) and auditing
  is standard/unified — accepted as ISSO deviations with compensating controls,
  documented on the broker's Oracle feature branch
  ([PR #537](https://github.com/cloud-gov/aws-broker/pull/537),
  `docs/oracle19c/licensing.md`; not yet on `aws-broker` `main`).
- **RDS master user, not SYS.** All SQL assumes the RDS master (no `SYS`/`SYSDBA`);
  RDS-incompatible statements skip with a reason rather than error.
- **OS/listener/host controls are AWS-inherited or not applicable** on managed RDS
  (no OS/listener/file access). `control-layers.yml` classifies these by pattern
  (e.g. `tnslsnr`, `lsnrctl`, `/etc/oratab`) so they are tagged, not failed. The
  exact count of affected controls will be known once the InSpec profile is
  committed and mapped (#3).
- **Local / offline runs are development signal only**, never compliance evidence.
  Authoritative evidence requires a run against a real brokered GovCloud RDS
  instance (the WS15 live proof), which has not happened yet.

## Related

- Broker Oracle docs (on the unmerged feature branch):
  [`aws-broker` PR #537](https://github.com/cloud-gov/aws-broker/pull/537) →
  `docs/oracle19c/`.
- Broker epic: [cloud-gov/aws-broker#519](https://github.com/cloud-gov/aws-broker/issues/519).
- Platform dependency for TLS-only (open TCPS 2484 / deny 1521):
  [cloud-gov/aws-broker#541](https://github.com/cloud-gov/aws-broker/issues/541).
- Remaining InSpec-profile work in this repo:
  [#3](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/3).
