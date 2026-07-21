# cg-oracle-database-19c-stig-overlay

Out-of-band **DISA Oracle Database 19c STIG validation** for the STIG-hardened
Oracle 19c offering brokered by [`cloud-gov/aws-broker`](https://github.com/cloud-gov/aws-broker)
(epic [cloud-gov/aws-broker#519](https://github.com/cloud-gov/aws-broker/issues/519)).

> **Status: work in progress — not a compliance attestation.** This is a
> STIG-hardening/validation baseline. **No STIG evidence has been generated against
> a live brokered instance yet.** Do not read anything here as "STIG compliant."

## What this is

The `aws-broker` **provisions and configures** a hardened Amazon RDS Oracle SE2 19c
instance; **this repo validates it**. The broker never runs InSpec/Cinc — validation
is deliberately kept separate (see aws-broker
[ADR-0002](https://github.com/cloud-gov/aws-broker/blob/main/docs/decisions/ADR-0002-keep-stig-validation-in-overlay-repo.md)).

Validation uses **CINC Auditor / InSpec** with the `oracledb_session` resource
(SQL\*Plus) against the brokered instance, fed a broker-produced
[validation contract](https://github.com/cloud-gov/aws-broker/blob/main/docs/oracle19c/validation-contract.md).

## Layout

| Path | Purpose |
|------|---------|
| `control-layers.yml` | **Control → implementation-layer map** (`set_by` / `verified_by`). On managed RDS many controls are AWS-inherited, parameter-group-set, or OS/listener-level (not applicable). This classifies each so a brokered-RDS run reports inherited/NA/param-group controls correctly instead of failing them. Marked `status: draft`; `benchmark_version` is `unverified` pending a cited DISA release. |
| `hardening/sql/` | Assessment-first, idempotent, **non-SYS** (RDS master-user model) SQL: connectivity, inventory, profile limits, sample-account lockout, unified audit policies, plus detect-first PUBLIC-grant + network assessments and a validation summary. Parameter-level controls (e.g. `audit_trail`) are set by the broker's RDS parameter group, **not** SQL. |
| `hardening/sql/rollback/` | Reversal for the reversible hardening scripts. |

## Scope on managed RDS (honest limits)

- **SE2 offering:** the brokered engine is Oracle **Standard Edition 2** + License
  Included. SE2 lacks EE-only features (native TDE, Fine-Grained Auditing, VPD,
  Label Security, Partitioning). At-rest encryption is RDS-KMS (AES-256), auditing
  is standard/unified — documented as ISSO deviations in the broker's
  [licensing.md](https://github.com/cloud-gov/aws-broker/blob/main/docs/oracle19c/licensing.md).
- **RDS master user, not SYS:** all SQL assumes the RDS master (no `SYS`/`SYSDBA`);
  RDS-incompatible statements skip with a reason.
- **~33 OS/listener controls are AWS-inherited / not applicable** on managed RDS —
  classified in `control-layers.yml`, not failed.
- **Local runs are development signal only**, never compliance evidence (aws-broker
  [ADR-0005](https://github.com/cloud-gov/aws-broker/blob/main/docs/decisions/ADR-0005-local-testing-is-development-signal-only.md)).
  Authoritative evidence requires a run against a real brokered GovCloud RDS
  instance.

## Related

- Broker + Oracle docs: [`cloud-gov/aws-broker` `docs/oracle19c/`](https://github.com/cloud-gov/aws-broker/tree/main/docs/oracle19c)
- Overlay applicability + control-layer gap: this repo's issue #1
