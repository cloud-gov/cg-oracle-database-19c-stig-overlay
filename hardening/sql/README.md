# Oracle 19c STIG SQL hardening & assessment (RDS-aware)

> Filed from the aws-broker Oracle 19c epic
> ([cloud-gov/aws-broker#519](https://github.com/cloud-gov/aws-broker/issues/519),
> WS10 [#529](https://github.com/cloud-gov/aws-broker/issues/529)); overlay
> gap tracked in
> [#1](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/1).

SQL-level STIG hardening + assessment for **brokered AWS RDS Oracle 19c**. These
scripts are the *SQL layer* only. OS/listener/host controls are **AWS-inherited**
on managed RDS and are validated as such by the InSpec profile, not remediated
here (see `../control-layers.yml`).

## Principles

- **Assessment-first.** `*_assess.sql` and `01_inventory.sql` only *read* state.
- **Idempotent (mostly).** Re-running `10`/`30` changes nothing on an
  already-hardened DB. **`20` is idempotent only against accounts it left locked**
  — if an operator deliberately unlocks a sample account, re-running `20` will
  re-lock it (it acts on OPEN / expired-unlocked accounts). Document that intent
  before scheduling `20` on a live system.
- **Detect-first for destructive change.** PUBLIC-grant revocations and any
  destructive change are **detected and reported**, never applied automatically —
  they require an explicit operator allowlist (app/vendor breakage risk).
- **Non-SYS.** Scripts assume the RDS **master user**, not `SYS`/`SYSDBA`.
  RDS-incompatible commands skip with a reason.
- **Fail loud, not silent.** `20`/`30` count failures and `RAISE_APPLICATION_ERROR`
  if any operation errored, so an automated run cannot record a false PASS when
  every statement was rejected.
- **Only touch sample schemas.** `20` locks/expires **Oracle-provided sample
  schemas only** (HR/OE/PM/IX/SH/BI/SCOTT) — never option/security schemas
  (DVSYS/Database Vault, LBACSYS, AUDSYS): locking those can break a live RDS
  option.
- **RDS layering.** Controls satisfied by an RDS **parameter group** (e.g.
  `audit_trail`, `sec_case_sensitive_logon`) are *set* by the broker
  ([aws-broker#525](https://github.com/cloud-gov/aws-broker/issues/525)) but remain
  **SQL-verifiable** — see `control-layers.yml` (`set_by` ≠ `verified_by`).

## Script groups

| Script | Kind | Purpose |
|--------|------|---------|
| `00_connectivity_check.sql` | assess | verify connection + effective user/privs |
| `01_inventory.sql` | assess | inventory users, profiles, roles, audit state |
| `10_profiles.sql` | harden | enforce password/lockout profile limits |
| `20_users_roles_privileges.sql` | harden | lock/expire Oracle **sample** accounts (does NOT modify roles/privileges — see note) |
| `30_audit_policies.sql` | harden | enable/verify unified audit policies |
| `40_public_grants_assess.sql` | assess | **detect** a curated set of excessive PUBLIC EXECUTE grants (no revoke) |
| `50_network_related_assess.sql` | assess | report SQL-visible network params (sqlnet/listener are inherited) |
| `90_validate.sql` | assess | post-hardening validation summary |
| `rollback/` | — | reversal for the **reversible** hardening scripts (`10`, `30`; `20` is only partially reversible — see below) |

> **`20` naming/scope:** the filename says `users_roles_privileges` but the script
> currently only **locks/expires sample accounts**. Role/privilege tightening is a
> planned addition, not yet implemented — do not assume it runs today.

## Rollback coverage

- `rollback/10_profiles_rollback.sql` — resets DEFAULT profile to Oracle **19c
  vendor defaults** (not this DB's pre-hardening values; capture those from
  `01_inventory` first for a true restore).
- `rollback/20_users_rollback.sql` — **unlocks** the sample accounts, but
  **cannot un-expire** a password (Oracle limitation); owner must reset it.
- `rollback/30_audit_policies_rollback.sql` — `NOAUDIT` the two policies (reduces
  posture; deliberate action only).

## RDS caveats

- No `SYS`/`SYSDBA`; some `V$`/`DBA_` views and `ALTER SYSTEM` are restricted — the
  scripts guard these and skip with a reason rather than error.
- Parameter-level controls belong to the broker's RDS parameter group, not here.
- Local runs (aws-broker `local/`) are **development signal only**
  ([aws-broker ADR-0005](https://github.com/cloud-gov/aws-broker/blob/main/docs/decisions/ADR-0005-local-testing-is-development-signal-only.md)).
