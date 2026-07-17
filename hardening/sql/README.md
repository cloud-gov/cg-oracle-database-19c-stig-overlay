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
- **Idempotent.** Re-running hardening changes nothing on an already-hardened DB.
- **Detect-first for destructive change.** PUBLIC-grant revocations and any
  destructive change are **detected and reported**, never applied automatically —
  they require an explicit operator allowlist (app/vendor breakage risk).
- **Non-SYS.** Scripts assume the RDS **master user**, not `SYS`/`SYSDBA`.
  RDS-incompatible commands skip with a printed reason.
- **RDS layering.** Controls satisfied by an RDS **parameter group** (e.g.
  `audit_trail`, `sec_case_sensitive_logon`) are set by the broker
  ([aws-broker#525](https://github.com/cloud-gov/aws-broker/issues/525)), NOT here;
  this layer covers profiles, users/roles/privileges, audit policies, and PUBLIC
  grants that live in SQL.

## Script groups

| Script | Kind | Purpose |
|--------|------|---------|
| `00_connectivity_check.sql` | assess | verify connection + effective user/privs |
| `01_inventory.sql` | assess | inventory users, profiles, roles, audit state |
| `10_profiles.sql` | harden | enforce password/lockout profile limits |
| `20_users_roles_privileges.sql` | harden | lock/expire default accounts, tighten roles |
| `30_audit_policies.sql` | harden | enable/verify unified audit policies |
| `40_public_grants_assess.sql` | assess | **detect** excessive PUBLIC grants (no revoke) |
| `50_network_related_assess.sql` | assess | report network/encryption-related settings |
| `90_validate.sql` | assess | post-hardening validation summary |
| `rollback/` | — | inverse of each hardening script |

## RDS caveats

- No `SYS`/`SYSDBA`; some `V$`/`DBA_` views and `ALTER SYSTEM` are restricted — the
  scripts guard these and skip with a reason rather than error.
- Parameter-level controls belong to the broker's RDS parameter group, not here.
- Local runs (aws-broker `local/`) are **development signal only**
  ([aws-broker ADR-0005](https://github.com/cloud-gov/aws-broker/blob/main/docs/decisions/ADR-0005-local-testing-is-development-signal-only.md)).
