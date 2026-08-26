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
- **Idempotent (mostly).** Re-running `10`/`11`/`15`/`30` changes nothing on an
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
| `10_profiles.sql` | harden | enforce password/lockout limits on the **DEFAULT** profile (incl. SV-270549/550/551) |
| `11_ora_stig_profile.sql` | harden | assign the Oracle-supplied **`ORA_STIG_PROFILE`** (immutable; already carries the SV-270549/550/551 lockout limits) to org-defined **non-Oracle** user accounts, detect-first (`assign_users=N` to report only). Does not create/modify/verify the profile. |
| `15_concurrent_sessions.sql` | harden | set DEFAULT profile `SESSIONS_PER_USER` to instance `SESSIONS` − headroom (SV-270495) — **sample** high per-user cap for the single-app-user case, review before use |
| `20_users_roles_privileges.sql` | harden | lock/expire Oracle **sample** accounts (does NOT modify roles/privileges — see note) |
| `30_audit_policies.sql` | harden | create + enable `CG_AUDIT_POLICY` for events the RDS default policies miss (REVOKE, CHANGE PASSWORD, LOGOFF, CREATE SPFILE) |
| `40_public_grants_assess.sql` | assess | **detect** a curated set of excessive PUBLIC EXECUTE grants (no revoke) |
| `50_network_related_assess.sql` | assess | report SQL-visible network params (sqlnet/listener are inherited) |
| `rollback/` | — | reversal for the **reversible** hardening scripts (`10`, `11`, `15`, `30`; `20` is only partially reversible — see below) |

> **`20` naming/scope:** the filename says `users_roles_privileges` but the script
> currently only **locks/expires sample accounts**. Role/privilege tightening is a
> planned addition, not yet implemented — do not assume it runs today.

> **`10` vs `11` (profile-lockout controls SV-270549/550/551):** `10_profiles.sql`
> hardens the **DEFAULT** profile (which on brokered RDS governs the app + master
> account). `11_ora_stig_profile.sql` uses the DISA-named, **Oracle-supplied**
> **`ORA_STIG_PROFILE`** — an immutable, Oracle-maintained profile that already
> carries the three lockout limits (`PASSWORD_LOCK_TIME UNLIMITED`,
> `FAILED_LOGIN_ATTEMPTS 3`, `INACTIVE_ACCOUNT_TIME 35`). Per the STIG the supplied
> profile can be used as-is, so `11` does **not** create, modify, or verify it — it
> only **assigns** it, **detect-first**, to org-defined non-Oracle accounts
> (`DBA_USERS.ORACLE_MAINTAINED='N'`, excluding the operator/platform list). The
> baseline checks assert these limits on **every user-assigned profile**, so run
> `11` if any account is on a profile other than a hardened DEFAULT. Run with
> `DEFINE assign_users = N` to report candidate accounts without changing their
> profile. Moving an app account onto a 3-strikes lockout profile can lock out its
> connection pool — review the candidate list first.

## Rollback coverage

- `rollback/10_profiles_rollback.sql` — resets DEFAULT profile to Oracle **19c
  vendor defaults** (not this DB's pre-hardening values; capture those from
  `01_inventory` first for a true restore).
- `rollback/11_ora_stig_profile_rollback.sql` — moves the accounts `11` assigned
  back to the **DEFAULT** profile (not each account's pre-hardening profile —
  capture from `01_inventory` for a true restore). Never drops `ORA_STIG_PROFILE`
  (it is Oracle-supplied/immutable). Reassigning to DEFAULT **re-opens**
  SV-270549/550/551 for those accounts unless DEFAULT was hardened by `10`.
- `rollback/15_concurrent_sessions_rollback.sql` — resets DEFAULT
  `SESSIONS_PER_USER` to the Oracle **19c vendor default (`UNLIMITED`)**; this
  **re-opens the SV-270495 finding** and is not this DB's pre-hardening value
  (capture from `01_inventory` for a true restore).
- `rollback/20_users_rollback.sql` — **unlocks** the sample accounts, but
  **cannot un-expire** a password (Oracle limitation); owner must reset it.
- `rollback/30_audit_policies_rollback.sql` — `NOAUDIT` then `DROP` the tenant
  `CG_AUDIT_POLICY` (reduces posture; deliberate action only). Does not touch the
  RDS-default policies, which this script never enabled.

## RDS caveats

- No `SYS`/`SYSDBA`; some `V$`/`DBA_` views and `ALTER SYSTEM` are restricted — the
  scripts guard these and skip with a reason rather than error.
- Parameter-level controls belong to the broker's RDS parameter group, not here.
- Local runs (aws-broker `local/`) are **development signal only** — never
  compliance evidence. Authoritative evidence requires a run against a real
  brokered GovCloud RDS instance.
