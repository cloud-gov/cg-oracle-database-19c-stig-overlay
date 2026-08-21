---
title: "Control responsibility model — platform vs. customer"
description: "How Oracle 19c STIG controls are flagged as a Cloud.gov platform responsibility or a customer responsibility, and how the overlay skips customer-responsibility controls on a platform-only run."
status: draft
tier: 2
last_updated: "2026-08-20"
---

# Control responsibility: platform vs. customer

On brokered Cloud.gov RDS Oracle 19c, responsibility for satisfying a STIG
control is split between the **platform** (Cloud.gov / AWS) and the **customer**
(the tenant who provisions the database). This document defines the model, how a
control is flagged, and how the overlay behaves in each run posture.

> **Why this matters.** A platform-only run must not be *failed* by remediation
> the platform cannot perform for the tenant (it would need an org-defined value,
> e.g. a session limit). Those controls are flagged **customer responsibility**
> and are *skipped* — not failed — unless the run is explicitly told the customer
> hardening has been applied.

## The two responsibilities

| Responsibility | Who satisfies it | How it is satisfied | Verified by |
| --- | --- | --- | --- |
| **Platform** | Cloud.gov / AWS | Broker infrastructure at provision (encryption, private networking, backups), an RDS **parameter/option group**, or an inherited OS/host/listener control. | AWS metadata, option/param-group config, or SQL against `V$PARAMETER` — see `control-layers.yml` `set_by` / `verified_by`. |
| **Customer** | The tenant | **Database-altering SQL with an organization-defined value** — e.g. `ALTER PROFILE ... LIMIT SESSIONS_PER_USER <n>`. Cloud.gov ships *sample* remediation in `hardening/sql/`, but the customer chooses the value and applies it. | SQL against the live database, once the customer has applied the hardening. |

The platform delivers a database hardened to the extent the platform *can*.
Hardening that requires database-altering SQL with a value only the organization
can decide is, by definition, the customer's action.

## How a control is flagged

A control is a **customer responsibility** when **all** of the following hold:

1. It is **SQL-verifiable** on managed RDS (the tenant can check it), AND
2. Its remediation is **database-altering SQL** (`ALTER PROFILE`, `ALTER USER`,
   `GRANT`/`REVOKE`, etc.), AND
3. The correct value is **organization-defined** (a site/mission decision the
   platform cannot make for the tenant).

Anything satisfied by the platform (broker infra, an RDS parameter/option group,
or an inherited OS/host/listener control) is a **platform responsibility** and is
classified in [`control-layers.yml`](../control-layers.yml) via its `set_by` /
`verified_by` axes — it is **not** listed as a customer responsibility here.

### Where the flags live

- **`control-layers.yml`** — the two-axis `set_by` / `verified_by` map is the
  starting point for the platform-side disposition (e.g. `aws_inherited`,
  `aws_rds_parameter_group`, `not_applicable_rds`, `sql_hardening`). Customer
  responsibility corresponds to a `set_by: sql_hardening` + `verified_by: sql`
  control whose remediation value is org-defined.
- **`controls/overlay.rb`** — the single, authoritative list of controls that
  are a **customer** responsibility. Each entry is one `skip_control 'SV-XXXXXX'`
  line inside the `include_controls` block, gated by the responsibility input.
  This is the file that actually drives the skip behavior at scan time.
- **`tag responsibility:`** — the DISA baseline metadata carries a bare
  `tag 'responsibility'`; overlay controls that document a platform disposition
  may use `tag responsibility: 'platform'`.

## Platform not-applicable overrides (not_applicable_rds)

Distinct from the customer-responsibility *skip*, some inherited controls have a
**platform disposition of `not_applicable_rds`**: their baseline check targets
the OS, host, or listener, which the tenant cannot reach on managed RDS. Running
such a check on RDS produces a *misleading* failure (e.g. reading a
`listener.ora` that does not exist under the tenant's `$ORACLE_HOME`).

For those, the overlay **overrides the inherited control in-place** and marks it
Not Applicable (`impact 0.0`) with a documented rationale, so the control is
reported once, honestly, as N/A rather than failed. Unlike the
customer-responsibility skip, this override applies in **both** run postures (it
is a platform fact, not a posture choice).

```ruby
include_controls 'oracle-database-19c-stig-baseline' do
  control 'SV-2704XX' do
    impact 0.0
    title '...'                      # required by the linter on an override
    desc  'Not Applicable on managed AWS RDS ...'
    tag responsibility: 'platform'
    describe '... is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): ...'
    end
  end
end
```

Confirm the control's `control-layers.yml` entry is
`set_by: aws_inherited` / `verified_by: not_applicable_rds` (or an equivalent
inherited/not-applicable pairing), then record it in the table below.

### Current platform not-applicable overrides

| Control | Intent | Why N/A on RDS |
| --- | --- | --- |
| SV-270496 | DoS attack mitigation (SC-5/AC-10) | Baseline check reads `$ORACLE_HOME/network/admin/listener.ora` for a connection `RATE_LIMIT`; the listener is AWS-managed on RDS (no OS/listener access) and the rate limit is inherited from the platform. Profile/quota DoS levers are org-defined limits on the customer-responsibility path (SV-270495), not this control's listener.ora assertion. |
| SV-270512 | Logical access restrictions on DBMS config/software (CM-5) | Baseline check is OS/filesystem only (`ls -ld` on the Oracle software install directory; fix sets the owner-account umask). No OS/host access on managed RDS — the Oracle Home and its permissions are AWS-managed and unreachable; the inherited `command('umask')` assertion reflects the InSpec runner host, not the DB server. Access restrictions to the DBMS software are inherited from the platform. |
| SV-270515 | Limit OS privileges over DBMS software libraries (CM-5(6)) | DISA check enumerates OS accounts with access to the software library (`cat /etc/group \| grep -i dba`, `cat /etc/passwd`) — unreachable on managed RDS (no OS access). The inherited baseline body substitutes a mismatched SQL check (DBA-role grantees via `dba_role_privs`) that does not assess the STIG's OS software-library file permissions (HANDOFF.md §6 needs_fix seed); DBA-role membership is covered by the dedicated account/role controls. Inherited from the platform. |
| SV-270510 | Protect the audit store (AU-9) | Inherited SQL check (mitre-baseline). RDS runs unified auditing in MIXED mode (pure mode unsupported), so the overlay sets `unified_auditing_used=true` / `standard_auditing_used=false` and SV-270510 assesses AUDSYS-owned objects (`AUD$UNIFIED` / `*UNIFIED_AUDIT_TRAIL`). `allowed_audit_users` defaults to the Oracle built-in audit roles (EXECUTE_CATALOG_ROLE, AUDIT_ADMIN, AUDIT_VIEWER) + RDSADMIN; the runner appends the broker DB_USER. **Accepted deviation:** the master/broker user holds RDS-default SELECT+DELETE on `AUD$UNIFIED`; AWS manages AUDSYS on RDS so the tenant cannot REVOKE it — allowlisted by grantee, documented, not a remediable finding. Any grantee outside the allowlist is still a finding. |
| SV-270499 | Organization-level auth / account management (AC-2(1)) | Platform-satisfied: database accounts are provisioned and authenticated through the FedRAMP-authorized CloudFoundry brokered-credentials model (part of the Cloud.gov ATO) — the enterprise-level authentication mechanism the DISA check's "not a finding" clause anticipates. Satisfied by the platform, not tenant SQL. `set_by: aws_inherited` / `verified_by: compensating_control`. |
| SV-270500 | Enforce approved authorizations for logical access (AC-3 / AC-6(10)) | Platform-satisfied at provision: the broker provisions the database with reviewed roles/profiles and issues a single customer user account via `cf create-service`. Appropriateness of that baseline authorization set is a platform provisioning fact, not a tenant SQL assertion. **Customer caveat:** if the customer creates additional users/roles, maintaining appropriate authorizations for them is the customer's responsibility. `set_by: broker_infra` / `verified_by: compensating_control`. |
| SV-270501 | Shared-account nonrepudiation (AU-10 / IA-2(5)) | Platform-satisfied at provision: the DISA check opens "If there are no shared accounts available to more than one user, this is not a finding," and the broker issues a single customer user account (not a shared account). Audit enablement (`audit_trail != NONE`) stays SQL-verified via SV-270502 (inherited). **Customer caveat:** if the customer creates additional users, maintaining individual attribution/nonrepudiation for them is the customer's responsibility. `set_by: broker_infra` / `verified_by: compensating_control`. |
| SV-270506 | Audit record storage capacity (AU-4) | DISA check assesses AUD$/AUDSYS tablespace placement (must not be SYSTEM/USERS), `audit_file_dest` space, and past audit-log-space exhaustion — all storage-capacity facts that on managed RDS are AWS/broker-owned (broker-provisioned storage + RDS storage autoscaling; AUDSYS/AUD$ and `audit_file_dest` live under SYS/AUDSYS and the DB host OS, AWS-managed and tenant-unreachable). The DISA fix (`dbms_audit_mgmt.move_dbaudit_tables`, resize) needs SYS/OS access the tenant lacks. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270507 | Off-load audit data to a central log facility (AU-4(1)) | Procedural DISA check (review documentation for how audit records are off-loaded). On managed RDS this is an AWS platform capability: RDS for Oracle publishes the audit trail to Amazon CloudWatch Logs continuously/near-real-time via DB instance log exports, feeding the Cloud.gov centralized logging posture (AU-4(1)/AU-6). A broker/platform integration configured outside the database, not a tenant SQL setting and not SQL-verifiable. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |

## Manual / compensating-control dispositions

Some DISA checks are **procedural**: the check procedure directs a reviewer to
inspect system documentation or organizational policy rather than query the
database. These are neither SQL-verifiable nor a managed-RDS platform fact, so
they are satisfied by **documentation or a compensating control** (typically a
Cloud.gov SSP control).

Like the platform not-applicable overrides, the overlay **overrides these
in-place** (`impact 0.0`) with a documented rationale so the control is reported
once, honestly, as a manual disposition rather than a zero-test pass or a
misleading failure. The override applies in **both** run postures (it is a
documentation fact, not a posture choice). Confirm the control's
`control-layers.yml` entry is `set_by: manual_review` / `verified_by:
manual_review`, then record it in the table below.

### Current manual / compensating-control overrides

| Control | Intent | How satisfied |
| --- | --- | --- |
| SV-270498 | Security labels on data in storage (AC-16) | Procedural: if no data is classified sensitive/CUI or labeling is not required per system documentation, this is Not a Finding. Satisfied by the Cloud.gov SSP data-classification (AC-16) posture. |
| SV-270503 | Select which auditable events are audited (AU-12 b) | Procedural, no pass/fail SQL: verify designated personnel can select audited events. Oracle inherently allows this via `AUDIT` / `CREATE AUDIT POLICY` under `AUDIT ANY` / `AUDIT SYSTEM` / `AUDIT_ADMIN`; the broker issues the customer a privileged account able to manage unified-audit policies (SV-270504 — the DoD event policies are platform-set on RDS). Satisfied by documentation of that audit-management authorization. |
| SV-270505 | Additional detailed audit info (AU-3(1)) | Conditional/procedural: "if there are none [additional site-specific detailed-audit requirements], this is not a finding." None defined for Cloud.gov RDS, so the not-a-finding clause is satisfied. The inherited baseline body runs an unconditional FGA-count query that would mislead on RDS; overridden to Manual. If additional detailed-audit requirements are later defined, deploying/verifying Fine-Grained Auditing is the customer's responsibility. |

## Run postures

The behavior is driven by the `skip_customer_responsibility_controls` input
(default `false`), set at scan time by `runner/run-validation.sh`:

| Posture | Flag | Input value | What runs |
| --- | --- | --- | --- |
| **`--all`** (default) | `--all` (or no flag) | `false` | The **full baseline** — every control, including customer-responsibility ones. Use this **after** the customer has applied the `hardening/sql/` scripts, to assess the fully-hardened database. |
| **Platform-only** | `--skip-customer-controls` (or `SKIP_CUSTOMER_CONTROLS=1`) | `true` | Customer-responsibility controls are **skipped** (reported as skipped with a caveat, `impact 0.0`), so a platform-only run is not failed by customer-owned remediation. |

```bash
# Platform-only posture (skip customer-responsibility controls):
run-validation.sh --skip-customer-controls
# or: SKIP_CUSTOMER_CONTROLS=1 run-validation.sh

# Full posture (default; assess everything after customer hardening):
run-validation.sh            # or explicitly: run-validation.sh --all
```

## How the skip is implemented (single file, input-gated)

`controls/overlay.rb` inherits **all** baseline controls via `include_controls`
and, in the same block, skips the customer-responsibility controls **only when the
gate is active** — following the MITRE overlay pattern
([sample-mysql-overlay/controls/overlay.rb](https://github.com/mitre/sample-mysql-overlay/blob/main/controls/overlay.rb)).
Because the skip happens in-place on the inherited control, it reports **once** (no
duplicate baseline finding):

```ruby
skip_customer = input('skip_customer_responsibility_controls') == true

include_controls 'oracle-database-19c-stig-baseline' do
  if skip_customer
    skip_control 'SV-270495'
  end
end
```

- **`skip_customer_responsibility_controls == false`** (default / `--all`): no
  `skip_control` is emitted, and the **inherited baseline assertion runs**.
- **`skip_customer_responsibility_controls == true`** (`--skip-customer-controls`):
  the control is skipped in-place — it does not run and cannot fail.

### Adding a control

Add **one line** inside the `if skip_customer` block in `controls/overlay.rb`:

```ruby
skip_control 'SV-2705XX'
```

Then record the same id in this document (below) and confirm its
`control-layers.yml` classification.

## Worked example — SV-270495

`SV-270495` (concurrent sessions per user / `SESSIONS_PER_USER`, AC-10) is the
canonical example:

- The **baseline check is correct** (it reads `SESSIONS_PER_USER` from the
  profiles and fails on `UNLIMITED`/`DEFAULT`).
- The **fix** is `ALTER PROFILE <profile_name> LIMIT SESSIONS_PER_USER <integer>`
  — database-altering SQL whose `<integer>` is **organization-defined** (the STIG
  itself says the number is site-specific). Cloud.gov cannot choose it for the
  tenant; `hardening/sql/15_concurrent_sessions.sql` is sample remediation only
  (it sets a high per-user cap of instance `SESSIONS` − headroom — sized for the
  single-app-user backend case these DBs serve — which the tenant MUST review; a
  multi-account tenant may need a tighter cap on its own profile).

Therefore SV-270495 is a **customer responsibility**: skipped on a platform-only
run, assessed under `--all` once the customer has applied a limit.

## Current customer-responsibility controls

| Control | Intent | Why customer-owned | Remediation step |
| --- | --- | --- | --- |
| SV-270495 | Concurrent session limits (`SESSIONS_PER_USER`) | Fix is `ALTER PROFILE ... LIMIT SESSIONS_PER_USER <n>` with an org-defined value (AC-10). | run `15_concurrent_sessions.sql` |
| SV-270504 (customer layer) | DoD-selected audit-event set — events the RDS defaults MISS (AU-12 c) | The RDS defaults (`ORA_SECURECONFIG` / `ORA_LOGON_FAILURES`) do not cover `REVOKE`, `CHANGE PASSWORD`, `LOGOFF`, `CREATE SPFILE`. Enabling a tenant policy that adds them is db-altering SQL against an org-defined action set. | run `30_audit_policies.sql` (creates/enables `CG_AUDIT_POLICY`) |

> **SV-270504 (DoD-selected audit-event set, AU-12 c) has two layers.** The
> control is tagged `responsibility: platform` (its base disposition) but runs a
> **second, customer-responsibility assertion** only in the `--all` posture:
>
> - **Platform layer (both postures):** the Oracle-provided policies
>   `ORA_SECURECONFIG` and `ORA_LOGON_FAILURES` are enabled **by default** on RDS
>   once the broker's `audit_trail` parameters are set (RDS parameter group), so
>   they cover the DoD categories they capture (privilege GRANT, security-config/
>   DDL, most account administration, ALTER SYSTEM/DATABASE, LOGON) with no tenant
>   step. Asserted via the `required_audit_policies` input (default
>   `ORA_SECURECONFIG` + `ORA_LOGON_FAILURES`).
> - **Customer layer (`--all` only):** the events the RDS defaults MISS — `REVOKE`,
>   `CHANGE PASSWORD`, `LOGOFF`, `CREATE SPFILE` — are covered
>   by a tenant-owned policy (`CG_AUDIT_POLICY`) created and enabled by
>   `hardening/sql/30_audit_policies.sql`. This assertion is **skipped on a
>   platform-only run** (`--skip-customer-controls`) and runs on `--all`. The site
>   policy name(s) are org-defined via the `customer_audit_policies` input (default
>   `CG_AUDIT_POLICY`); an **empty list skips** the customer assertion rather than
>   failing a site that has not declared its policies.
>
> Both layers are **detect-first** (this control never enables a policy). The
> generic mitre-baseline control remains a **Manual Review**; the overlay overrides
> it in-place. A site that uses a different policy name changes the
> `customer_audit_policies` default in `inspec.yml` (the runner is baked into the
> image, so inputs are not supplied at runtime). See `control-layers.yml`
> (`set_by: aws_rds_parameter_group / verified_by: sql`).

> **SV-270497 (automatic idle-session termination, `max_idle_time`, AC-12) is
> PLATFORM-remediated, not customer-owned.** `max_idle_time` is a modifiable,
> dynamic RDS parameter (confirmed 2026-08-19 in GovCloud us-gov-west-1 via
> `aws rds describe-engine-default-parameters --db-parameter-group-family
> oracle-se2-19 --region us-gov-west-1` → `IsModifiable=true`,
> `ApplyType=dynamic`, `AllowedValues 0-2147483647`), so it
> is applied through the RDS DB parameter group (not `ALTER SYSTEM`, which RDS
> blocks). It runs in every posture and is SQL-verified via `GV$PARAMETER`; see
> `control-layers.yml` (`set_by: aws_rds_parameter_group / verified_by: sql`).

> This list grows as controls are dispositioned. It MUST stay in sync with
> `controls/overlay.rb` (the authoritative, executable `skip_control` list).
