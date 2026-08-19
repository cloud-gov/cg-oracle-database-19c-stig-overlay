---
title: "Control responsibility model — platform vs. customer"
description: "How Oracle 19c STIG controls are flagged as a Cloud.gov platform responsibility or a customer responsibility, and how the overlay skips customer-responsibility controls on a platform-only run."
status: draft
tier: 2
last_updated: "2026-08-18"
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
- **`controls/baseline.rb`** — the single, authoritative list of controls that
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
| SV-270499 | Organization-level auth / account management (AC-2(1)) | Satisfied by the Cloud.gov SSP AC-2(1) control (org identity + account-management automation). Mirrors the MySQL STIG disposition. |

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

`controls/baseline.rb` inherits **all** baseline controls via `include_controls`
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

Add **one line** inside the `if skip_customer` block in `controls/baseline.rb`:

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
  tenant; `hardening/sql/10_profiles.sql` is sample remediation only.

Therefore SV-270495 is a **customer responsibility**: skipped on a platform-only
run, assessed under `--all` once the customer has applied a limit.

## Current customer-responsibility controls

| Control | Intent | Why customer-owned |
| --- | --- | --- |
| SV-270495 | Concurrent session limits (`SESSIONS_PER_USER`) | Fix is `ALTER PROFILE ... LIMIT SESSIONS_PER_USER <n>` with an org-defined value (AC-10). |

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
> `controls/baseline.rb` (the authoritative, executable `skip_control` list).
