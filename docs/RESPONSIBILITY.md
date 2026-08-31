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
| SV-270508 | Audit storage 75 percent capacity warning (AU-5(1)) | Procedural DISA check (review OS or third-party logging application settings for warning delivery). On managed RDS, local audit storage and OS-level alerting are AWS-managed, and audit records are off-loaded through RDS log exports / CloudWatch Logs; capacity monitoring and alerting for that managed path are inherited from AWS/Cloud.gov, not tenant SQL. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270509 | Real-time alert on audit failure (AU-5(2)) | Procedural DISA check (review Oracle, OS, or third-party logging software alerting). On managed RDS, audit collection/log export and monitoring are broker/AWS platform integrations outside tenant database control; no tenant SQL assertion proves external alert delivery. Inherited from AWS/Cloud.gov. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270511 | Protect audit tools from unauthorized access/modification/deletion (AU-9 a/b/c) | Procedural DISA check (review permissions on tools used to view or modify audit logs). For brokered RDS, platform audit tooling is the managed AWS/Cloud.gov logging stack plus AWS-managed host/Oracle tooling tenants cannot access; protection is inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270513 | Vendor-supported Oracle Database version (SA-22 a) | Customers run AWS-exposed RDS Oracle engine versions; AWS has policies/procedures for support, deprecation, patching, and required upgrade paths to ensure supported versions. Unsupported engine selection is not tenant SQL remediation. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270514 | Monitor DBMS software/configuration changes (CM-5(6)) | DISA check reviews monitoring of DBMS software libraries and configuration files. On managed RDS those files are on AWS-managed hosts tenants cannot access; monitoring is inherited from AWS/Cloud.gov operational controls, and the inherited AIDE cron check reflects the runner host. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270516 | Restrict Oracle software installation account (CM-5(6)) | The Oracle software owner / host SYSDBA-capable installation account is AWS-managed and unavailable to tenants on RDS; the broker-created database user is not that account. Use restriction is inherited from AWS/Cloud.gov platform controls. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270537 | Log Oracle software installation account use (CM-6 b) | DISA check reviews procedures and host audit logs for monitoring use of the DBMS software installation account. On managed RDS the installation account and host audit logs are AWS-managed and unavailable to tenants; the broker-created database user is not that account. Logging/accountability is inherited from platform controls. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270538 | Separate data/log/audit directories (CM-6 b) | DISA check reviews host disk/directory placement for database data files, transaction logs, audit files, and application/software files. On managed RDS that filesystem/storage layout is AWS-managed (Oracle-Managed Files on RDS-provisioned storage), tenants cannot inspect or change host directories/partitions, and no tenant application shares the host filesystem. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270517 | Dedicated DBMS software/config directories (CM-5(6)) | DISA check is a filesystem/host review — inspect the DBMS software library directory and its disk/DASD neighbors for shared non-DBMS software — and the fix relocates other applications off that directory. Both need OS/filesystem access to the DB host, which the tenant lacks on managed RDS: the Oracle Home, its directory layout, and disk/DASD placement are AWS-managed and unreachable, and no other tenant application shares the RDS host. Inherited baseline body is a manual-review skip. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270531 | Oracle Listener administration authentication (CM-6 b, CAT I) | DISA check is OS/listener-level: Not a Finding when no listener runs on the local host, else enumerate host listener processes (`ps -ef \| grep tnslsnr`, Windows TNSListener services) and run `lsnrctl status` to read the Security value; fix relies on local OS authentication of the listener-owner account. On managed RDS the listener is AWS-managed on the AWS-controlled host — no tenant OS/listener access; the inherited `command('ps ... tnslsnr')` / `command('lsnrctl status')` assertions reflect the InSpec runner host (no listener), producing a misleading result. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-275999 | Three+ control files, each on a separate physical/logical device (CM-6 b) | The control-file count (>=3) is SQL-visible via `v$controlfile`, but the STIG's actual requirement — each control file on a **separate physical and logical device** (RAID 1+0) — is a storage-topology fact the DISA check directs a reviewer to confirm with the storage/system/database administrator (file paths do not prove device separation). On managed RDS the tenant has no visibility into or control over the underlying storage: control-file count, multiplexing, and physical/logical device placement are AWS-managed (Oracle-Managed Files on RDS-provisioned storage with AWS-side redundancy), and `v$controlfile` paths cannot be mapped to distinct devices. A count-only SQL check cannot see the device-separation requirement; overridden to N/A. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270539 | Restrict network access to authorized personnel (CM-6 b) | DISA check enforces IP-address restriction at the network layer — the listener SQLNET.ORA (`tcp.validnode_checking=YES` / `tcp.invited_nodes`) in `$ORACLE_HOME/network/admin`, an Oracle Connection Manager CMAN.ORA `RULE` set, or an external network device — none reachable by the tenant on managed RDS. The inherited baseline reads the runner host's `sqlnet.ora` (no tenant-managed file on RDS), a misleading signal. Network access restriction is an AWS platform function: the listener is AWS-managed and unreachable, and inbound access is governed by VPC security groups and the Cloud.gov brokered private-networking posture, not a tenant SQL/OS setting. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270541 | Protect `<DIAGNOSTIC_DEST>/diag` from unauthorized access (CM-6 b) | DISA check reads `DIAGNOSTIC_DEST` via SQL, then inspects OS filesystem permissions on `<DIAGNOSTIC_DEST>/diag` (`ls -ld` on Unix, Explorer ACLs on Windows); the fix alters host filesystem permissions. Both need OS/filesystem access to the DB host, which the tenant lacks on managed RDS — the diagnostic/diag directory and its permissions are AWS-managed and unreachable, and the inherited baseline `command('ls -ld <DIAGNOSTIC_DEST>/diag')` assertion reflects the InSpec runner host, not the DB server. Filesystem protection of the diagnostic directory is inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270542 | Disable remote administration for the Oracle Connection Manager (CM-6 b) | DISA check reads `cman.ora` in `$ORACLE_HOME/network/admin` and is explicitly **Not a Finding when the file does not exist** (Connection Manager not in use). On managed RDS Oracle Connection Manager is not deployed and the tenant has no OS access to place or read a `cman.ora`; any Connection Manager in the AWS network path is AWS-managed and unreachable. The inherited baseline reads `cman.ora` on the runner host and asserts `should exist`, which would falsely FAIL on a missing file even though the STIG treats that as Not a Finding — a misleading signal. Connection Manager configuration is inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270534 | Protect LOG_ARCHIVE_DEST* directories (CM-6 b) | DISA check has a SQL fragment (confirm archive logging is configured; Not a Finding when NOARCHIVELOG) but its actual requirement is the **OS filesystem permissions** on the archive/recovery directories (`ls -ld [pathname]`, Windows ACLs — a finding on world/everyone access or any account beyond the Oracle owner/DBAs/backup operators). The fixed baseline body only asserts a destination is configured, not its permissions. On managed RDS the archive-log and fast-recovery-area directories are AWS-managed (Oracle-Managed Files on RDS-provisioned storage) with no tenant OS access to run `ls -ld` or alter permissions — the protectable target is unreachable. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270543 | Restrict clients to supported logon versions (CM-6 b) | DISA check inspects the `sqlnet.ora` file in `$ORACLE_HOME/network/admin` (or `TNS_ADMIN`) for `SQLNET.ALLOWED_LOGON_VERSION_SERVER` / `_CLIENT` = 12 (or 12a); the fix edits that file. Both need host/OS access to the Oracle Net configuration, which the tenant lacks on managed RDS — `sqlnet.ora` is AWS-managed and unreachable, and the inherited `file(".../sqlnet.ora")` assertion reflects the runner host, not the DB server. Allowed-logon-version enforcement is part of the broker-managed Oracle Net configuration (same AWS-managed `sqlnet.ora` layer as the SSL option group). Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270544 | Limit DBA OS-account host privileges (CM-6 b, high) | DISA check is entirely OS/host-level: Unix `cat /etc/group \| grep -i dba`, `groups root`, `groups [dba user]` (findings: root in the DBA group, a DBA account in the root group, or a DBA account in non-DBA privilege groups); Windows `ORA_DBA` / `ORA_[SID]_DBA` local groups and directly assigned User Rights. The fix revokes host privileges and OS group memberships. On managed RDS the tenant has no OS/host access — `/etc/group`, `/etc/passwd`, the DBA/root groups, and Windows local groups are AWS-managed and unreachable, and the broker-issued database user is not a host OS account; the inherited `command('cat /etc/group ...')` / `command('groups root')` assertions reflect the runner host, not the DB server. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270548 | Protect DB from developers on shared prod/dev hosts (AC-5 c / CM-6 b) | DISA check is explicitly **Not Applicable when no host contains both a development and a production database**, and otherwise is a host/OS review (`/etc/oratab` co-resident instances, host developer-privilege documentation). On managed RDS the tenant has no host/OS access and the broker provisions each database as a **dedicated** instance — not a shared dev/prod host — so the not-applicable clause holds. Inherited baseline body is a manual-review skip. In-database developer-privilege appropriateness on customer-created accounts remains a customer responsibility (role/authorization controls). Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270555 | Limit extproc OS-account privileges (CM-6 b / CM-7 a) | DISA check inspects the OS account behind the external-procedure agent — reads `$ORACLE_HOME/rdbms/admin/externaljob.ora` for `run_user=`/`run_group=` (expected "nobody") and reviews that account's privileges; the fix limits those DBMS-related OS-account privileges. Both are host/OS facts unreachable on managed RDS (`externaljob.ora` and the OS accounts are under the AWS-managed Oracle Home / DB host; no tenant OS access nor a tenant-usable extproc OS agent). The inherited `file(".../externaljob.ora")` assertion reflects the runner host. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270557 | Disable/restrict access to external executables (CM-7 a) | DISA check is host/OS/listener-level: locate the `extproc` executable under `$ORACLE_HOME/bin` and check its permissions; read `$ORACLE_HOME/rdbms/admin/externaljob.ora` and `$ORACLE_HOME/hs/admin/extproc.ora` (`EXTPROC_DLLS=ONLY:...`); inspect `listener.ora`/`tnsnames.ora` for `extproc` references and a dedicated IPC listener. The fix stops the listener, edits those files, and alters executable permissions. All need OS/filesystem + listener access the tenant lacks on managed RDS — the Oracle Home and AWS-managed listener are unreachable, and RDS does not expose the extproc agent; the inherited `file(...)` `should exist` assertions would falsely fail on the runner host. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270578 | Limit access to Oracle Database files (SC-4) | DISA check is OS/filesystem-only: `ls -ld [pathname]` against the data-file, log, and backup directories (`.../oradata/db_name`, `.../oradata/db_name/audit`, `.../fast_recovery_area/db_name`) — a finding on world access or any non-authorized reader — or the equivalent Windows Explorer directory ACLs; the fix sets those filesystem permissions. Both need OS/filesystem access to the DB host, which the tenant lacks on managed RDS — the data files, redo/archive logs, and backup files reside on AWS-managed Oracle-Managed-Files storage that is not tenant-reachable, and RDS backups are AWS-managed snapshots. The inherited baseline is a documentation/manual control with no SQL body. Inherited from the platform. `set_by: aws_inherited` / `verified_by: not_applicable_rds`. |
| SV-270579 | Encrypt information in transit (SC-8(1)/SC-8(2)) | DISA check reads `$ORACLE_HOME/network/admin/sqlnet.ora` for the network-encryption / crypto-checksum parameters (`SQLNET.ENCRYPTION_TYPES_*` = AES256, `SQLNET.CRYPTO_CHECKSUM_TYPES_*` = SHA384, `CRYPTO_CHECKSUM_SERVER` = required), and the inherited baseline asserts those same strings in that file. On managed RDS `sqlnet.ora` is AWS-managed and unreachable, so the inherited `file()` assertion reflects the InSpec runner host, not the DB server. Encryption in transit is delivered by the broker SSL option group — a TCPS 2484 listener running TLS 1.2 with a FedRAMP/FIPS cipher (`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`) and `FIPS.SSLFIPS_140=TRUE`, in the AWS-managed `sqlnet.ora`/`fips.ora` layer (aws-broker#564) — evidenced by option-group config + a client TCPS handshake, not tenant SQL. A true TLS-only posture also depended on the platform blocking 1521 (terraform-provision#2351, implemented). Inherited from the platform. `set_by: aws_rds_option_group` / `verified_by: not_applicable_rds`. |
| SV-270589 | Only approved trust anchors (SC-17 b) | DISA check is Not a Finding when accounts are authenticated by the OS or an enterprise-level mechanism rather than by Oracle, and otherwise verifies TLS trust anchors by inspecting the Oracle Wallet and `$ORACLE_HOME/network/admin/sqlnet.ora` (`WALLET_LOCATION`, `SSL_CIPHER_SUITES`, `SSL_VERSION`, `SSL_CLIENT_AUTHENTICATION`). The wallet and `sqlnet.ora` are the same AWS-managed Oracle Net / SSL layer as SV-270579 — unreachable by the tenant on managed RDS. The TLS trust store / Oracle Wallet is provisioned and managed by the broker SSL option group; which trust anchors are present is a platform responsibility evidenced by the option-group configuration, not tenant SQL. The inherited baseline is a documentation/manual control with no SQL body. Inherited from the platform. `set_by: aws_rds_option_group` / `verified_by: not_applicable_rds`. |
| SV-270569 | FIPS 140 cryptography for authentication (IA-7) | DISA check/fix target `SSLFIPS_140=TRUE` in `$ORACLE_HOME/ldap/admin/fips.ora` (or the `FIPS_HOME` location) — a host/OS file in the AWS-managed Oracle Net / SSL layer the tenant cannot reach on managed RDS; the inherited `file("#{oracle_home}/ldap/admin/fips.ora")` assertion resolves `ORACLE_HOME` on the InSpec runner host, not the DB server. FIPS-mode SSL/TLS for authentication is set by the broker SSL option group (`FIPS.SSLFIPS_140=TRUE` on the TCPS 2484 / TLS 1.2 listener — the SV-270579 posture), evidenced by option-group config, not tenant SQL. Inherited from the platform. `set_by: aws_rds_option_group` / `verified_by: not_applicable_rds`. |
| SV-270571 | FIPS 140 validated cryptographic modules (SC-13 b) | DISA check is Not a Finding if encryption is not required, else verifies FIPS mode via `DBFIPS_140` (`V$PARAMETER`, for TDE / `DBMS_CRYPTO`), `SSLFIPS_140=TRUE` in `fips.ora` (SSL/TLS), and `SQLNET.FIPS_140=TRUE` in `sqlnet.ora` (Native Network Encryption). The `fips.ora`/`sqlnet.ora` legs are AWS-managed Oracle Net / SSL files unreachable on RDS (same layer as SV-270569 / SV-270579); `DBFIPS_140` is set at the instance level by the AWS RDS parameter/option group, not a tenant `ALTER SYSTEM`. Validated crypto modules are platform-provided in transit (broker SSL option group, aws-broker#564) and at rest (broker KMS storage encryption — the "at rest" entry), evidenced by option-group config + AWS metadata, not tenant SQL. Generic baseline is a `needs_dev` stub (no SQL body). Inherited from the platform. `set_by: aws_rds_option_group` / `verified_by: not_applicable_rds`. |
| SV-270574 | Protect data at rest (SC-28) | DISA check is procedural: "If full-disk encryption is being used, this is not a finding"; only if data-at-rest encryption is required and full-disk encryption is not in use does it fall back to Oracle TDE (`dba_encrypted_columns` / `v$encrypted_tablespaces`). On managed RDS storage encryption at rest is enabled by the broker at provision (`StorageEncrypted` set from the catalog plan's `encrypted:true`, which uses an AWS-managed KMS key by default — the "at rest" entry), which is the full-disk / storage-volume encryption the not-a-finding clause names, and Cloud.gov defines no data-at-rest encryption requirement beyond it, so the TDE fallback never applies. Encryption at rest is a platform fact evidenced by AWS metadata (`StorageEncrypted`), not tenant SQL; the queried TDE target is not tenant-reachable on RDS, so the overlay overrides to **N/A (platform)** (impact 0.0). **Customer caveat:** if a data owner/AO requires column/tablespace TDE beyond volume encryption, deploying/verifying TDE for that data is the customer's responsibility. Inherited from the platform. `set_by: broker_infra` / `verified_by: aws_inherited`. |



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

## Inherited controls with a platform-seeded allowlist input

Some inherited baseline controls are **SQL-verifiable and kept running as-is**
(no override), but their assertion compares against an **org-defined allowlist
input** whose *baseline* membership on a stock brokered RDS instance is a
**platform** fact. For these the overlay stays `inherited` (the baseline check is
correct and runs in both postures), and `rds-inputs.yml` **seeds the
platform accounts** into the input so a stock brokered instance passes without a
finding. Any grantee/owner **outside** the seeded list is still a real finding —
seeding the platform baseline never suppresses a detectable drift (the two-axis
rule). Customer-added principals can be appended via an input file passed after
the runner's default.

| Control | Intent | Input | Platform-seeded baseline | Still a finding |
| --- | --- | --- | --- | --- |
| SV-270518 | Authorized database object owners (CM-5(6)) | `allowed_dbaobject_owners` | Pre-provisioned object owners allowed on the reviewed brokered RDS instance: `SYS`, `SYSTEM`, `DBSNMP`, `APPQOSSYS`, `DBSFWUSER`, `REMOTE_SCHEDULER_AGENT`, `PUBLIC`, `CTXSYS`, `AUDSYS`, `GSMADMIN_INTERNAL`, `RDSADMIN`, `OUTLN`, `ORACLE_OCM`, `XDB` **plus the per-instance broker `DB_USER`** (the baseline asserts every `DBA_OBJECTS` owner is allowlisted, so the connecting user must be present or the control fails on its first owned object). Seeded dynamically by `run-validation.sh` (not the committed file, which cannot interpolate `DB_USER`); inherited baseline SQL runs in both postures. | Any owner outside this allowlist is a finding unless documented and added by the site. |
| SV-270530 | Restrict object permissions granted to PUBLIC (CM-6 b) | `users_allowed_access_to_public` | The Oracle predefined product accounts that hold PUBLIC object grants on a stock install (`SYS`, `SYSTEM`, `CTXSYS`, `GSMADMIN_INTERNAL`, `XDB`) plus the AWS-managed **`RDSADMIN`** platform account — the DISA check's "list of nonapplicable [Oracle product] accounts." Seeding these is a **platform responsibility** (confirmed against a provisioned RDS instance: owners with PUBLIC grants = SYS, SYSTEM, CTXSYS, GSMADMIN_INTERNAL, RDSADMIN, XDB). | Any **other** owner granting to PUBLIC (e.g. a customer application schema) is a finding; the tenant must `REVOKE` it (`40_public_grants_assess.sql` is detect-first). |
| SV-270553 | Remove unused DBMS components (CM-7 a) | `authorized_components` | On managed RDS the installed component set is fixed at database creation by AWS and is **not tenant-removable**; a brokered instance ships Oracle Text (**`CONTEXT`**) installed and VALID, so `CONTEXT` is the default authorized member (documented and authorized here). The overlay overrides the baseline pending-skip with an in-place SQL assertion (overlay-sql) that runs the DISA `dba_registry` query — which already excludes the core comp_ids `CATJAVA`/`CATALOG`/`CATPROC`/`SDO`/`DV`/`XDB` and `OPTION OFF` rows — and fails on any returned comp_id not in this list. Detect-first (removal is not possible on RDS). | Any installed component **outside** the allowlist (beyond the STIG-excluded core comp_ids) is a finding for review; the customer documents/authorizes it or, where removal is possible, requests it be excluded at provisioning. |

## Run postures

The behavior is driven by the `skip_customer_responsibility_controls` input
(default `false`), set at scan time by `runner/run-validation.sh`:

| Posture | Flag | Input value | What runs |
| --- | --- | --- | --- |
| **`--all`** (default) | `--all` (or no flag) | `false` | The **full baseline** — every control, including customer-responsibility ones. Use this **after** the customer has applied the `hardening/sql/` scripts, to assess the fully-hardened database. |
| **Platform-only** | `--skip-customer-controls` (or `SKIP_CUSTOMER_CONTROLS=1`) | `true` | Customer-responsibility controls with SQL-assessed elements are **skipped** when they would produce misleading findings in a platform-provider run. Baseline controls already skipped because they require manual review are not included in this overlay gate. |

```bash
# Platform-only posture (skip customer-responsibility controls):
run-validation.sh --skip-customer-controls
# or: SKIP_CUSTOMER_CONTROLS=1 run-validation.sh

# Full posture (default; assess everything after customer hardening):
run-validation.sh            # or explicitly: run-validation.sh --all
```

## How the skip is implemented (single file, input-gated)

`controls/overlay.rb` inherits **all** baseline controls via `include_controls`
and, in the same block, skips only customer-responsibility controls with
**SQL-assessed elements** that would produce misleading findings in a
platform-provider run. Baseline controls already skipped because they require
manual review are not included in this overlay gate. This follows the MITRE overlay pattern
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
  qualifying SQL-assessed customer-responsibility controls are skipped in-place —
  they do not run and cannot fail in a platform-provider run.

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

Controls marked `baseline manual skip` are already skipped by the baseline manual
review implementation and are not listed in `controls/overlay.rb`'s SQL-only
customer skip gate.

| Control | Intent | Why customer-owned | Remediation step |
| --- | --- | --- | --- |
| SV-270495 | Concurrent session limits (`SESSIONS_PER_USER`) | Fix is `ALTER PROFILE ... LIMIT SESSIONS_PER_USER <n>` with an org-defined value (AC-10). | run `15_concurrent_sessions.sql` |
| SV-270520 | Apply STIG/DOD configuration guidance (CM-6 b) | Running Oracle DBSAT requires a customer-created DBSAT user with specific privileges/grants, which is database-altering setup outside platform provisioning scope. Cloud.gov uses this InSpec/CINC Auditor overlay as a compensating automated validation path for controls subject to automated validation. Baseline manual skip. | create/configure DBSAT user as needed; run InSpec/CINC Auditor overlay |
| SV-270536 | Shield production from development access (CM-6 b) | Customers must define and enforce policies/procedures for how team members use broker-provided database access across production and development environments. This is not satisfied by AWS RDS and has no tenant SQL assertion in the overlay. Baseline manual skip. | document and review customer team access policies/procedures |
| SV-270549 | Account lockout persists until admin reset (`PASSWORD_LOCK_TIME`, AC-7 b) | Fix is `ALTER PROFILE <profile> LIMIT PASSWORD_LOCK_TIME UNLIMITED` against a site profile — org-defined db-altering SQL. Baseline check correct (`should cmp 'UNLIMITED'` per profile). | run `10_profiles.sql` (DEFAULT) and/or `11_ora_stig_profile.sql` (`ORA_STIG_PROFILE`) |
| SV-270550 | Max consecutive invalid logon attempts = 3 (`FAILED_LOGIN_ATTEMPTS`, CM-6 b) | Fix is `ALTER PROFILE <profile> LIMIT FAILED_LOGIN_ATTEMPTS 3` — org-defined db-altering SQL. Baseline SQL assertion implemented upstream (mitre-baseline `fix/sv-270550-failed-login-attempts`, held for PR). | run `10_profiles.sql` (DEFAULT) and/or `11_ora_stig_profile.sql` (`ORA_STIG_PROFILE`) |
| SV-270551 | Disable accounts after 35 days inactivity (`INACTIVE_ACCOUNT_TIME`, IA-4 e / AC-2(3)(a)) | Fix is `ALTER PROFILE <profile> LIMIT INACTIVE_ACCOUNT_TIME 35` (or `ALTER USER ... PROFILE ORA_STIG_PROFILE`) — org-defined db-altering SQL. Baseline check correct (`should_not cmp 'UNLIMITED'` and `<= account_inactivity_age` per profile). | run `10_profiles.sql` (DEFAULT) and/or `11_ora_stig_profile.sql` (`ORA_STIG_PROFILE`) |
| SV-270504 (customer layer) | DoD-selected audit-event set — events the RDS defaults MISS (AU-12 c) | The RDS defaults (`ORA_SECURECONFIG` / `ORA_LOGON_FAILURES`) do not cover `REVOKE`, `CHANGE PASSWORD`, `LOGOFF`, `CREATE SPFILE`. Enabling a tenant policy that adds them is db-altering SQL against an org-defined action set. | run `30_audit_policies.sql` (creates/enables `CG_AUDIT_POLICY`) |
| SV-270546 | Identify temporary/emergency accounts (CM-6 b / AC-2(2)) | DISA allows a policy forbidding temporary/emergency accounts or enterprise authentication as Not a Finding; if Oracle-managed temporary accounts are used, the customer must define, create, and assign a distinctive temporary profile. | customer policy, or create/assign a temporary profile |

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
