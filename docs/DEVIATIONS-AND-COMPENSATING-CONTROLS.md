# Oracle 19c Broker — STIG Deviations & Compensating Controls (ISSO Package)

> **Audience:** ISSO / Authorizing Official reviewing the STIG-hardened Oracle
> Database 19c offering on brokered AWS RDS (GovCloud).
> **Baseline:** FedRAMP / NIST 800-53 **Moderate**; DISA **Oracle Database 19c STIG**.
> **System component:** the Oracle SE2 RDS plans in the cloud.gov `aws-broker` —
> `medium-oracle-se2` and `medium-oracle-se2-redundant` (Multi-AZ) — validated
> out-of-band by the
> [`cg-oracle-database-19c-stig-overlay`](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay).
> **Status at time of writing:** DEV/TEST only; **not yet authorized for
> staging/production**. This document is the deviation/compensating-control record
> the ISSO needs to make that determination.
> **Last reviewed:** 2026-09-04.
>
> **Read this first.** The Oracle broker code is on the long-lived integration branch
> `feat/oracle-19c-stig-brokered-rds`, **not on `aws-broker`'s `main`** — `main`
> carries the catalog plans only. Merged so far: cloud-gov/aws-broker#564 (minimal
> SE2 + TLS/TCPS), #567 (Multi-AZ plan), #573 (`max_idle_time`), #562 (storage
> autoscaling, opt-in). Remaining hardening: cloud-gov/aws-broker#568. Control
> dispositions in this repo are still landing in batches — re-check this package
> against the code and `controls/overlay.rb` before an authorization decision.

This is a summary/rollup for the ISSO. **`controls/overlay.rb` is authoritative** —
it is the executable profile that produces the assessment result, and each
control's canonical rationale lives in its `control` block. `control-layers.yml` is
a machine-readable index over those dispositions, and this document is a narrative
rollup of them. Where any of the three disagree, the order of precedence is
`controls/overlay.rb` → `control-layers.yml` → this document.

> **Two kinds of deviation in this package.** §2 (**D-1…D-4**) are *feature-absence*
> deviations — capabilities SE2 does not have. §2a (**D-5…D-10**) are
> *compensating-control* dispositions — controls the platform cannot satisfy as the
> STIG literally specifies, met instead by a different documented mechanism. Both
> require explicit ISSO acceptance; they are recorded separately because the
> assessor's question differs ("is the missing feature acceptable?" vs. "is the
> substitute mechanism equivalent?").

---

## 1. Scope and shared-responsibility boundary

The offering provisions a **dedicated Amazon RDS for Oracle Database 19c, Standard
Edition 2 (SE2), License Included** instance, private-only and encrypted at rest,
with a broker-managed hardened parameter group, default CloudWatch audit log
exports, and an SSL/TCPS option group for encryption in transit.

Responsibility is split across four parties. Every deviation below is a direct
consequence of this boundary:

| Layer | Owner | Examples |
|-------|-------|----------|
| Host OS, hypervisor, physical, patching of the managed engine, listener process | **AWS (inherited)** | OS STIG controls, `sqlnet.ora` on disk, file permissions |
| Instance-level config (encryption, private networking, backups, parameter/option groups, log exports) | **Broker (this repo)** | at-rest encryption, `audit_trail`, TLS option group |
| Network ingress/egress (open TCPS 2484, deny plaintext 1521) | **cg-provision platform** (security groups) | TLS-only enforced by [terraform-provision#2351](https://github.com/cloud-gov/terraform-provision/pull/2351) (merged); cloud-gov/aws-broker#541 closed |
| In-database hardening (profiles, account lockout, unified audit policies, PUBLIC-grant review, least-privilege app users) | **Customer**, validated by the **overlay** | SQL-layer STIG controls; per-binding least-privilege users |

Because this is **managed RDS**, no party has host/OS/listener-file access. That is
the root cause of the "not applicable / AWS-inherited" control set in §3.

> **⚠️ In-database hardening is not automatic (issue
> [#557](https://github.com/cloud-gov/aws-broker/issues/557)).** The broker hardens
> the control-plane layer (parameter/option groups, encryption, networking) and
> never connects to the provisioned database. The row-4 SQL controls exist in this
> repo's `hardening/sql/` but nothing in the `cf create-service` flow runs them, so
> the in-database layer is **operator/customer-applied and overlay-validated**, not
> applied at provision. Some of it could not be applied at provision in any case —
> SQL must run against a started instance, and some parameter-group values only
> take effect after a reboot.
>
> **The ISSO/AO decision this forces:** what "STIG-hardened" means contractually
> for this offering — control-plane-only, with in-database hardening as a documented
> operator prerequisite, or something stronger. cloud-gov/aws-broker#557 tracks that decision; no
> mechanism is proposed here.

---

## 2. Deviations requiring ISSO acceptance

Four deviations require an explicit risk-acceptance decision. Each is stated as:
*what the STIG expects → why we deviate → the compensating control → residual risk.*

### D-1 — No Oracle-native Transparent Data Encryption (TDE)

- **STIG expectation:** Oracle-native TDE for data-at-rest encryption
  (tablespace/column), an Enterprise-Edition feature.
- **Deviation:** SE2 does **not** include TDE. (See §4 for why the offering is SE2.)
- **Compensating control:** **RDS storage-level encryption at rest, AES-256 via
  AWS KMS** (`encrypted: true` on every instance — enforced by the broker, not
  optional). This is the *same* at-rest control already accepted for the
  PostgreSQL and MySQL RDS plans in this broker, and is edition-independent. It
  encrypts the underlying storage volume, automated backups, snapshots, and read
  replicas.
- **Residual risk:** TDE encrypts within the database (column/tablespace
  granularity, protecting against some DBA-tier and backup-copy scenarios); KMS
  storage encryption encrypts the volume beneath the database. For a
  **Moderate** system where the threat model is loss/theft of the storage medium
  and backup artifacts — not defense against a compromised DBA — KMS storage
  encryption is a recognized equivalent. **Low residual risk at Moderate.**
- **Re-open trigger:** if any control is interpreted to *require* in-database TDE
  specifically, the edition decision (EE + BYOL) must be re-opened — see §4.

### D-2 — No Fine-Grained Auditing (FGA)

- **STIG expectation:** Fine-Grained Auditing for policy-based, column/predicate-
  level audit — an Enterprise-Edition feature.
- **Deviation:** SE2 does not include FGA. Additionally, **even on EE, RDS does not
  export FGA events to CloudWatch**, so FGA would not close the gap on managed RDS
  regardless of edition.
- **Compensating control:** **Standard / unified (mixed-mode) auditing** via
  `audit_trail = DB,EXTENDED` + `audit_sys_operations = TRUE` (broker parameter
  group), exported to CloudWatch Logs via the default **`audit`** log export
  (retained/forwarded per platform log policy). SYS/privileged operations are
  audited. The overlay's unified-audit-policy hardening (SQL layer) builds on this.
- **Residual risk:** standard/unified auditing captures statement- and
  privilege-level events across the instance; it lacks FGA's row/column-predicate
  selectivity. For Moderate audit-generation requirements (AU-2/AU-3/AU-12) the
  captured event set is sufficient. **Low residual risk at Moderate.**

### D-3 — Oracle Database Vault, VPD, Label Security, Data Redaction not present

- **STIG expectation:** several STIG controls reference EE-only separation-of-duty
  / access-mediation features (Database Vault, VPD, OLS, Data Redaction).
- **Deviation:** none are available on SE2; **Database Vault is unsupported on RDS
  even for EE** (AWS does not offer it as a managed option).
- **Compensating control:** access mediation is provided by (a) private-only
  networking + security groups (SC-7), (b) the DBA/least-privilege split the
  customer implements per binding (AC-6, see §5 / D-4 pattern), and (c) unified
  auditing of privileged operations (AU-2). These are not feature-for-feature
  equivalents; they are the standard managed-RDS control posture.
- **Residual risk:** **accepted as not-applicable to a managed-RDS SE2 offering.**
  A workload that specifically requires Database Vault-style separation of duty is
  **out of scope** for this plan and should not be placed on it.

### D-4 — Binding returns the instance master credential (DBA-class)

- **STIG expectation:** least-privilege database accounts (AC-6).
- **Deviation:** the OSB binding returns the **instance master credential**, the
  same model as the Postgres/MySQL RDS plans. On Oracle this credential is
  **DBA-class** (RDS grants the master a DBA-style role), i.e. more privileged than
  a Postgres/MySQL master.
- **Compensating control (current):** documented **customer guidance** to create a
  least-privilege application user inside the database and bind applications to
  *that*, never to the master (`docs/oracle19c/limitations.md`). Credential
  rotation runbook provided (`ops/oracle19c/credential-rotation.md`). Encryption in
  transit (§5, TCPS/TLS) protects the credential on the wire; the broker stores
  bound credentials encrypted at rest per its existing model (see the crypto note
  in §5 re: **cloud-gov/aws-broker#554** — the at-rest cipher is being migrated to an authenticated/
  FIPS-validated mode).
- **Residual risk:** this is a **known pre-release blocker for any non-dev /
  production plan** — tracked as **cloud-gov/aws-broker#534** (broker-managed per-binding
  least-privilege users). Until cloud-gov/aws-broker#534 lands, the offering stays **dev/test only**.
  **This deviation is acceptable for the dev/test plan; it is NOT yet acceptable for
  staging/production** — see §6.

---

## 2a. Compensating-control dispositions requiring ISSO acceptance

These are controls where the STIG requirement is **not met as literally specified**
and is instead addressed by a different documented mechanism. D-5…D-9 are the five
controls classified `verified_by: compensating_control` in `control-layers.yml`;
**D-10 is classified `verified_by: sql`** — its SQL check still runs and still
detects grant drift — but it carries an accepted deviation in its rationale, so it
belongs in this section for acceptance purposes.

They are listed separately from D-1…D-4 because the assessor's question is not "is a
missing feature acceptable?" but "is the substitute mechanism equivalent?".

**None of these is a silent pass.** Each is a recorded disposition with a rationale
in `control-layers.yml`. Each requires ISSO acceptance before production.

### D-5 — Redo log member multiplexing not achievable on managed RDS (SV-276000)

- **STIG expectation:** ≥3 redo log groups **and** ≥2 members per group
  (`V$LOG.MEMBERS >= 2`), so the loss of a single member does not lose the log.
- **Deviation:** on managed RDS, groups are compliant (≥3) but **`MEMBERS = 1`**, and
  the tenant **cannot** fix it — `ALTER DATABASE ADD LOGFILE MEMBER` requires OS
  filesystem paths no party has on managed RDS. The requirement is therefore
  **factually unmet**, not merely unverifiable.
- **Compensating control:** redo logs sit on **Amazon EBS**, which replicates within
  the Availability Zone, and the `medium-oracle-se2-redundant` plan adds
  **Multi-AZ** synchronous standby replication. Automated backups + point-in-time
  recovery provide the recovery objective the STIG's multiplexing requirement
  exists to protect. The DISA check text itself exempts an equivalent
  hardware/RAID-level redundancy mechanism; EBS replication is that class of
  mechanism, applied at the storage layer rather than by Oracle.
- **Why SQL cannot confirm it:** `V$LOG`/`V$LOGFILE` can see the **deficit**
  (`MEMBERS = 1`) but not the **compensating mechanism** — EBS replication and
  customer-elected Multi-AZ are not visible to any tenant SQL. Hence
  `verified_by: compensating_control`, not `sql`.
- **Residual risk:** loss of the single member in a non-Multi-AZ instance falls back
  to backup/PITR rather than an in-place mirror. Multi-AZ is **customer-elected**,
  so a customer on the single-AZ plan carries more of this risk.
- **Status:** **pending ISSO acceptance.** Until accepted, the honest reading is an
  open finding with a documented compensating control — not "Not Applicable".

### D-6 — Enterprise authentication satisfied by the CF brokered-credentials model (SV-270499)

- **STIG expectation:** organization-level account management / authentication
  (AC-2(1)).
- **Deviation / mechanism:** database accounts are provisioned and authenticated
  through the standard CloudFoundry brokered-credentials model rather than an
  Oracle-native enterprise directory integration. The DISA check anticipates this
  via its "authenticated by an enterprise-level authentication/access mechanism"
  clause.
- **Compensating control:** the CF/cloud.gov identity and credential model, which is
  itself FedRAMP-authorized and inherited into the customer's ATO.
- **Residual risk:** the equivalence argument depends on the cloud.gov platform
  authorization remaining current; it is not an Oracle-layer control.
- **Status:** **pending ISSO acceptance.**

### D-7 — Access-authorization review satisfied at provision (SV-270500)

- **STIG expectation:** review roles/profiles for appropriateness of access
  permitted and denied per user type (AC-3 / AC-6(10)); DISA offers Oracle Database
  Vault as one mechanism.
- **Deviation / mechanism:** procedural check with no pass/fail SQL predicate. The
  broker provisions reviewed roles/profiles and issues a **single** customer account
  via `cf create-service`; the baseline authorization set is fixed at provision.
  Database Vault is unavailable (see **D-3**).
- **Compensating control:** the reviewed provision-time role/profile set, plus
  documented customer guidance to create least-privilege application users.
- **Residual risk:** **customer-created** users and roles are outside this
  disposition and are the customer's responsibility. Compounded by **D-4** while the
  binding returns a DBA-class master.
- **Status:** **pending ISSO acceptance.**

### D-8 — Nonrepudiation via single-account provisioning (SV-270501)

- **STIG expectation:** individual attribution for shared accounts (AU-10 /
  IA-2(5)).
- **Deviation / mechanism:** the DISA check opens "if there are no shared accounts
  available to more than one user, this is not a finding." The broker provisions a
  single, non-shared customer account, satisfying that clause literally.
- **Compensating control:** single-account provisioning; the supporting
  audit-enabled requirement remains **SQL-verified** via SV-270502 and the
  `audit_trail` disposition — nothing detectable is suppressed here.
- **Residual risk:** the clause holds only while the account is not shared. If a
  customer distributes the credential among people, attribution is lost and the
  premise fails. That is a customer-responsibility control with no platform
  enforcement.
- **Status:** **pending ISSO acceptance.**

### D-9 — This overlay substitutes for Oracle DBSAT (SV-270520)

- **STIG expectation:** apply DOD/STIG configuration guidance; the DISA check
  references running **Oracle DBSAT** (Database Security Assessment Tool).
- **Deviation / mechanism:** DBSAT is **not run**. It requires creating a DBSAT user
  with specific privileges and grants — database-altering, customer-owned setup
  outside platform provisioning scope.
- **Compensating control:** this **InSpec/CINC Auditor overlay** performs automated
  STIG validation for every control subject to automated validation, against the
  DISA Oracle 19c STIG itself rather than DBSAT's own ruleset.
- **Residual risk (assessor will probe this one):** the substitution is
  *self-referential* — the tool asserting compliance is the tool we built. DBSAT and
  this overlay are not feature-equivalent: DBSAT covers findings this overlay does
  not (and vice versa), and no gap analysis between the two has been performed. An
  assessor may reasonably require either a DBSAT run or a documented DBSAT-to-STIG
  coverage comparison.
- **Status:** **pending ISSO acceptance.** Of D-5…D-10 this is the weakest
  equivalence claim and should be raised explicitly rather than assumed.

### D-10 — Master/broker user holds DELETE on the unified audit trail (SV-270510)

- **STIG expectation:** protect the audit store from unauthorized access and
  deletion (AU-9).
- **Deviation:** the RDS master user — which the broker issues to the customer —
  holds RDS-default `SELECT` **and `DELETE`** on `AUDSYS.AUD$UNIFIED`, plus `EXECUTE`
  on `DBMS_AUDIT_MGMT`. So the audited principal can purge its own audit records.
  AWS manages the `AUDSYS` schema on managed RDS, so the tenant **cannot** `REVOKE`
  it. These grants are AWS-provisioned by design — they mirror `RDSADMIN`'s own — and
  exist because there is no SYS/OS access through which audit-trail purge/archive
  (`DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL`, `CREATE_PURGE_JOB`) could otherwise be
  performed. Without them the trail would grow unbounded with no tenant-reachable
  way to manage it.
- **Compensating control:** audit records are off-boxed to a store the in-database
  principal cannot alter — the RDS `audit` log export to **CloudWatch Logs**, with
  platform-enforced retention. The in-database trail is the working copy; the
  authoritative, tamper-resistant copy is off-box. Additionally, the SQL check is
  **not** suppressed: SV-270510 still runs (`verified_by: sql`) and fails for any
  grantee outside the documented allowlist (Oracle built-in audit roles + `RDSADMIN`
  + the broker `DB_USER`), so grant drift is still detected.
- **⚠️ Unresolved dependency — read before accepting.** The off-box argument is only
  as strong as the export actually covering the records in question. On RDS,
  CloudWatch export ships the OS `.aud`/`.xml` files; records written with
  `audit_trail = DB` / `DB,EXTENDED` stay **in-database and are not exportable**, and
  the unified trail (`AUDSYS.AUD$UNIFIED`) is not an OS file either. Getting the
  *unified* trail off-box requires **Database Activity Streams**, which is out of
  scope for this offering. The correct `audit_trail` value and off-box mechanism are
  still being decided in [**overlay #48**](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/48). Until that closes, D-10's compensating
  control is **partially evidenced**: what currently reaches CloudWatch is the
  mandatory/`audit_sys_operations` OS-file records, not the full unified trail.
- **Residual risk:** between purge and export (or for records never exported), a
  privileged customer could remove evidence of their own actions. Mitigated in
  practice because the master credential is intended for provisioning, not
  application runtime (see **D-4** and the least-privilege guidance).
- **Status:** **pending ISSO acceptance, and pending [overlay #48](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/48).** This entry should
  not be signed off until the off-box mechanism for the unified trail is settled.

---

## 3. Controls that are Not Applicable or AWS-Inherited on managed RDS

A substantial set of OS/listener/file-system STIG controls **cannot be applied or
verified** on managed RDS because no party has host/OS access. These are **not
silently passed** — this repo's `control-layers.yml` classifies controls by layer
so the assessment does not report a misleading pass/fail.

As of 2026-09-01 the map pins **62 controls explicitly by `id_pattern`**, plus **13
`text_pattern` rules** and a small set of `default_layer_rules`, against the
baseline's **96** controls. Disposition is still landing in batches — do not treat
any number in this document as authoritative; **`control-layers.yml` is the source
of truth**.

A recurring, load-bearing reason for `not_applicable_rds` deserves stating plainly
for the assessor: several inherited baseline controls assert with host `command()` /
`file()` resources (e.g. `ps -ef | grep tnslsnr`, reading
`$ORACLE_HOME/network/admin/sqlnet.ora`, `grep aide /etc/crontab`). On managed RDS
those execute against the **InSpec runner host, not the database server**, so they
produce a *guaranteed false result* rather than a meaningful verdict. Marking them
N/A prevents a misleading finding; it is not a waiver of the underlying requirement,
which is inherited from the AWS GovCloud authorization.

The layer classifications are:

| Layer (in `control-layers.yml`) | Meaning | ISSO handling |
|---|---|---|
| `aws_inherited` | satisfied by the AWS/RDS platform (host, OS, patching, listener process) | inherit from the AWS GovCloud FedRAMP authorization / SSP inheritance |
| `not_applicable_rds` | cannot apply or verify on managed RDS (no OS/listener/file access) | mark N/A with the layer classification as justification |
| `broker_infra` | broker sets at provision (encryption, private, backups) | evidence = broker config (this repo) |
| `aws_rds_parameter_group` / `aws_rds_option_group` | broker parameter/option group sets it | evidence = `services/rds/baselines/oracle19c/` |
| `sql_hardening` / `sql_assessment_only` | remediated/verified by overlay SQL | evidence = overlay run against a live instance |
| `manual_review` | requires human determination | ISSO/assessor review |
| `compensating_control` | requirement not met as literally specified; met by a documented substitute mechanism | **explicit acceptance required — see §2a (D-5…D-10)** |
| `blocked` | cannot be met on RDS by any mechanism | POA&M candidate (none currently classified this way) |

> **Any `not_applicable_rds` control that an assessor determines is in fact
> required becomes a POA&M candidate.** The classification is a documented
> justification for N/A, not an automatic waiver.

The layer counts and the authoritative per-control mapping are in
`control-layers.yml` in the overlay repo (the single source of truth for control
applicability).

---

## 4. Why SE2 (the root cause of D-1/D-2/D-3)

The edition choice is deliberate and is what forces the EE-feature deviations:

- The plan uses RDS **License Included**, where **AWS holds the Oracle license and
  bundles it into the instance price**. There is therefore **no unlicensed state** —
  cloud.gov never facilitates an unlicensed Oracle database on GSA-operated
  infrastructure.
- On RDS, **License Included is Standard Edition 2 only**; **Enterprise Edition is
  BYOL-only**. The two are mutually exclusive.
- BYOL/EE would only *reallocate* the unlicensed-Oracle liability via customer
  license attestation — it does not remove it — and would introduce a licensing-
  compliance burden onto GSA. The security team chose License Included (→ SE2) to
  eliminate that liability, accepting the EE-feature deviations in §2 as
  compensated.
- **Re-open condition:** if a control is found to *require* an EE-only feature
  (TDE, FGA, Database Vault) with no acceptable compensating control, the edition
  decision must be revisited (EE + BYOL, licensing handled by attestation).

Full rationale: `docs/oracle19c/licensing.md`, `docs/oracle19c/design-notes.md`.

---

## 5. Compensating / hardening controls implemented by the broker

Positive controls the broker enforces at provision (the "compensating" side of the
ledger, mapped to 800-53 and DISA STIG IDs where applicable):

| Control | Implementation | 800-53 / STIG |
|---|---|---|
| **Encryption at rest** | RDS KMS storage encryption, AES-256, always on (`encrypted: true`) | SC-28 (compensates D-1) |
| **Encryption in transit (FIPS)** | SSL option group: TCPS listener **2484**, `SQLNET.SSL_VERSION=1.2`, `SQLNET.CIPHER_SUITE=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `FIPS.SSLFIPS_140=TRUE` | SC-8, SC-8(1), SC-13; DISA **V-270579**, **V-270571** |
| **DB auditing** | `audit_trail=DB,EXTENDED`, `audit_sys_operations=TRUE`, CloudWatch `audit`/`alert`/`listener` exports | AU-2, AU-3, AU-12 (compensates D-2) |
| **Password / auth hardening** | `sec_case_sensitive_logon=TRUE`, `remote_login_passwordfile=NONE` | IA-5, AC-17 |
| **Least-privilege enforcement in DB** | `resource_limit=TRUE`, `sql92_security=TRUE`, + overlay SQL (profiles, account lockout, PUBLIC-grant review) | AC-6, AC-7 |
| **Private-only networking** | no public accessibility (broker rejects `publicly_accessible` for Oracle); private subnet group + security group | SC-7 |
| **Reduced attack surface** | no XML DB HTTP listener, `extproc`, Java VM, or APEX enabled; create-param **allowlist** rejects STIG-weakening / attack-surface overrides on create AND update | CM-7 |
| **FIPS-only handshake** | `FIPS.SSLFIPS_140=TRUE` means a non-FIPS cipher fails the handshake (fail-closed) | SC-13 |
| **Fail-closed identifier validation** | Oracle identifiers validated before any AWS call; reserved words rejected | SI-10 |

Authoritative values: `services/rds/baselines/oracle19c/{parameters,options,log_exports}.yml`.
Full mapping narrative: `docs/oracle19c/hardening-baseline.md`.

### 5a. Known hardening gaps in the at-rest credential path (disclosed)

Two credential-at-rest items are **not weaknesses specific to Oracle** — they
affect the broker's existing Postgres/MySQL/Redis/ES handling too — but are
disclosed here for completeness because they touch the credential model in D-4:

- **Credential-at-rest cipher (SC-13, SC-28(1)) — tracked cloud-gov/aws-broker#554.** The broker
  encrypts stored credentials with AES in **CFB** mode (`helpers/crypto.go`). CFB
  is unauthenticated and **not part of a FIPS 140-3 validated module**. Mitigated
  today by the underlying **RDS-KMS / S3-SSE at-rest encryption** (so credentials
  are never stored in cleartext), but the application-layer cipher should migrate
  to an authenticated AEAD mode (AES-GCM) on a FIPS-validated provider. Requires a
  migration path for existing ciphertext — hence its own tracked work, not a code
  change folded in silently.
- **Plaintext IAM `SecretKey` in the ES restore manifest — tracked cloud-gov/aws-broker#552.** The
  Elasticsearch delete/snapshot path marshals the instance (incl. a long-lived IAM
  `SecretKey`) in plaintext into an `instance_manifest.json` written to the broker's
  **private, SSE-AES256** snapshots bucket. Encrypted at rest and not
  logged/returned, but the plaintext IAM secret should be field-encrypted (as the
  DB `Password` already is). **ES-specific**; the Oracle plan does not carry IAM
  keys, so this does not affect the Oracle credential path — disclosed for the
  broker-wide picture.

---

## 6. Outstanding preconditions before production authorization

The Oracle plans are deployable for dev/test validation. The following MUST be
resolved before any **staging/production** authorization. Each is tracked as a GitHub
issue:

| # | Precondition | Why it gates production |
|---|---|---|
| ~~**cloud-gov/aws-broker#541**~~ | ~~Platform security group must **allow TCPS 2484 and deny plaintext 1521**~~ | **SATISFIED.** [terraform-provision#2351](https://github.com/cloud-gov/terraform-provision/pull/2351) removed the plaintext 1521 ingress rule (merged 2026-08-13; `#2359` fixed the resulting apply oscillation), and cloud-gov/aws-broker#541 closed 2026-08-31. TLS-only (SC-8) is now enforced at the security group. Retained here so the ISSO can see the gate was closed rather than dropped. |
| **cloud-gov/aws-broker#534** | Broker-managed **per-binding least-privilege users** | Resolves deviation **D-4**; returning a DBA-class master per binding is not acceptable for production. |
| **cloud-gov/aws-broker#539** | Apply static (pending-reboot) hardened params on **modify** + reboot | New instances get the full baseline; the modify path must not leave pending-reboot params unapplied. |
| **cloud-gov/aws-broker#540** | Enable RDS **storage autoscaling** (`MaxAllocatedStorage`) | Operational availability (A-family) before customers land. Implemented in **cloud-gov/aws-broker#562** (merged to the Oracle integration branch; autoscaling is **opt-in** per instance via `max_storage`, no plan default). |
| **WS15** (live proof) | **Validate the overlay against a real GovCloud RDS Oracle instance** | All hardening/parameter/option/log support is verified offline + via moto/local only. Compliance **evidence** requires a live run — see `docs/oracle19c/limitations.md`. The overlay profile is committed and runnable (`controls/overlay.rb` + `control-layers.yml`); what is missing is a run against a live brokered instance — `aws-broker` **cloud-gov/aws-broker#558**. |
| **cloud-gov/aws-broker#557** | **Decide + implement how in-database SQL hardening is applied** (see §1 warning) | Today the in-DB STIG controls are not applied automatically at provision. Production requires either an AO/ISSO-accepted "control-plane-hardened + operator-applies-SQL" model, or the dedicated post-provision hardening component from cloud-gov/aws-broker#557. |
| this doc | **ISSO acceptance of deviations D-1…D-4 (feature-absence) and D-5…D-10 (compensating-control)** — and the §1 in-DB-hardening model | The formal risk-acceptance decision this package supports. **D-9 (this overlay substituting for Oracle DBSAT) is the weakest equivalence claim and should be raised explicitly.** |

Related hardening items (not strictly production gates for the Oracle plan, but on
the broker-wide backlog and disclosed in §5a): **cloud-gov/aws-broker#554** (at-rest cipher → AEAD/FIPS),
**cloud-gov/aws-broker#552** (plaintext IAM SecretKey in ES manifest), **cloud-gov/aws-broker#553** (HTTP server graceful
shutdown).

**Where the code lives.** `aws-broker`'s `main` carries the Oracle catalog plans but
not the Oracle provisioning code; that work is on the long-lived integration branch
`feat/oracle-19c-stig-brokered-rds` and has not merged to `main`. An ISSO reading
`main` alone will not see the hardening described in §5. The credential model is
identical to the Postgres/MySQL plans.

---

## 7. Evidence index (where the ISSO/assessor looks)

| Evidence | Location |
|---|---|
| Broker-enforced instance config (encryption, private, baselines) | `aws-broker`: `services/rds/` (`broker.go`, `create_worker.go`, `option_group.go`, `parameter_group.go`) |
| Hardened parameter/option/log values (reviewable) | `aws-broker`: `services/rds/baselines/oracle19c/*.yml` |
| Create-parameter allowlist (STIG-weakening rejection) | `aws-broker`: `services/rds/validate.go` (`validateOracleOptions`) |
| Encryption-in-transit / binding contract | `aws-broker`: `services/rds/credentials.go` |
| Control → layer applicability map (N/A & inherited justification) | this repo: `control-layers.yml` |
| SQL hardening + assessment scripts | this repo: `hardening/sql/` |
| STIG profile (InSpec/Cinc) | this repo: `controls/overlay.rb` (dispositions) + `inspec.yml` (`depends` on the forked DISA baseline) |
| Per-control layer dispositions + rationales | this repo: `control-layers.yml` |
| Platform vs. customer responsibility split | this repo: `docs/RESPONSIBILITY.md` |
| Runner / scan invocation | this repo: `runner/` (`run-validation.sh`, `Dockerfile`) |
| Licensing / edition rationale | `aws-broker`: `docs/oracle19c/licensing.md`, `docs/decisions/ADR-0001-*` |
| Hardening baseline narrative + STIG IDs | `aws-broker`: `docs/oracle19c/hardening-baseline.md` |
| Known limitations & caveats | `aws-broker`: `docs/oracle19c/limitations.md` |
| Operator credential-rotation runbook | `aws-broker`: `ops/oracle19c/credential-rotation.md` |

---

*Prepared for ISSO review. The broker configures the instance; the
`cg-oracle-database-19c-stig-overlay` validates it against a live instance and
produces the STIG assessment evidence. Neither this document nor any local/offline
run constitutes compliance evidence — that requires the live GovCloud proof (WS15).*
