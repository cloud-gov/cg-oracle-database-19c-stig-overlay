# Include ALL Oracle 19c STIG controls from the depended-on baseline and, on a
# platform-only run, skip the CUSTOMER-responsibility controls in-place (they are
# not FAILED by remediation the tenant owns). Rationale, criteria, postures, and
# how to add a control: docs/RESPONSIBILITY.md.
#
# Separately, some inherited controls carry a PLATFORM disposition of
# not_applicable_rds (control-layers.yml): their baseline check targets the OS,
# host, or listener, which the tenant cannot reach on managed RDS. Running such a
# check on RDS produces a MISLEADING failure (e.g. reading a listener.ora that
# does not exist under the tenant's $ORACLE_HOME). For those, the overlay
# OVERRIDES the inherited control in-place and marks it N/A (impact 0.0) with a
# documented rationale, rather than skipping it silently.

skip_customer = input('skip_customer_responsibility_controls') == true

include_controls 'oracle-database-19c-stig-baseline' do
  if skip_customer
    skip_control 'SV-270495'  # SESSIONS_PER_USER — org-defined value; see docs/RESPONSIBILITY.md
    skip_control 'SV-270549'  # PASSWORD_LOCK_TIME UNLIMITED — org-defined ALTER PROFILE; 10_profiles.sql / 11_ora_stig_profile.sql
    skip_control 'SV-270550'  # FAILED_LOGIN_ATTEMPTS <=3 — org-defined ALTER PROFILE; 10_profiles.sql / 11_ora_stig_profile.sql
    skip_control 'SV-270551'  # INACTIVE_ACCOUNT_TIME <=35 — org-defined ALTER PROFILE; 10_profiles.sql / 11_ora_stig_profile.sql
  end

  # --- PLATFORM disposition: not_applicable_rds --------------------------------
  # SV-270496 (DoS mitigation, SC-5/AC-10). The baseline check inspects
  # $ORACLE_HOME/network/admin/listener.ora for a connection RATE_LIMIT. On
  # managed RDS the listener is AWS-managed and unreachable by the tenant (no OS
  # or listener access) — the primary DoS mitigation named by the STIG (listener
  # CONNECTION_RATE_LISTENER / RATE_LIMIT) is inherited from the AWS platform and
  # cannot be applied or verified by SQL. control-layers.yml classifies this
  # listener.ora path as set_by: aws_inherited / verified_by: not_applicable_rds.
  # The STIG's other DoS levers (profile CPU_PER_CALL/IDLE_TIME/LOGICAL_READS,
  # tablespace quotas) are org-defined resource-limit decisions that ride the same
  # customer-responsibility profile-hardening path as SV-270495; they are not the
  # baseline check's assertion and are not re-implemented here. Override the
  # inherited control to N/A so an RDS run is not misled by a missing listener.ora.
  # SV-270512 (CM-5) — logical access restrictions on DBMS configuration/software.
  # The DISA check is purely OS/filesystem: `ls -ld` on the Oracle software
  # install directory (Unix) or the install directory ACLs (Windows), and the fix
  # sets the software-owner account umask. On managed RDS the tenant has no OS or
  # filesystem access — the Oracle Home and its permissions are AWS-managed and
  # unreachable — so neither the check nor the fix is tenant-applicable or
  # SQL-verifiable. The inherited baseline body runs `command('umask')`, which on
  # RDS reflects the InSpec RUNNER's shell, not the database host, producing a
  # meaningless result. control-layers.yml classifies the OS/filesystem path as
  # set_by: aws_inherited / verified_by: not_applicable_rds. Override to N/A.
  control 'SV-270512' do
    impact 0.0
    title 'Oracle Database must support enforcement of logical access ' \
          'restrictions associated with changes to the database management ' \
          'system (DBMS) configuration and to the database itself.'
    desc 'Not Applicable on managed AWS RDS. The baseline check inspects OS ' \
         'filesystem permissions on the Oracle software install directory ' \
         '(`ls -ld [pathname]`) and the fix sets the software-owner account ' \
         'umask — both require host/OS access the tenant does not have on ' \
         'managed RDS. The Oracle Home and its permissions are AWS-managed and ' \
         'unreachable; the inherited `command(\'umask\')` assertion would reflect ' \
         'the InSpec runner host, not the database server, so it is not a valid ' \
         'signal. Access restrictions to the DBMS software are inherited from the ' \
         'AWS platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270512 (logical access restrictions on DBMS config/software) ' \
             'is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check reads OS filesystem ' \
           'permissions on the Oracle software directory and the fix sets the ' \
           'owner-account umask; the host/OS is AWS-managed on RDS with no tenant ' \
           'access, and the inherited umask assertion reflects the runner host, ' \
           'not the DB server. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270515 (CM-5(6)) — OS must limit privileges to change DBMS software in the
  # software libraries. The DISA check is purely OS-level: enumerate accounts with
  # access to the software library via `cat /etc/group | grep dba` and
  # `cat /etc/passwd`. On managed RDS the tenant has no OS access — the software
  # library, /etc/group, and /etc/passwd on the DB host are AWS-managed and
  # unreachable. NOTE: the inherited baseline body substitutes a DIFFERENT check
  # (querying dba_role_privs for DBA-role grantees), which does not assess the
  # STIG's OS software-library permissions at all (see references/HANDOFF.md §6,
  # the SV-270515 needs_fix seed case). Rather than run that mismatched SQL, the
  # overlay overrides to N/A: the actual control target (OS software-library file
  # permissions) is unreachable on RDS and inherited from the AWS platform.
  # DBA-role membership is separately assessed by the account/role controls.
  control 'SV-270515' do
    impact 0.0
    title 'The OS must limit privileges to change the database management ' \
          'system (DBMS) software resident within software libraries ' \
          '(including privileged programs).'
    desc 'Not Applicable on managed AWS RDS. The DISA check enumerates OS ' \
         'accounts with access to the DBMS software library (`cat /etc/group | ' \
         'grep -i dba`, `cat /etc/passwd`) — an OS/host review the tenant cannot ' \
         'perform on managed RDS (no OS access; the software library, ' \
         '/etc/group, and /etc/passwd on the DB host are AWS-managed and ' \
         'unreachable). The inherited baseline body substitutes a mismatched SQL ' \
         'check (DBA-role grantees via dba_role_privs) that does not assess the ' \
         'STIG\'s OS software-library file permissions; DBA-role membership is ' \
         'covered by the dedicated account/role controls. The software-library ' \
         'privilege restriction is inherited from the AWS platform ' \
         '(control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270515 (OS privileges over DBMS software libraries) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check enumerates OS ' \
           'accounts (/etc/group, /etc/passwd) with access to the DBMS software ' \
           'library; the host/OS is AWS-managed on RDS with no tenant access. ' \
           'The inherited body\'s dba_role_privs query does not assess the OS ' \
           'software-library permissions this control targets. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270517 (CM-5(6)) — DBMS software directories/config files must be stored in
  # dedicated directories or DASD pools, separate from the host OS and other
  # applications. The DISA check is purely a filesystem/host review: inspect the
  # DBMS software library directory and its sibling/root directories for non-DBMS
  # software sharing the same disk directory (or, for mainframes, DASD pools). The
  # fix relocates/reinstalls other applications off the DBMS software directory.
  # Both require OS/filesystem access to the DB host. On managed RDS the tenant
  # has no OS access — the Oracle Home, its directory layout, and disk/DASD
  # placement are AWS-managed and unreachable, and no other tenant application
  # shares the RDS host. The inherited baseline body is a manual-review skip (no
  # SQL). control-layers.yml classifies the OS/filesystem path ("$ORACLE_HOME/",
  # etc.) as set_by: aws_inherited / verified_by: not_applicable_rds. Override to
  # N/A so an RDS run reports it honestly rather than as a zero-test pass.
  control 'SV-270517' do
    impact 0.0
    title 'Database software directories, including database management system ' \
          '(DBMS) configuration files, must be stored in dedicated directories, ' \
          'or DASD pools, separate from the host OS and other applications.'
    desc 'Not Applicable on managed AWS RDS. The DISA check is a filesystem/host ' \
         'review — inspect the DBMS software library directory and other ' \
         'directories on the same disk (or DASD pools on mainframes) for non-DBMS ' \
         'software sharing the location — and the fix relocates other ' \
         'applications off that directory. Both require OS/filesystem access to ' \
         'the DB host, which the tenant does not have on managed RDS: the Oracle ' \
         'Home, its directory layout, and disk/DASD placement are AWS-managed and ' \
         'unreachable, and no other tenant application shares the RDS host. ' \
         'Directory isolation of the DBMS software is inherited from the AWS ' \
         'platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270517 (dedicated DBMS software/config directories, CM-5(6)) is ' \
             'Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check inspects the DBMS ' \
           'software library directory and its disk/DASD neighbors for shared ' \
           'non-DBMS software; the host/OS filesystem is AWS-managed on RDS with ' \
           'no tenant access, and no other tenant application shares the host. ' \
           'See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270531 (CM-6 b) — the Oracle Listener must require administration
  # authentication (CAT I). The DISA check is entirely OS/listener-level: it opens
  # "If a listener is not running on the local database host server, this check is
  # not a finding," then enumerates host listener processes (`ps -ef | grep
  # tnslsnr`, Windows TNSListener services) and runs `lsnrctl status` on the host
  # to read the Security value. The fix relies on local OS authentication of the
  # account that started the listener. On managed RDS the listener is AWS-managed
  # and runs on the AWS-controlled host: the tenant has no OS/listener access,
  # cannot run `ps`/`lsnrctl`, and cannot administer the listener at all. The
  # inherited baseline body runs host `command('ps -ef ... tnslsnr')` and
  # `command('lsnrctl status ...')`, which on RDS reflect the InSpec RUNNER's
  # shell (no listener) and produce a misleading empty/failed result.
  # control-layers.yml classifies the tnslsnr/lsnrctl/listener.ora path as set_by:
  # aws_inherited / verified_by: not_applicable_rds. Override to N/A.
  control 'SV-270531' do
    impact 0.0
    title 'The Oracle Listener must be configured to require administration ' \
          'authentication.'
    desc 'Not Applicable on managed AWS RDS. The DISA check is OS/listener-level: ' \
         'enumerate host listener processes (`ps -ef | grep tnslsnr`, Windows ' \
         'TNSListener services) and run `lsnrctl status` on the host to read the ' \
         'Security value; it is explicitly Not a Finding when no listener runs on ' \
         'the local host. The fix relies on local OS authentication of the ' \
         'listener-owner account. On managed RDS the listener is AWS-managed and ' \
         'runs on the AWS-controlled host — the tenant has no OS or listener ' \
         'access and cannot run `ps`/`lsnrctl` or administer the listener. The ' \
         'inherited baseline `command(\'ps -ef ... tnslsnr\')` / `command(\'lsnrctl ' \
         'status\')` assertions reflect the InSpec runner host (no listener), ' \
         'producing a misleading result. Listener administration authentication is ' \
         'inherited from the AWS platform (control-layers.yml: set_by ' \
         'aws_inherited / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270531 (Oracle Listener administration authentication, CM-6 b) ' \
             'is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check enumerates host ' \
           'listener processes and runs `lsnrctl status` on the DB host; the ' \
           'listener is AWS-managed on RDS with no tenant OS/listener access, so ' \
           'the inherited ps/lsnrctl assertions reflect the runner host, not the ' \
           'DB server. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  control 'SV-270496' do
    impact 0.0
    title 'Oracle Database must protect against or limit the effects of ' \
          'organization-defined types of denial-of-service (DoS) attacks.'
    desc 'Not Applicable on managed AWS RDS. The baseline check reads ' \
         '$ORACLE_HOME/network/admin/listener.ora for a connection RATE_LIMIT / ' \
         'CONNECTION_RATE_LISTENER, but on managed RDS the listener is ' \
         'AWS-managed and unreachable by the tenant (no OS/listener access). The ' \
         'listener-level DoS rate limit is inherited from the AWS platform ' \
         '(control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds). The STIG profile/quota DoS levers ' \
         '(CPU_PER_CALL/IDLE_TIME/LOGICAL_READS, tablespace quotas) are ' \
         'org-defined resource limits on the customer-responsibility hardening ' \
         'path (see SV-270495, docs/RESPONSIBILITY.md), not this control\'s ' \
         'listener.ora assertion.'
    tag responsibility: 'platform'
    describe 'SV-270496 (DoS mitigation) is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the listener is AWS-managed on ' \
           'RDS; the listener.ora RATE_LIMIT check is neither tenant-applicable ' \
           'nor SQL-verifiable. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # --- MANUAL disposition: satisfied by documentation / compensating control ---
  # These DISA checks are procedural (system-documentation / organizational
  # policy review), not SQL-verifiable and not platform-unreachable. The overlay
  # overrides them in-place (impact 0.0) and records the manual/compensating
  # disposition so an RDS run reports them honestly rather than as a zero-test
  # pass or a misleading failure. See docs/RESPONSIBILITY.md ("Manual /
  # compensating-control dispositions") and control-layers.yml (manual_review).

  # SV-270498 (AC-16) — security labels on data in storage. Whether data-labeling
  # is required is a system-documentation decision; if no data is classified as
  # sensitive/CUI, or labeling is not required, the STIG check is Not a Finding.
  control 'SV-270498' do
    impact 0.0
    title 'Oracle Database must associate organization-defined types of ' \
          'security labels having organization-defined security label values ' \
          'with information in storage.'
    desc 'Manual disposition. The DISA check is procedural: if no data is ' \
         'identified as sensitive/classified in the system documentation, or ' \
         'security labeling is not required, this is Not a Finding. This ' \
         'determination is an organizational documentation/policy decision that ' \
         'is not SQL-verifiable and is not a managed-RDS platform fact; it is ' \
         'satisfied by documentation (the Cloud.gov SSP data-classification / ' \
         'AC-16 posture) or a compensating control, not by an automated ' \
         'assertion. See docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, associating "organization-defined ' \
             'types of security labels having organization-defined security label ' \
             'values with information in storage", is a manual/documentation ' \
             'determination: if no data is classified as sensitive/CUI or security ' \
             'labeling is not required per the system documentation, this is Not a ' \
             'Finding. It is satisfied by the Cloud.gov SSP data-classification ' \
             'posture (AC-16), not by an automated SQL assertion.' do
      skip 'Manual review: satisfied by system documentation / SSP (AC-16); no ' \
           'SQL assertion is applicable on managed RDS.'
    end
  end

  # SV-270499 (AC-2(1)) — organization-level authentication/account management.
  # PLATFORM responsibility, not customer. Database authentication uses the
  # standard CloudFoundry brokered-credentials model — the enterprise-level
  # authentication/access mechanism the DISA check's "not a finding" clause
  # anticipates. That model is FedRAMP-authorized/certified and is part of the
  # ATO granted to Cloud.gov by the customer's agency; the customer's separate
  # duty (agency-approved authentication TO Cloud.gov) is out of this control's
  # database scope.
  control 'SV-270499' do
    impact 0.0
    title 'Oracle Database must integrate with an organization-level ' \
          'authentication/access mechanism providing account management and ' \
          'automation for all users, groups, roles, and any other principals.'
    desc 'Platform disposition (Not a Finding). Database accounts are provisioned ' \
         'and authenticated through the standard CloudFoundry brokered-credentials ' \
         'model, which is the organization/enterprise-level authentication and ' \
         'account-management mechanism the DISA check\'s "not a finding" clause ' \
         'anticipates. That model is FedRAMP-authorized/certified and is part of ' \
         'the ATO granted to Cloud.gov by the customer\'s agency; it is satisfied ' \
         'by the platform, not by tenant SQL. See docs/RESPONSIBILITY.md and ' \
         'control-layers.yml.'
    tag responsibility: 'platform'
    describe 'The implementation of this control, integration "with an ' \
             'organization-level authentication/access mechanism providing account ' \
             'management and automation for all users, groups, roles, and any other ' \
             'principals", is satisfied by the FedRAMP-authorized CloudFoundry ' \
             'brokered-credentials model that provisions and authenticates database ' \
             'accounts as part of the Cloud.gov ATO.' do
      skip 'Platform disposition: database authentication uses the ' \
           'FedRAMP-authorized CloudFoundry brokered-credentials model (part of ' \
           'the Cloud.gov ATO); no tenant SQL assertion is applicable on managed RDS.'
    end
  end

  # SV-270500 (AC-3/AC-6(10)) — enforce approved authorizations for logical
  # access. PLATFORM responsibility. The DISA check is procedural: review the
  # roles/profiles (or Oracle Database Vault) for appropriateness/completeness of
  # the access permitted and denied each type of user. On brokered Cloud.gov RDS
  # the database is provisioned by the broker with the roles/profiles reviewed and
  # a SINGLE customer user account issued via `cf create-service`; the
  # appropriateness of that baseline authorization set is a platform provisioning
  # fact, satisfied at provision, not a tenant SQL assertion. (If the customer
  # creates additional users/roles, maintaining appropriate authorizations for
  # them becomes the customer's responsibility — see docs/RESPONSIBILITY.md.)
  control 'SV-270500' do
    impact 0.0
    title 'Oracle Database must enforce approved authorizations for logical ' \
          'access to the system in accordance with applicable policy.'
    desc 'Platform disposition (Not a Finding). The DISA check is a procedural ' \
         'review of roles/profiles (or Oracle Database Vault) for the ' \
         'appropriateness and completeness of the access permitted and denied ' \
         'each type of user. On brokered Cloud.gov RDS the database is ' \
         'provisioned by the broker with its roles/profiles reviewed and a single ' \
         'customer user account issued via `cf create-service`; the baseline ' \
         'authorization set is satisfied at provision by the platform, not by a ' \
         'tenant SQL assertion. If the customer creates additional users or roles, ' \
         'maintaining appropriate authorizations for them is the customer\'s ' \
         'responsibility. See docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'platform'
    describe 'The implementation of this control, enforcing "approved ' \
             'authorizations for logical access to the system in accordance with ' \
             'applicable policy", is satisfied at provision: the broker provisions ' \
             'the database with reviewed roles/profiles and issues a single ' \
             'customer user account. Appropriateness of that baseline authorization ' \
             'set is a platform fact; if the customer adds users/roles, their ' \
             'authorization is the customer\'s responsibility.' do
      skip 'Platform disposition: roles/profiles are reviewed and a single ' \
           'customer user is issued at broker provision; no tenant SQL assertion ' \
           'is applicable on managed RDS. Customer-created users/roles are the ' \
           'customer\'s responsibility (docs/RESPONSIBILITY.md).'
    end
  end

  # SV-270501 (AU-10/IA-2(5)) — nonrepudiation for shared accounts. PLATFORM
  # responsibility at provision. The DISA check is procedural, opening with "If
  # there are no shared accounts available to more than one user, this is not a
  # finding." The broker provisions the database with a SINGLE customer user
  # account (not a shared account), so the "no shared accounts" clause is
  # satisfied at provision. The check's supporting audit-enabled SQL (audit_trail
  # != NONE) remains SQL-verified elsewhere (SV-270502 inherited; control-layers
  # audit_trail entry). If the customer creates additional users, maintaining
  # individual attribution/nonrepudiation for them becomes the customer's
  # responsibility (docs/RESPONSIBILITY.md).
  control 'SV-270501' do
    impact 0.0
    title 'Oracle Database must protect against an individual who uses a shared ' \
          'account falsely denying having performed a particular action.'
    desc 'Platform disposition (Not a Finding). The DISA check opens "If there ' \
         'are no shared accounts available to more than one user, this is not a ' \
         'finding." On brokered Cloud.gov RDS the broker provisions the database ' \
         'with a single customer user account issued via `cf create-service` — ' \
         'not a shared account — so this is satisfied at provision by the ' \
         'platform. The check\'s supporting requirement (Oracle auditing enabled, ' \
         'audit_trail != NONE) is SQL-verified elsewhere (SV-270502 inherited; ' \
         'control-layers.yml audit_trail entry). If the customer creates ' \
         'additional users, maintaining individual attribution/nonrepudiation for ' \
         'them is the customer\'s responsibility. See docs/RESPONSIBILITY.md and ' \
         'control-layers.yml.'
    tag responsibility: 'platform'
    describe 'The implementation of this control, protecting against a shared-' \
             'account user "falsely denying having performed a particular action", ' \
             'is satisfied at provision: the broker issues a single customer user ' \
             'account (no shared account), satisfying the DISA check\'s "no shared ' \
             'accounts" not-a-finding clause. Audit enablement is SQL-verified via ' \
             'SV-270502. If the customer adds users, individual attribution for ' \
             'them is the customer\'s responsibility.' do
      skip 'Platform disposition: the broker issues a single customer user ' \
           'account (no shared account) at provision; no tenant SQL assertion is ' \
           'applicable on managed RDS. Customer-created users are the customer\'s ' \
           'responsibility for individual attribution (docs/RESPONSIBILITY.md).'
    end
  end

  # SV-270503 (AU-12 b) — designated personnel can SELECT which auditable events
  # are audited. The DISA check is procedural ("Check DBMS settings and
  # documentation to determine whether designated personnel are able to select
  # which auditable events are being audited"); there is no pass/fail SQL query in
  # the check. In Oracle this capability is inherent — a user with AUDIT SYSTEM /
  # AUDIT ANY (and any user for their own schema) can configure auditing via the
  # AUDIT/CREATE AUDIT POLICY statements. On brokered Cloud.gov RDS the broker
  # issues the customer a privileged account able to manage unified-audit policies
  # (the customer-responsibility audit hardening path, SV-270504 /
  # hardening/sql/30_audit_policies.sql), which is exactly the "designated
  # personnel can select auditable events" capability this control asks for. The
  # determination is a documentation/policy fact, not a tenant SQL assertion, so
  # the overlay records a Manual disposition rather than a zero-test pass.
  control 'SV-270503' do
    impact 0.0
    title 'Oracle Database must allow designated organizational personnel to ' \
          'select which auditable events are to be audited by the database.'
    desc 'Manual disposition. The DISA check is procedural: verify (via DBMS ' \
         'settings and documentation) that designated personnel are able to ' \
         'select which auditable events are audited — there is no pass/fail SQL ' \
         'query. In Oracle this capability is inherent: any user can configure ' \
         'auditing for objects in their own schema, and AUDIT ANY / AUDIT SYSTEM ' \
         'privileges (plus AUDIT_ADMIN for unified auditing) allow designated ' \
         'personnel to select audited events. On brokered Cloud.gov RDS the broker ' \
         'issues the customer a privileged account able to manage unified-audit ' \
         'policies (the customer-responsibility audit path — SV-270504, ' \
         'hardening/sql/30_audit_policies.sql), satisfying this capability. The ' \
         'determination is a documentation/policy fact (audit-management ' \
         'authorization), not a tenant SQL assertion. See docs/RESPONSIBILITY.md ' \
         'and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, allowing "designated ' \
             'organizational personnel to select which auditable events are to be ' \
             'audited by the database", is a manual/documentation determination: ' \
             'Oracle inherently lets AUDIT ANY / AUDIT SYSTEM (and AUDIT_ADMIN for ' \
             'unified auditing) holders select audited events, and the broker ' \
             'issues the customer a privileged account able to manage audit ' \
             'policies. It is satisfied by documentation of that audit-management ' \
             'authorization, not by an automated SQL assertion.' do
      skip 'Manual review: Oracle inherently supports selecting auditable events ' \
           'via AUDIT / CREATE AUDIT POLICY under AUDIT ANY / AUDIT SYSTEM / ' \
           'AUDIT_ADMIN; the broker issues a privileged customer account able to ' \
           'manage audit policies. Satisfied by documentation of audit-management ' \
           'authorization; no SQL assertion is applicable on managed RDS.'
    end
  end

  # SV-270504 (AU-12 c) — generate audit records for the DOD-selected list of
  # auditable events. The generic baseline marks this a Manual Review because the
  # full DOD event set is organization-defined/documentable and has no single
  # portable SQL predicate (see mitre-baseline/controls/SV-270504.rb). On managed
  # AWS RDS the audit-policy posture is SQL-verifiable in two layers:
  #
  #   1. PLATFORM (both postures): RDS for Oracle enables the Oracle-provided
  #      ORA_SECURECONFIG and ORA_LOGON_FAILURES unified-audit policies BY DEFAULT
  #      once the broker's audit_trail parameters are set (RDS parameter group) —
  #      no tenant step. Those cover privilege GRANT, security-config/DDL, most
  #      account administration (CREATE/ALTER/DROP USER), ALTER SYSTEM/DATABASE, and
  #      LOGON. Asserted via the required_audit_policies input in every posture.
  #
  #   2. CUSTOMER (--all posture only): the events the RDS defaults MISS — REVOKE,
  #      CHANGE PASSWORD, LOGOFF, CREATE SPFILE — are covered by
  #      a tenant-owned policy (CG_AUDIT_POLICY) created/enabled by
  #      hardening/sql/30_audit_policies.sql. This is customer-responsibility
  #      remediation, so it is asserted ONLY when skip_customer_responsibility_controls
  #      is false (the --all / post-hardening posture). The site policy name(s) are
  #      org-defined via the customer_audit_policies input; an empty list skips the
  #      second assertion (a site that has not declared its policies is not falsely
  #      failed here — see docs/RESPONSIBILITY.md).
  #
  # Both layers assert the policies are ENABLED (present in
  # AUDIT_UNIFIED_ENABLED_POLICIES). detect-first: this control never enables a
  # policy; remediation is the hardening SQL.
  control 'SV-270504' do
    impact 0.5
    title 'Oracle Database must generate audit records for the DOD-selected list ' \
          'of auditable events, when successfully accessed, added, modified, or ' \
          'deleted, to the extent such information is available.'
    desc 'AWS RDS overlay of the DOD-audit-event-set control. The generic baseline ' \
         'is a Manual Review because the DOD event set is organization-defined and ' \
         'has no single portable SQL predicate. On managed RDS the audit-policy ' \
         'posture is SQL-verifiable in two layers. PLATFORM (both postures): the ' \
         'Oracle-provided unified-audit policies ORA_SECURECONFIG (privilege ' \
         'grants, security configuration and DDL, account administration, ' \
         'parameter changes) and ORA_LOGON_FAILURES (logon events) are enabled BY ' \
         'DEFAULT on RDS for Oracle once the broker\'s audit_trail parameters are ' \
         'set (the RDS parameter group). CUSTOMER (--all posture only): the events ' \
         'the RDS defaults MISS — REVOKE, CHANGE PASSWORD, LOGOFF, CREATE SPFILE ' \
         '— are covered by a tenant-owned policy ' \
         '(CG_AUDIT_POLICY) created and enabled by ' \
         'hardening/sql/30_audit_policies.sql, and are asserted only when ' \
         'customer-responsibility controls are in scope. Both layers assert the ' \
         'policies are ENABLED (present in AUDIT_UNIFIED_ENABLED_POLICIES). The ' \
         'required_audit_policies and customer_audit_policies inputs are ' \
         'org-defined; an empty customer list skips the customer-posture ' \
         'assertion. See docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'platform'
    tag cci: ['CCI-000172']
    tag nist: ['AU-12 c']

    # Inline value: defaults so the control is self-contained. This control lives
    # in the depended-on baseline (via include_controls), whose input namespace
    # does NOT see the overlay inspec.yml defaults; without an inline default the
    # resolver warns and returns nil on a bare run. run-validation.sh still writes
    # both keys into /tmp/inputs.yml so operators can override them centrally.
    required_policies = input('required_audit_policies',
                              value: %w[ORA_SECURECONFIG ORA_LOGON_FAILURES])
    customer_policies = input('customer_audit_policies', value: %w[CG_AUDIT_POLICY])
    sql = oracledb_session(user: input('user'), password: input('password'),
                           host: input('host'), port: input('port'),
                           service: input('service'), sqlplus_bin: input('sqlplus_bin'))

    enabled_policies = sql.query(
      "SELECT DISTINCT policy_name FROM audit_unified_enabled_policies;"
    ).column('policy_name').map(&:upcase)

    # Layer 1 — PLATFORM defaults (asserted in every posture).
    required_policies.each do |policy|
      describe "Platform unified audit policy required for the DOD event set: #{policy}" do
        subject { enabled_policies }
        it 'is enabled (present in AUDIT_UNIFIED_ENABLED_POLICIES)' do
          expect(enabled_policies).to include(policy.upcase)
        end
      end
    end

    # Layer 2 — CUSTOMER-owned policies covering events the RDS defaults miss.
    # Asserted only in the customer/--all posture; skipped (not failed) when the
    # site has not declared any customer_audit_policies.
    unless skip_customer
      if customer_policies.nil? || customer_policies.empty?
        describe 'Customer-responsibility unified audit policies (SV-270504)' do
          skip 'No customer_audit_policies declared; skipping the ' \
               'customer-posture assertion. Set customer_audit_policies (default ' \
               'CG_AUDIT_POLICY) and apply hardening/sql/30_audit_policies.sql. ' \
               'See docs/RESPONSIBILITY.md.'
        end
      else
        customer_policies.each do |policy|
          describe "Customer unified audit policy required for the DOD event set: #{policy}" do
            subject { enabled_policies }
            it 'is enabled (present in AUDIT_UNIFIED_ENABLED_POLICIES)' do
              expect(enabled_policies).to include(policy.upcase)
            end
          end
        end
      end
    end
  end

  # SV-270505 (AU-3(1)) — organization-defined ADDITIONAL, more detailed
  # information in audit records for events identified by type/location/subject.
  # The DISA check is explicitly conditional and procedural: "Review the system
  # documentation to identify additional site-specific information not covered by
  # the default audit options... If there are none, this is not a finding." Only
  # IF the organization has defined additional detailed-audit requirements does the
  # check then compare them against existing Fine-Grained Auditing (FGA) specs. On
  # Cloud.gov RDS no additional site-specific detailed-audit requirement beyond the
  # default unified-audit options is defined in the system documentation, so the
  # DISA "if there are none, this is not a finding" clause is satisfied. This is a
  # documentation/policy determination, not a tenant SQL assertion. NOTE: the
  # inherited baseline body runs an FGA-count SQL check unconditionally, which
  # would FAIL on RDS whenever no FGA policy exists even though the STIG says that
  # is Not a Finding when no additional requirements are defined — a misleading
  # failure. The overlay overrides to Manual so an RDS run reports it honestly.
  control 'SV-270505' do
    impact 0.0
    title 'Oracle Database must include organization-defined additional, more ' \
          'detailed information in the audit records for audit events identified ' \
          'by type, location, or subject.'
    desc 'Manual disposition. The DISA check is conditional and procedural: ' \
         '"Review the system documentation to identify additional site-specific ' \
         'information not covered by the default audit options... If there are ' \
         'none, this is not a finding." Only if additional detailed-audit ' \
         'requirements are defined does it then compare them against existing ' \
         'Fine-Grained Auditing (FGA) specifications. On Cloud.gov RDS no ' \
         'additional site-specific detailed-audit requirement beyond the default ' \
         'unified-audit options is defined in the system documentation, so the ' \
         '"if there are none, this is not a finding" clause is satisfied — a ' \
         'documentation/policy determination, not a tenant SQL assertion. The ' \
         'inherited baseline body runs an unconditional FGA-count query that would ' \
         'FAIL whenever no FGA policy exists, even though the STIG treats that as ' \
         'Not a Finding absent additional requirements; the overlay overrides to ' \
         'Manual to avoid that misleading failure. If the organization later ' \
         'defines additional detailed-audit requirements, deploying/verifying FGA ' \
         'to cover them becomes the customer\'s responsibility. See ' \
         'docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, including "organization-defined ' \
             'additional, more detailed information in the audit records", is a ' \
             'manual/documentation determination: per the DISA check, if no ' \
             'additional site-specific detailed-audit information beyond the ' \
             'default audit options is defined in the system documentation, this ' \
             'is Not a Finding. No such additional requirement is defined for ' \
             'Cloud.gov RDS. If one is later defined, deploying/verifying ' \
             'Fine-Grained Auditing to cover it is the customer\'s responsibility.' do
      skip 'Manual review: per the DISA check, absent any organization-defined ' \
           'additional detailed-audit requirement beyond the default audit ' \
           'options, this is Not a Finding. None is defined for Cloud.gov RDS. ' \
           'Satisfied by system documentation; no SQL assertion is applicable ' \
           '(the inherited unconditional FGA-count query would mislead on RDS).'
    end
  end

  # SV-270506 (AU-4) — allocate audit record STORAGE CAPACITY per org-defined
  # requirements. PLATFORM disposition. The DISA check assesses where the audit
  # store lives (AUD$ tablespace not SYSTEM; AUDSYS tablespace not USERS),
  # audit_file_dest space, and whether the DBMS has ever run out of audit-log
  # space — all storage-capacity facts that on managed RDS are owned by AWS/the
  # broker, not the tenant. On RDS: (1) DB storage is broker-provisioned and RDS
  # storage autoscaling grows capacity automatically; (2) AUDSYS/AUD$ tablespace
  # placement is managed under SYS/AUDSYS, which AWS controls (the tenant cannot
  # run dbms_audit_mgmt.move_dbaudit_tables against AWS-managed AUDSYS, and the
  # `audit_file_dest` OS path is not tenant-reachable). The remediation
  # (move audit tablespace, size disk) requires SYS/OS access the tenant does not
  # have. control-layers.yml classifies this as set_by aws_inherited /
  # verified_by not_applicable_rds. Override to N/A so an RDS run is not misled.
  control 'SV-270506' do
    impact 0.0
    title 'Oracle Database must allocate audit record storage capacity in ' \
          'accordance with organization-defined audit record storage ' \
          'requirements.'
    desc 'Not Applicable on managed AWS RDS. The DISA check assesses ' \
         'audit-storage capacity facts — the AUD$/AUDSYS tablespace placement ' \
         '(must not be SYSTEM/USERS), the `audit_file_dest` OS location and its ' \
         'free space, and whether the DBMS has ever run out of audit-log space. ' \
         'On managed RDS these are AWS/broker-owned: DB storage is ' \
         'broker-provisioned with RDS storage autoscaling, and the AUDSYS/AUD$ ' \
         'tablespaces plus `audit_file_dest` live under SYS/AUDSYS and the DB ' \
         'host OS, which AWS manages and the tenant cannot reach. The DISA fix ' \
         '(`dbms_audit_mgmt.move_dbaudit_tables`, resize disk) needs SYS/OS ' \
         'access the tenant does not have on RDS. Audit-storage capacity is ' \
         'inherited from the AWS platform (control-layers.yml: set_by ' \
         'aws_inherited / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270506 (audit record storage capacity, AU-4) is Not Applicable ' \
             'on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): audit-store tablespace ' \
           'placement, audit_file_dest, and disk capacity are AWS/broker-managed ' \
           'on RDS (broker-provisioned storage + RDS autoscaling; AUDSYS is ' \
           'AWS-controlled). The DISA fix (move_dbaudit_tables / resize) needs ' \
           'SYS/OS access the tenant lacks. See control-layers.yml and ' \
           'docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270507 (AU-4(1)) — OFF-LOAD audit data to a separate/centralized log
  # management facility, continuous/near-real-time when networked. PLATFORM
  # disposition. The DISA check is procedural: "Review the system documentation
  # for a description of how audit records are off-loaded... If there is no
  # centralized audit log management system... this is a finding." On managed RDS
  # audit off-loading is an AWS platform capability: RDS for Oracle publishes the
  # audit trail to Amazon CloudWatch Logs (continuous, near-real-time) via the DB
  # instance's log exports — a broker/platform integration, not a tenant SQL
  # setting, and not something the tenant configures inside the database. The
  # centralized log-management facility (CloudWatch Logs, and downstream Cloud.gov
  # logging) is part of the platform's AU-4(1)/AU-6 posture. Not SQL-verifiable by
  # the tenant and not a database-level fact; satisfied by the AWS/Cloud.gov
  # platform. Override to N/A (platform).
  control 'SV-270507' do
    impact 0.0
    title 'Oracle Database must off-load audit data to a separate log management ' \
          'facility; this must be continuous and in near-real-time for systems ' \
          'with a network connection to the storage facility, and weekly or more ' \
          'often for stand-alone systems.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'is procedural — review the system documentation for how audit records ' \
         'are off-loaded to a centralized log management system. On managed RDS ' \
         'audit off-loading is an AWS platform capability: RDS for Oracle ' \
         'publishes the audit trail to Amazon CloudWatch Logs continuously and in ' \
         'near-real-time via the DB instance log exports, feeding the Cloud.gov ' \
         'centralized logging posture (AU-4(1)/AU-6). This is a broker/platform ' \
         'integration configured outside the database, not a tenant SQL setting, ' \
         'and it is not SQL-verifiable by the tenant. Audit off-loading is ' \
         'inherited from the AWS/Cloud.gov platform (control-layers.yml: set_by ' \
         'aws_inherited / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270507 (off-load audit data to a central log facility, AU-4(1)) ' \
             'is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): RDS for Oracle off-loads the ' \
           'audit trail to Amazon CloudWatch Logs (continuous, near-real-time) ' \
           'via DB instance log exports — an AWS/platform integration configured ' \
           'outside the database, feeding the Cloud.gov centralized logging ' \
           'posture. Not a tenant SQL setting and not SQL-verifiable. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end
end
