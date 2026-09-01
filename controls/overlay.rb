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
    # Only skip customer-responsibility controls when they have a SQL-assessed
    # element that would produce misleading findings in a platform-provider run.
    # Baseline controls already skipped for manual review do not belong here.
    skip_control 'SV-270495'  # SESSIONS_PER_USER — org-defined value; see docs/RESPONSIBILITY.md
    skip_control 'SV-270549'  # PASSWORD_LOCK_TIME UNLIMITED — org-defined ALTER PROFILE; 10_profiles.sql / 11_ora_stig_profile.sql
    skip_control 'SV-270550'  # FAILED_LOGIN_ATTEMPTS <=3 — org-defined ALTER PROFILE; 10_profiles.sql / 11_ora_stig_profile.sql
    skip_control 'SV-270551'  # INACTIVE_ACCOUNT_TIME <=35 — org-defined ALTER PROFILE; 10_profiles.sql / 11_ora_stig_profile.sql
    # SV-270547 (auto-remove temp accounts after 72h) is NOT added here. Like its
    # sibling SV-270546, its baseline body is a pure manual-review stub with no SQL
    # assertion, so it produces no misleading finding in a platform-provider run —
    # the gate's own criterion (above) excludes manual-review-only controls. It
    # remains a baseline manual-review skip; the customer disposition is documented
    # in control-layers.yml / docs/RESPONSIBILITY.md and remediated by the sample
    # hardening/sql/60_temporary_users.sql (TEMPORARY_USERS profile + 72h lock job).
    skip_control 'SV-270561'  # PASSWORD_VERIFY_FUNCTION — org-defined DoD-complexity function; 12_password_verify_function.sql / ORA_STIG_PROFILE
    skip_control 'SV-270563'  # PASSWORD_LIFE_TIME<=60 / GRACE_TIME not UNLIMITED — org-defined ALTER PROFILE; 10_profiles.sql / 11_ora_stig_profile.sql
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

  # SV-275999 (CM-6 b) — a minimum of three Oracle control files must exist, each
  # stored on a SEPARATE physical and logical device. The count (>=3) is
  # SQL-visible via SELECT name FROM v$controlfile, but the STIG's actual
  # requirement — that each control file resides on a separate physical/logical
  # (RAID 1+0) device — is a STORAGE-TOPOLOGY fact the DISA check itself directs a
  # reviewer to confirm with "the storage administrator, system administrator, or
  # database administrator," noting file paths alone do not prove device
  # separation. On managed RDS the tenant has no visibility into or control over
  # the underlying storage: control-file placement, multiplexing, and the physical/
  # logical device layout are AWS-managed (Oracle-Managed Files on RDS-provisioned,
  # EBS-backed storage with AWS-side redundancy). The v$controlfile paths on RDS
  # point into the RDS-managed filesystem and cannot be mapped by the tenant to
  # distinct physical/logical devices, so the control's real assertion is neither
  # tenant-settable nor tenant-verifiable — control-file redundancy is inherited
  # from the AWS platform. Override the inherited pending-skip to N/A (impact 0.0)
  # so an RDS run reports it honestly rather than as a zero-test pass or a
  # count-only check that cannot see the device-separation requirement.
  control 'SV-275999' do
    impact 0.0
    title 'A minimum of three Oracle Control Files must be created and each ' \
          'stored on a separate physical and logical device.'
    desc 'Not Applicable on managed AWS RDS. The DISA check lists control files ' \
         '(SELECT name FROM v$controlfile) but its actual requirement — three or ' \
         'more control files each on a SEPARATE physical and logical device ' \
         '(RAID 1+0) — is a storage-topology determination the check itself ' \
         'directs a reviewer to confirm with the storage/system/database ' \
         'administrator, noting file paths do not prove device separation. On ' \
         'managed RDS the tenant has no visibility into or control over the ' \
         'underlying storage: control-file count, multiplexing, and physical/' \
         'logical device placement are AWS-managed (Oracle-Managed Files on ' \
         'RDS-provisioned storage with AWS-side redundancy), and the ' \
         'v$controlfile paths cannot be mapped by the tenant to distinct ' \
         'devices. Control-file redundancy and separation are inherited from the ' \
         'AWS platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-275999 (three+ control files on separate devices, CM-6 b) is ' \
             'Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): control-file count, ' \
           'multiplexing, and physical/logical device separation are AWS-managed ' \
           'on RDS (Oracle-Managed Files on RDS-provisioned storage); the tenant ' \
           'cannot map v$controlfile paths to distinct devices or alter ' \
           'placement. See control-layers.yml and docs/RESPONSIBILITY.md.'
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

  # SV-270553 (CM-7 a) — unused DBMS components/software/objects must be removed.
  # The DISA check runs a fixed query listing installed components, EXCLUDING a
  # hard-coded set of expected core comp_ids and OPTION OFF rows:
  #   SELECT comp_id, comp_name, version, status FROM dba_registry
  #   WHERE comp_id NOT IN ('CATJAVA','CATALOG','CATPROC','SDO','DV','XDB')
  #   AND status <> 'OPTION OFF';
  # then directs the reviewer: "If unused components are installed and are not
  # documented and authorized, this is a finding." The pass/fail therefore depends
  # on an ORGANIZATION-DEFINED authorized-components list — there is no fixed SQL
  # predicate, which is why the generic baseline is a pending-assessment skip.
  # On managed RDS the component set is NOT tenant-removable: DBCA component
  # selection happens at database CREATION, which AWS owns; a brokered RDS instance
  # ships Oracle Text (CONTEXT) installed and VALID, and the tenant cannot deselect
  # it. So on RDS the question reduces to: are the STILL-installed components on the
  # org-authorized list? The overlay OVERRIDES the baseline pending-skip with a
  # concrete AWS-RDS SQL assertion (SV-270504 overlay-sql pattern): run the DISA
  # query and FAIL on any returned component whose comp_id is NOT in the org-defined
  # authorized_components allowlist. CONTEXT (Oracle Text) is the default allowlist
  # member — it is an RDS default-installed component, documented and authorized
  # here. detect-first: this control never removes a component (removal is not
  # possible on RDS); it flags any unauthorized/undocumented component for review.
  control 'SV-270553' do
    impact 0.5
    title 'Unused database components, database management system (DBMS) ' \
          'software, and database objects must be removed.'
    desc 'AWS RDS overlay of the unused-components control. The DISA check lists ' \
         'installed components (dba_registry, excluding the core comp_ids and ' \
         'OPTION OFF rows) and is a finding only if an installed component is ' \
         'unused and NOT documented/authorized — an organization-defined ' \
         'determination with no fixed SQL predicate (hence the generic baseline ' \
         'pending-skip). On managed RDS the component set is fixed at ' \
         'database creation by AWS and is not tenant-removable (a brokered ' \
         'instance ships Oracle Text / CONTEXT installed and VALID), so the ' \
         'question reduces to whether the still-installed components are ' \
         'org-authorized. The overlay asserts every component returned by the ' \
         'DISA query is present in the org-defined authorized_components ' \
         'allowlist (default: CONTEXT, the RDS default-installed Oracle Text ' \
         'component, documented and authorized here). Any component outside the ' \
         'allowlist is a finding for review. Detect-first: removal is not ' \
         'possible on RDS. See docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    tag cci: ['CCI-000381']
    tag nist: ['CM-7 a']

    # Inline value: this control lives in the depended-on baseline (via
    # include_controls), whose input namespace does NOT see the overlay inspec.yml
    # defaults; without an inline default the resolver returns nil on a bare run.
    # run-validation.sh also writes the key into /tmp/inputs.yml so operators can
    # override the authorized-components list centrally.
    authorized = input('authorized_components', value: %w[CONTEXT]).map(&:upcase)
    sql = oracledb_session(user: input('user'), password: input('password'),
                           host: input('host'), port: input('port'),
                           service: input('service'), sqlplus_bin: input('sqlplus_bin'))

    installed = sql.query(
      "SELECT comp_id FROM dba_registry " \
      "WHERE comp_id NOT IN ('CATJAVA','CATALOG','CATPROC','SDO','DV','XDB') " \
      "AND status <> 'OPTION OFF';"
    ).column('comp_id').map(&:upcase)

    unauthorized = installed - authorized

    describe 'Installed DBMS components not on the org-defined ' \
             'authorized_components allowlist (dba_registry)' do
      subject { unauthorized }
      it 'is empty (every installed component is documented and authorized)' do
        expect(unauthorized).to be_empty
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

  # SV-270562 (IA-5(1)(a/d)) — procedures for establishing TEMPORARY PASSWORDS
  # that meet DOD requirements for new accounts must be defined, documented, and
  # implemented. MANUAL disposition. The DISA check is procedural: it opens "If
  # all user accounts are authenticated by the OS or an enterprise-level
  # authentication/access mechanism, and not by Oracle, this is not a finding,"
  # and otherwise directs the reviewer to "review procedures and implementation
  # evidence for creation of temporary passwords" — there is no pass/fail SQL
  # predicate (the temporary-password issuance procedure is an organizational
  # process, not a queryable database setting). The inherited baseline is not
  # SQL-based (baseline_status: not_applicable — a manual-review stub skip).
  # Satisfied by the Cloud.gov account-provisioning process
  # and SSP (IA-5): database credentials are issued through the FedRAMP-authorized
  # CloudFoundry brokered-credentials model (the enterprise-level mechanism the
  # check's "not a finding" clause anticipates), and any Oracle-managed temporary
  # credential is governed by documented procedures. The overlay overrides the
  # inherited control in-place so it reports once, honestly, as a Manual
  # disposition rather than a zero-test pass. See docs/RESPONSIBILITY.md and
  # control-layers.yml.
  control 'SV-270562' do
    impact 0.0
    title 'Procedures for establishing temporary passwords that meet DOD ' \
          'password requirements for new accounts must be defined, documented, ' \
          'and implemented.'
    desc 'Manual disposition. The DISA check is procedural: "If all user ' \
         'accounts are authenticated by the OS or an enterprise-level ' \
         'authentication/access mechanism, and not by Oracle, this is not a ' \
         'finding"; otherwise review procedures and implementation evidence for ' \
         'creation of temporary passwords. There is no pass/fail SQL predicate — ' \
         'temporary-password issuance is an organizational process, not a ' \
         'queryable database setting. Database credentials on Cloud.gov RDS are ' \
         'issued through the FedRAMP-authorized CloudFoundry brokered-credentials ' \
         'model (the enterprise-level mechanism the check anticipates), and any ' \
         'Oracle-managed temporary credential is governed by documented ' \
         'procedures satisfying DOD length/complexity requirements. Satisfied by ' \
         'system documentation / the Cloud.gov SSP (IA-5); no tenant SQL ' \
         'assertion applies. The inherited baseline is not SQL-based ' \
         '(a manual-review stub skip). See ' \
         'docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'Procedures for establishing DOD-compliant temporary passwords for ' \
             'new accounts are a manual/documentation determination: database ' \
             'credentials are issued through the Cloud.gov brokered-credentials ' \
             'model and any Oracle-managed temporary credential is governed by ' \
             'documented procedures (Cloud.gov SSP, IA-5). No SQL assertion ' \
             'applies.' do
      skip 'Manual review: temporary-password issuance is an organizational ' \
           'process, not a queryable database setting. Satisfied by system ' \
           'documentation / the Cloud.gov SSP (IA-5); credentials are issued via ' \
           'the FedRAMP-authorized brokered-credentials model.'
    end
  end

  # SV-270564 (IA-5(1)(c), HIGH) — for password-based authentication, store
  # passwords using an approved SALTED key derivation function, preferably a keyed
  # hash. MANUAL disposition. The DISA check is a procedural review: enumerate
  # DBMS objects, configuration files, associated scripts, applications, and
  # environment files/settings, and confirm none store passwords in clear text or
  # with reversible encryption, and that any external password store (Oracle
  # Wallet) is encrypted. Oracle Database itself stores password verifiers as
  # one-way salted hashes by design (SHA-2/SHA-512 verifiers on 19c), so the
  # database-native portion is inherently satisfied; the residual is a
  # documentation review of scripts/config/external stores for embedded
  # plaintext/reversible credentials, which is not a pass/fail SQL predicate. The
  # inherited baseline is not SQL-based (baseline_status: not_applicable — a
  # manual-review stub skip). On Cloud.gov RDS the tenant
  # does not embed credentials in database objects or host config, and any
  # external password handling rides the broker credential model; satisfied by
  # system documentation / the Cloud.gov SSP (IA-5). The overlay overrides the
  # inherited control in-place so it reports once as a Manual disposition rather
  # than a zero-test pass. See docs/RESPONSIBILITY.md and control-layers.yml.
  control 'SV-270564' do
    impact 0.0
    title 'Oracle Database must, for password-based authentication, store ' \
          'passwords using an approved salted key derivation function, ' \
          'preferably using a keyed hash.'
    desc 'Manual disposition. The DISA check is a procedural review of DBMS ' \
         'objects, configuration files, scripts, applications, and environment ' \
         'files/settings to confirm no passwords are stored in clear text or ' \
         'with reversible encryption, and that any external password store ' \
         '(Oracle Wallet) is encrypted — there is no pass/fail SQL predicate. ' \
         'Oracle Database stores its password verifiers as one-way salted hashes ' \
         'by design, so the database-native portion is inherently satisfied; the ' \
         'residual is a documentation review of scripts/config/external stores ' \
         'for embedded plaintext or reversibly-encrypted credentials. On ' \
         'Cloud.gov RDS the tenant does not embed credentials in database ' \
         'objects or host configuration, and credential handling rides the ' \
         'FedRAMP-authorized broker credential model. Satisfied by system ' \
         'documentation / the Cloud.gov SSP (IA-5); no tenant SQL assertion ' \
         'applies. The inherited baseline is not SQL-based (a manual-review ' \
         'stub skip). See ' \
         'docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'Approved salted hashing of stored passwords is a ' \
             'manual/documentation determination: Oracle stores password ' \
             'verifiers as one-way salted hashes by design, and confirming no ' \
             'clear-text/reversible passwords are embedded in scripts, config, ' \
             'or an external store is a documentation review (Cloud.gov SSP, ' \
             'IA-5). No SQL assertion applies.' do
      skip 'Manual review: Oracle stores password verifiers as one-way salted ' \
           'hashes by design; confirming no plaintext/reversible credentials are ' \
           'embedded in objects/scripts/config/external stores is a ' \
           'documentation review. Satisfied by system documentation / the ' \
           'Cloud.gov SSP (IA-5).'
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

  # SV-270508 (AU-5(1)) — warning at 75 percent of allocated audit-log storage.
  # PLATFORM disposition. The DISA check is procedural: review OS or third-party
  # logging application settings for a capacity warning. On managed RDS, local
  # audit storage and the OS-level alerting surface are AWS-managed, and the
  # centralized audit-log path is the RDS log-export / CloudWatch Logs integration
  # documented for SV-270507. Capacity monitoring and alerting for that managed log
  # path are Cloud.gov/AWS operational controls, not tenant SQL. Override to N/A
  # (platform) so the inherited manual-review skip is reported as a platform
  # disposition.
  control 'SV-270508' do
    impact 0.0
    title 'The Oracle Database, or the logging or alerting mechanism the ' \
          'application uses, must provide a warning when allocated audit record ' \
          'storage volume record storage volume reaches 75 percent of maximum ' \
          'audit record storage capacity.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'is procedural: review OS or third-party logging application settings to ' \
         'determine whether support personnel are warned when DBMS audit-log ' \
         'storage reaches 75 percent of maximum capacity. On managed RDS, local ' \
         'audit storage and OS-level alerting are AWS-managed, and audit records ' \
         'are off-loaded through the RDS log-export / CloudWatch Logs integration ' \
         'described for SV-270507. Capacity monitoring and alerting for that ' \
         'managed log path are inherited from the AWS/Cloud.gov platform, not ' \
         'tenant SQL (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270508 (75 percent audit-log capacity warning, AU-5(1)) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): audit-log storage capacity ' \
           'warning is an AWS/Cloud.gov platform logging and monitoring control ' \
           'for the RDS/CloudWatch Logs path, not a tenant SQL setting. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270509 (AU-5(2)) — real-time alert when auditing fails. PLATFORM
  # disposition. The DISA check is procedural: review Oracle, OS, or third-party
  # logging settings for alert delivery. On managed RDS, audit collection and log
  # export are broker/AWS platform integrations outside the tenant database, and
  # operational alerting on those pipeline failures is handled by the Cloud.gov/AWS
  # monitoring posture. There is no portable tenant SQL assertion that proves the
  # external alerting path. Override to N/A (platform).
  control 'SV-270509' do
    impact 0.0
    title 'Oracle Database must provide an immediate real-time alert to ' \
          'appropriate support staff of all audit log failures.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'is procedural: review Oracle Database, OS, or third-party logging ' \
         'software settings to determine whether real-time alerts are sent when ' \
         'auditing fails. On managed RDS, audit collection and log export are ' \
         'broker/AWS platform integrations outside tenant database control, and ' \
         'operational alerting for failures in that logging path is inherited from ' \
         'the AWS/Cloud.gov monitoring posture. There is no tenant SQL assertion ' \
         'that can prove the external alert delivery path (control-layers.yml: ' \
         'set_by aws_inherited / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270509 (real-time audit-failure alert, AU-5(2)) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): real-time audit-failure alerting ' \
           'is an AWS/Cloud.gov platform monitoring control around the managed ' \
           'audit/log-export path, not a tenant SQL setting. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270511 (AU-9 a/b/c) — protect audit tools from unauthorized access,
  # modification, or deletion. PLATFORM disposition. The DISA check is a review of
  # permissions on the tools used to view or modify audit data, including OS,
  # vendor, open-source, and DBMS tooling. For brokered RDS, the audit-log viewing
  # and manipulation tooling is the managed AWS/Cloud.gov logging stack (RDS log
  # exports, CloudWatch Logs, and platform IAM/operational controls) plus
  # AWS-managed host/Oracle tooling that tenants cannot access. Protection of those
  # tools is inherited from the AWS/Cloud.gov platform; customer application-level
  # tools, if created, are outside the broker baseline. Override to N/A (platform).
  control 'SV-270511' do
    impact 0.0
    title 'The system must protect audit tools from unauthorized access, ' \
          'modification, or deletion.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'reviews access permissions to tools used to view or modify audit log ' \
         'data, including the DBMS itself and external audit tools. On brokered ' \
         'RDS, the audit-log tooling for the platform path is the managed ' \
         'AWS/Cloud.gov logging stack (RDS log exports, CloudWatch Logs, and ' \
         'platform IAM/operational controls) plus AWS-managed host/Oracle tooling ' \
         'that tenants cannot access. Protection from unauthorized access, ' \
         'modification, or deletion of those tools is inherited from the ' \
         'AWS/Cloud.gov platform; any customer-created application audit tooling ' \
         'is outside the broker baseline (control-layers.yml: set_by aws_inherited ' \
         '/ verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270511 (protect audit tools, AU-9 a/b/c) is Not Applicable on ' \
             'managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): platform audit tooling is ' \
           'protected by AWS/Cloud.gov logging, IAM, and operational controls; ' \
           'tenants cannot access AWS-managed host/Oracle audit tooling. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270513 (SA-22 a) — Oracle Database products must be vendor-supported.
  # PLATFORM disposition. The DISA check combines documentation review, DBA
  # interview, SQL version identification, and verification against the Oracle
  # support lifecycle. For brokered RDS, customers select from AWS-exposed Oracle
  # engine versions and AWS has policies/procedures for RDS Oracle support,
  # deprecation, patching, and required upgrade paths; unsupported engine versions
  # are not a tenant-remediated SQL condition. Override to N/A (platform).
  control 'SV-270513' do
    impact 0.0
    title 'Oracle Database products must be a version supported by the vendor.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'requires reviewing system documentation, identifying database software ' \
         'components and versions (including SELECT version FROM v$instance), and ' \
         'verifying vendor support against Oracle\'s release schedule. For ' \
         'brokered RDS, customers run AWS-provided Oracle engine versions; AWS has ' \
         'policies and procedures for RDS for Oracle support, deprecation, patching, ' \
         'and required upgrade paths to ensure customers are running supported ' \
         'versions. Unsupported engine selection is not a tenant SQL-remediated ' \
         'condition in the database. Vendor-support lifecycle management is ' \
         'inherited from the AWS/Cloud.gov platform (control-layers.yml: set_by ' \
         'aws_inherited / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270513 (vendor-supported Oracle version, SA-22 a) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): RDS Oracle engine-version support, ' \
           'deprecation, patching, and required upgrade paths are governed by AWS ' \
           'policies/procedures and Cloud.gov platform operation, not tenant SQL. ' \
           'See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270514 (CM-5(6)) — monitor database software, applications, and
  # configuration files for unauthorized changes. PLATFORM disposition. The DISA
  # check reviews monitoring procedures and implementation evidence for software
  # libraries, related applications, and configuration files; the inherited baseline
  # tries to inspect AIDE cron configuration on the runner host. On managed RDS the
  # Oracle software libraries and configuration files live on AWS-managed hosts, so
  # file integrity/change monitoring is inherited from AWS/Cloud.gov operational
  # controls rather than tenant OS access or SQL. Override to N/A (platform).
  control 'SV-270514' do
    impact 0.0
    title 'Database software, applications, and configuration files must be ' \
          'monitored to discover unauthorized changes.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'reviews monitoring procedures and implementation evidence for changes to ' \
         'DBMS software libraries, related applications, and configuration files. ' \
         'The inherited baseline checks AIDE cron configuration on the runner host, ' \
         'which is not evidence about the RDS database host. On managed RDS, Oracle ' \
         'software libraries and DBMS configuration files are on AWS-managed hosts ' \
         'that tenants cannot access; unauthorized-change monitoring for those ' \
         'platform components is inherited from AWS/Cloud.gov operational controls, ' \
         'not tenant SQL (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270514 (monitor DBMS software/configuration changes, CM-5(6)) is ' \
             'Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): DBMS software/configuration file ' \
           'monitoring is inherited from AWS/Cloud.gov host and operational ' \
           'controls; the inherited AIDE cron check reflects the runner host, not ' \
           'the RDS DB host. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270516 (CM-5(6)) — restrict use of the Oracle software installation
  # account. PLATFORM disposition. The DISA check is procedural: review procedures
  # for controlling use of the DBMS software installation account. On managed RDS
  # the Oracle software owner / installation account and SYSDBA-equivalent host
  # access are AWS-managed and unavailable to tenants; the broker-created database
  # user is not the software installation account. Access restriction for that
  # account is inherited from AWS/Cloud.gov platform controls. Override to N/A.
  control 'SV-270516' do
    impact 0.0
    title 'The Oracle Database software installation account must be restricted to ' \
          'authorized users.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'reviews procedures for controlling and granting access to the DBMS ' \
         'software installation account, which Oracle equates with host-level ' \
         'SYSDBA-capable installation ownership. On managed RDS, the Oracle ' \
         'software owner / installation account and SYSDBA-equivalent host access ' \
         'are AWS-managed and unavailable to tenants; the broker-created database ' \
         'user is not the software installation account. Restricting use of the ' \
         'installation account is inherited from AWS/Cloud.gov platform controls, ' \
         'not tenant SQL (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270516 (restrict Oracle software installation account, CM-5(6)) ' \
             'is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the Oracle software installation ' \
           'account and host-level SYSDBA access are AWS-managed on RDS with no ' \
           'tenant access; the broker user is not that account. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270537 (CM-6 b) — use of the Oracle Database installation account must be
  # logged. PLATFORM disposition. The DISA check is procedural/host-oriented:
  # review documented monitoring procedures for the DBMS software installation
  # account and include host audit logs/accountability for whoever accessed that
  # account. On managed RDS the Oracle software installation account and host audit
  # logs are AWS-managed and unavailable to tenants; the broker-created database
  # user is not the software installation account. Logging/accountability for use
  # of the installation account is inherited from AWS/Cloud.gov platform controls.
  control 'SV-270537' do
    impact 0.0
    title 'Use of the Oracle Database installation account must be logged.'
    desc 'Not Applicable on managed AWS RDS (platform-satisfied). The DISA check ' \
         'reviews documented procedures and host audit logs for monitoring use of ' \
         'the DBMS software installation account. On managed RDS, the Oracle ' \
         'software installation account and host audit logs are AWS-managed and ' \
         'unavailable to tenants; the broker-created database user is not the ' \
         'software installation account. Logging/accountability for that host-level ' \
         'account is inherited from AWS/Cloud.gov platform controls, not tenant SQL ' \
         '(control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270537 (log Oracle software installation account use, CM-6 b) is ' \
             'Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the Oracle software installation ' \
           'account and host audit logs are AWS-managed on RDS with no tenant ' \
           'access; the broker user is not that account. See control-layers.yml ' \
           'and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270538 (CM-6 b) — database data files, transaction logs, and audit files
  # must live in dedicated directories/partitions. PLATFORM disposition. The DISA
  # check reviews host disk/directory placement and separation of database data,
  # transaction logs, audit files, and application/software files. On managed RDS
  # that storage layout is AWS-managed (Oracle-Managed Files on RDS-provisioned
  # storage); tenants cannot inspect or change host directories/partitions, and no
  # tenant application shares the RDS host filesystem. Directory/partition
  # separation is inherited from the AWS platform. Override to N/A.
  control 'SV-270538' do
    impact 0.0
    title 'The Oracle Database data files, transaction logs and audit files must ' \
          'be stored in dedicated directories or disk partitions separate from ' \
          'software or other application files.'
    desc 'Not Applicable on managed AWS RDS. The DISA check reviews host ' \
         'disk/directory placement for database data files, transaction logs, audit ' \
         'files, and application/software files. On managed RDS that filesystem and ' \
         'storage layout is AWS-managed (Oracle-Managed Files on RDS-provisioned ' \
         'storage); tenants cannot inspect or change host directories/partitions, ' \
         'and no tenant application shares the RDS host filesystem. Separation of ' \
         'database files from software/application files is inherited from the AWS ' \
         'platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270538 (separate data/log/audit directories, CM-6 b) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): database data/log/audit file ' \
           'placement is on AWS-managed RDS storage with no tenant host/filesystem ' \
           'access, and no tenant application shares the host filesystem. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270539 (CM-6 b) — network access to the database must be restricted to
  # authorized personnel. The DISA check inspects network-layer artifacts the
  # tenant cannot reach on managed RDS: the listener SQLNET.ORA
  # (tcp.validnode_checking / tcp.invited_nodes) in $ORACLE_HOME/network/admin, an
  # Oracle Connection Manager CMAN.ORA RULE set, or an external network device.
  # The inherited baseline body reads
  # file("#{$ORACLE_HOME}/network/admin/sqlnet.ora"), which on RDS resolves against
  # the InSpec RUNNER host (no tenant-managed sqlnet.ora), producing a misleading
  # result. On managed RDS network access restriction is an AWS platform function:
  # the listener is AWS-managed and unreachable, and inbound access is governed by
  # VPC security groups / the Cloud.gov brokered private-networking posture, not a
  # tenant SQL/OS setting. control-layers.yml classifies the SQLNET.ORA/listener
  # path as set_by: aws_inherited / verified_by: not_applicable_rds. Override to N/A.
  control 'SV-270539' do
    impact 0.0
    title 'Network access to Oracle Database must be restricted to authorized ' \
          'personnel.'
    desc 'Not Applicable on managed AWS RDS. The DISA check enforces IP-address ' \
         'restriction at the network layer — the listener SQLNET.ORA ' \
         '(tcp.validnode_checking=YES / tcp.invited_nodes) in ' \
         '$ORACLE_HOME/network/admin, an Oracle Connection Manager CMAN.ORA RULE ' \
         'set, or an external network device — none of which the tenant can reach ' \
         'on managed RDS. The inherited baseline reads the runner host\'s ' \
         'sqlnet.ora (no tenant-managed file on RDS), a misleading signal. Network ' \
         'access restriction is an AWS platform function: the listener is ' \
         'AWS-managed and unreachable, and inbound access is governed by VPC ' \
         'security groups and the Cloud.gov brokered private-networking posture, ' \
         'not a tenant SQL/OS setting (control-layers.yml: set_by aws_inherited / ' \
         'verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270539 (restrict network access, CM-6 b) is Not Applicable on ' \
             'managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): IP-address restriction is set at ' \
           'the listener SQLNET.ORA / Connection Manager / external network device ' \
           'level; the listener is AWS-managed on RDS with no tenant OS/listener ' \
           'access, inbound access is governed by VPC security groups, and the ' \
           'inherited sqlnet.ora assertion reflects the runner host. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270541 (CM-6 b) — the /diag subdirectory under DIAGNOSTIC_DEST must be
  # protected from unauthorized access. The DISA check reads DIAGNOSTIC_DEST via
  # SQL, then inspects the OS filesystem permissions of <DIAGNOSTIC_DEST>/diag
  # (`ls -ld` on Unix, Explorer ACLs on Windows), and the fix alters host filesystem
  # permissions on that directory. The inherited baseline body runs
  # command("ls -ld #{diagnostic_dest}/diag | awk ..."), an OS/filesystem check.
  # On managed RDS the tenant has no OS access — the ADR/diag directory and its
  # permissions live on the AWS-managed DB host and are unreachable; the `ls -ld`
  # command reflects the InSpec RUNNER host, not the DB server, producing a
  # meaningless result. Filesystem protection of the diagnostic directory is
  # AWS-managed. control-layers.yml classifies the OS/filesystem path as set_by:
  # aws_inherited / verified_by: not_applicable_rds. Override to N/A.
  control 'SV-270541' do
    impact 0.0
    title 'The /diag subdirectory under the directory assigned to the ' \
          'DIAGNOSTIC_DEST parameter must be protected from unauthorized access.'
    desc 'Not Applicable on managed AWS RDS. The DISA check reads DIAGNOSTIC_DEST ' \
         'via SQL and then inspects OS filesystem permissions on ' \
         '<DIAGNOSTIC_DEST>/diag (`ls -ld` on Unix, Explorer ACLs on Windows); the ' \
         'fix alters host filesystem permissions. Both require OS/filesystem access ' \
         'to the DB host, which the tenant does not have on managed RDS — the ' \
         'diagnostic/diag directory and its permissions are AWS-managed and ' \
         'unreachable, and the inherited baseline `command(\'ls -ld ' \
         '<DIAGNOSTIC_DEST>/diag\')` assertion reflects the InSpec runner host, not ' \
         'the DB server, so it is not a valid signal. Filesystem protection of the ' \
         'diagnostic directory is inherited from the AWS platform ' \
         '(control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270541 (protect <DIAGNOSTIC_DEST>/diag, CM-6 b) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check inspects OS filesystem ' \
           'permissions on <DIAGNOSTIC_DEST>/diag and the fix alters host ' \
           'permissions; the DB host filesystem is AWS-managed on RDS with no ' \
           'tenant access, and the inherited `ls -ld` assertion reflects the runner ' \
           'host, not the DB server. See control-layers.yml and ' \
           'docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270542 (CM-6 b) — remote administration must be disabled for the Oracle
  # Connection Manager (REMOTE_ADMIN = NO in cman.ora). The DISA check reads the
  # cman.ora file in $ORACLE_HOME/network/admin and is EXPLICITLY Not a Finding when
  # that file does not exist (i.e. Connection Manager is not in use). The inherited
  # baseline body reads file("#{$ORACLE_HOME}/network/admin/cman.ora") and also
  # asserts `it { should exist }` — which on RDS resolves against the InSpec RUNNER
  # host and FAILS on a missing cman.ora even though the STIG treats a missing file
  # as Not a Finding, a misleading failure. On managed RDS Oracle Connection Manager
  # is not deployed and the tenant has no OS access to place or read a cman.ora; any
  # Connection Manager, if present in the AWS network path, is AWS-managed and
  # unreachable. control-layers.yml classifies the cman.ora/listener path as set_by:
  # aws_inherited / verified_by: not_applicable_rds. Override to N/A.
  control 'SV-270542' do
    impact 0.0
    title 'Remote administration must be disabled for the Oracle connection ' \
          'manager.'
    desc 'Not Applicable on managed AWS RDS. The DISA check reads the cman.ora ' \
         'file in $ORACLE_HOME/network/admin and is explicitly Not a Finding when ' \
         'the file does not exist (Connection Manager not in use). On managed RDS ' \
         'Oracle Connection Manager is not deployed and the tenant has no OS access ' \
         'to place or read a cman.ora; any Connection Manager in the AWS network ' \
         'path is AWS-managed and unreachable. The inherited baseline reads ' \
         'cman.ora on the runner host and asserts `should exist`, which FAILS on a ' \
         'missing file even though the STIG treats that as Not a Finding — a ' \
         'misleading signal. Connection Manager configuration is inherited from the ' \
         'AWS platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270542 (disable Connection Manager remote admin, CM-6 b) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check reads cman.ora in ' \
           '$ORACLE_HOME/network/admin and is Not a Finding when the file is ' \
           'absent; Oracle Connection Manager is not deployed on managed RDS and ' \
           'the tenant has no OS access, while the inherited `should exist` ' \
           'assertion would falsely fail on the runner host. See control-layers.yml ' \
           'and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270534 (CM-6 b) — the directories assigned to the LOG_ARCHIVE_DEST*
  # parameters must be protected from unauthorized access. The DISA check has two
  # parts: (1) a SQL portion that confirms archive logging is configured (LOG_MODE,
  # log_archive_dest / log_archive_dest_[1-10] / db_recovery_file_dest — and is Not
  # a Finding outright when LOG_MODE is NOARCHIVELOG), and (2) the control's ACTUAL
  # requirement — inspect the OS filesystem permissions on those directories
  # (`ls -ld [pathname]` on Unix, Explorer ACLs on Windows) and it is a finding if
  # world/everyone access is granted or any account beyond the Oracle owner/DBAs/
  # backup operators is listed. The fixed baseline body only implements part 1 (it
  # asserts at least one destination is configured); it does NOT assess the
  # directory permissions that are the STIG's real target. On managed RDS the
  # archive-log and fast-recovery-area directories are AWS-managed (Oracle-Managed
  # Files on RDS-provisioned storage) and the tenant has no OS/filesystem access to
  # run `ls -ld` or alter their permissions — the protectable target is unreachable
  # and inherited from the AWS platform. control-layers.yml classifies the
  # OS/file-permission path as set_by: aws_inherited / verified_by:
  # not_applicable_rds. Override to N/A (impact 0.0) in BOTH postures so an RDS run
  # is not misled by the config-only fragment standing in for a permissions check.
  control 'SV-270534' do
    impact 0.0
    title 'The directories assigned to the LOG_ARCHIVE_DEST* parameters must be ' \
          'protected from unauthorized access.'
    desc 'Not Applicable on managed AWS RDS. The DISA check confirms archive ' \
         'logging is configured via SQL (LOG_MODE, log_archive_dest*, ' \
         'db_recovery_file_dest) and then — the control\'s actual requirement — ' \
         'inspects the OS filesystem permissions on those archive/recovery ' \
         'directories (`ls -ld [pathname]`, Explorer ACLs), a finding if world/' \
         'everyone access or any account beyond the Oracle owner, DBAs, and backup ' \
         'operators is present. The fixed baseline body only asserts a destination ' \
         'is configured; it does not assess the directory permissions the STIG ' \
         'targets. On managed RDS the archive-log and fast-recovery-area ' \
         'directories are AWS-managed (Oracle-Managed Files on RDS-provisioned ' \
         'storage) and the tenant has no OS/filesystem access to run `ls -ld` or ' \
         'alter their permissions — the protectable target is unreachable. ' \
         'Directory protection of the archive logs is inherited from the AWS ' \
         'platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270534 (protect LOG_ARCHIVE_DEST* directories, CM-6 b) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the control\'s real requirement ' \
           'is OS filesystem permissions on the archive-log / recovery ' \
           'directories (`ls -ld`), which are AWS-managed on RDS (Oracle-Managed ' \
           'Files) with no tenant OS access; the fixed baseline only checks that a ' \
           'destination is configured, not its permissions. See control-layers.yml ' \
           'and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270543 (CM-6 b) — network client connections must be restricted to
  # supported versions. The DISA check inspects the sqlnet.ora file in
  # $ORACLE_HOME/network/admin (or TNS_ADMIN) for
  # SQLNET.ALLOWED_LOGON_VERSION_SERVER / _CLIENT set to 12 (or 12a); the fix edits
  # that file. Both require host/OS access to the Oracle Net configuration, which
  # the tenant does not have on managed RDS — sqlnet.ora is AWS-managed and
  # unreachable. The inherited baseline body reads
  # file("#{oracle_home}/network/admin/sqlnet.ora"), which on RDS resolves against
  # the InSpec RUNNER host (no tenant-managed sqlnet.ora), producing a misleading
  # result. control-layers.yml classifies the sqlnet.ora path as set_by:
  # aws_inherited / verified_by: not_applicable_rds. Override to N/A in BOTH
  # postures. NOTE: allowed-logon-version enforcement of the SSL/native crypto
  # posture is delivered by the broker's Oracle Net configuration (the same
  # AWS-managed sqlnet.ora layer as the SSL option group, see SV-270579/271),
  # inherited from the platform rather than tenant-set.
  control 'SV-270543' do
    impact 0.0
    title 'Network client connections must be restricted to supported versions.'
    desc 'Not Applicable on managed AWS RDS. The DISA check inspects the ' \
         'sqlnet.ora file in $ORACLE_HOME/network/admin (or the TNS_ADMIN ' \
         'directory) for SQLNET.ALLOWED_LOGON_VERSION_SERVER / _CLIENT set to 12 ' \
         'or 12a, and the fix edits that file. Both require host/OS access to the ' \
         'Oracle Net configuration, which the tenant does not have on managed RDS ' \
         '— sqlnet.ora is AWS-managed and unreachable. The inherited baseline ' \
         'reads file("$ORACLE_HOME/network/admin/sqlnet.ora"), which on RDS ' \
         'resolves against the InSpec runner host (no tenant-managed sqlnet.ora), ' \
         'producing a misleading result. Allowed-logon-version enforcement is part ' \
         'of the broker-managed Oracle Net configuration (the same AWS-managed ' \
         'sqlnet.ora layer as the SSL option group) and is inherited from the AWS ' \
         'platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270543 (restrict clients to supported logon versions, CM-6 b) is ' \
             'Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check reads ' \
           'SQLNET.ALLOWED_LOGON_VERSION_* in sqlnet.ora under ' \
           '$ORACLE_HOME/network/admin and the fix edits that file; sqlnet.ora is ' \
           'AWS-managed on RDS with no tenant OS access, and the inherited file ' \
           'assertion reflects the runner host, not the DB server. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270544 (CM-6 b, severity high) — DBA OS accounts must be granted only the
  # host system privileges necessary to administer the Oracle Database. The DISA
  # check is entirely OS/host-level: on Unix, `cat /etc/group | grep -i dba`,
  # `groups root`, and `groups [dba user]` to inspect host group memberships (root
  # in the DBA group, DBA accounts in the root group, or DBA accounts in groups
  # granting non-DBA privileges are findings); on Windows, the ORA_DBA /
  # ORA_[SID]_DBA local groups and directly assigned User Rights. The fix revokes
  # host privileges and OS group memberships. All of this targets the OS accounts
  # and groups on the DB host. On managed RDS the tenant has no OS/host access —
  # /etc/group, /etc/passwd, the DBA/root groups, and Windows local groups are
  # AWS-managed and unreachable, and the broker-issued database user is not a host
  # OS account at all. The inherited baseline body runs
  # command('cat /etc/group | grep -i dba') / command('groups root') on the InSpec
  # RUNNER host, not the DB server, producing a meaningless signal.
  # control-layers.yml classifies the /etc/group OS-enumeration path as set_by:
  # aws_inherited / verified_by: not_applicable_rds. Override to N/A in BOTH
  # postures.
  control 'SV-270544' do
    impact 0.0
    title 'Database administrator (DBA) OS accounts must be granted only those ' \
          'host system privileges necessary for the administration of the Oracle ' \
          'Database.'
    desc 'Not Applicable on managed AWS RDS. The DISA check is OS/host-level: on ' \
         'Unix it enumerates host group memberships (`cat /etc/group | grep -i ' \
         'dba`, `groups root`, `groups [dba user]`) and is a finding when root is ' \
         'in the DBA group, a DBA account is in the root group, or a DBA account ' \
         'belongs to groups granting non-DBA privileges; on Windows it reviews the ' \
         'ORA_DBA / ORA_[SID]_DBA local groups and directly assigned User Rights. ' \
         'The fix revokes host privileges and OS group memberships. On managed RDS ' \
         'the tenant has no OS/host access — /etc/group, /etc/passwd, the DBA/root ' \
         'groups, and Windows local groups are AWS-managed and unreachable, and ' \
         'the broker-issued database user is not a host OS account. The inherited ' \
         'baseline `command(\'cat /etc/group | grep -i dba\')` / ' \
         '`command(\'groups root\')` assertions reflect the InSpec runner host, ' \
         'not the DB server, producing a meaningless signal. DBA OS-privilege ' \
         'restriction is inherited from the AWS platform (control-layers.yml: ' \
         'set_by aws_inherited / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270544 (limit DBA OS-account host privileges, CM-6 b) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check enumerates host OS ' \
           'groups (/etc/group, root group, Windows ORA_DBA) and the fix revokes ' \
           'host privileges/group memberships; the DB host OS is AWS-managed on ' \
           'RDS with no tenant access, the broker user is not a host account, and ' \
           'the inherited /etc/group / groups assertions reflect the runner host, ' \
           'not the DB server. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270548 (AC-5 c / CM-6 b) — the database must be protected from unauthorized
  # access by developers on SHARED production/development HOST systems. The DISA
  # check is explicitly Not Applicable when no host contains both a development and
  # a production database, and otherwise is a host/OS review: inspect /etc/oratab
  # for co-resident instances and interview the system owner / development team,
  # then check whether developer OS/DB privileges on the production host are
  # documented and approved. The fix separates developer vs. production
  # accounts/roles at the host level. On managed RDS the tenant has no host/OS
  # access — /etc/oratab and the DB host are AWS-managed and unreachable — and the
  # broker provisions each database as a DEDICATED instance, not a shared dev/prod
  # host, so the DISA "no host contains both" Not-Applicable clause holds. The
  # inherited baseline body is a manual-review skip (no SQL). control-layers.yml
  # classifies the OS/host path as set_by: aws_inherited / verified_by:
  # not_applicable_rds. Override to N/A (impact 0.0) in BOTH postures. (In-database
  # developer-privilege appropriateness on customer-created accounts remains a
  # customer responsibility, covered by the role/authorization controls.)
  control 'SV-270548' do
    impact 0.0
    title 'Oracle Database must be protected from unauthorized access by ' \
          'developers on shared production/development host systems.'
    desc 'Not Applicable on managed AWS RDS. The DISA check is explicitly Not ' \
         'Applicable when no host contains both a development and a production ' \
         'database, and otherwise is a host/OS review — inspect /etc/oratab for ' \
         'co-resident instances, interview the system owner/development team, and ' \
         'check whether developer OS/DB privileges on the production host are ' \
         'documented and approved; the fix separates developer vs. production ' \
         'accounts/roles at the host level. On managed RDS the tenant has no ' \
         'host/OS access (/etc/oratab and the DB host are AWS-managed and ' \
         'unreachable) and the broker provisions each database as a dedicated ' \
         'instance — not a shared dev/prod host — so the DISA "no host contains ' \
         'both" Not-Applicable clause holds. The inherited baseline body is a ' \
         'manual-review skip. Shared-host isolation is inherited from the AWS ' \
         'platform (control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds). In-database developer-privilege appropriateness on ' \
         'customer-created accounts remains a customer responsibility, covered by ' \
         'the role/authorization controls.'
    tag responsibility: 'platform'
    describe 'SV-270548 (protect DB from developers on shared prod/dev hosts, ' \
             'AC-5 c) is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check is a host/OS review ' \
           '(/etc/oratab co-resident instances, host developer privileges) and is ' \
           'Not a Finding when no host holds both dev and prod databases; brokered ' \
           'RDS provisions dedicated instances with no tenant host access. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270555 (CM-6 b / CM-7 a) — OS accounts used to run external procedures
  # called by the database must have limited privileges. The DISA check inspects
  # the OS account behind extproc/external jobs — it reads
  # $ORACLE_HOME/rdbms/admin/externaljob.ora for run_user=/run_group= (must be
  # "nobody") and reviews the privileges of the OS account running external
  # procedures. The fix limits those DBMS-related OS-account privileges. Both are
  # host/OS-level facts unreachable on managed RDS: externaljob.ora and the OS
  # accounts live under the AWS-managed Oracle Home / DB host, and the tenant has
  # no OS access. The inherited baseline body reads
  # file("$ORACLE_HOME/rdbms/admin/externaljob.ora"), which on RDS resolves against
  # the InSpec RUNNER host (no tenant-managed file), a misleading signal. Managed
  # RDS also does not expose a tenant-usable external-procedure OS agent. The
  # extproc OS-account privilege restriction is inherited from the AWS platform.
  # control-layers.yml classifies the "$ORACLE_HOME/" OS path as set_by:
  # aws_inherited / verified_by: not_applicable_rds. Override to N/A in BOTH
  # postures.
  control 'SV-270555' do
    impact 0.0
    title 'OS accounts used to run external procedures called by Oracle Database ' \
          'must have limited privileges.'
    desc 'Not Applicable on managed AWS RDS. The DISA check inspects the OS ' \
         'account behind the external-procedure agent: it reads ' \
         '$ORACLE_HOME/rdbms/admin/externaljob.ora for run_user=/run_group= ' \
         '(expected "nobody") and reviews the privileges of the OS account used to ' \
         'run external procedures; the fix limits those DBMS-related OS-account ' \
         'privileges. Both are host/OS-level facts the tenant cannot reach on ' \
         'managed RDS — externaljob.ora and the OS accounts live under the ' \
         'AWS-managed Oracle Home / DB host, and there is no tenant OS access nor a ' \
         'tenant-usable external-procedure OS agent. The inherited baseline reads ' \
         'file("$ORACLE_HOME/rdbms/admin/externaljob.ora"), which on RDS resolves ' \
         'against the InSpec runner host (no tenant-managed file), a misleading ' \
         'signal. External-procedure OS-account privilege restriction is inherited ' \
         'from the AWS platform (control-layers.yml: set_by aws_inherited / ' \
         'verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270555 (limit extproc OS-account privileges, CM-6 b / CM-7 a) is ' \
             'Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check reads ' \
           '$ORACLE_HOME/rdbms/admin/externaljob.ora and reviews the ' \
           'external-procedure OS account; the Oracle Home and host OS accounts ' \
           'are AWS-managed on RDS with no tenant access, and the inherited file ' \
           'assertion reflects the runner host, not the DB server. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270557 (CM-7 a) — access to external executables must be disabled or
  # restricted. The DISA check is entirely host/OS/listener-level: locate the
  # extproc/extproc.exe executable under $ORACLE_HOME/bin (or the ORACLE_BASE
  # path) and check its file permissions; read $ORACLE_HOME/rdbms/admin/
  # externaljob.ora (run_user/run_group) and $ORACLE_HOME/hs/admin/extproc.ora
  # (EXTPROC_DLLS=ONLY:...); and inspect listener.ora / tnsnames.ora for any
  # "extproc" references, a dedicated IPC listener, etc. The fix stops the
  # listener, edits listener.ora/tnsnames.ora, and alters executable file
  # permissions. All of it requires OS/filesystem and listener access the tenant
  # does not have on managed RDS: the Oracle Home, its bin/hs/rdbms directories,
  # and the AWS-managed listener are unreachable. The inherited baseline body reads
  # file("$ORACLE_HOME/rdbms/admin/externaljob.ora") and
  # file("$ORACLE_HOME/hs/admin/extproc.ora") (asserting `should exist`), which on
  # RDS resolve against the InSpec RUNNER host and would falsely fail. Managed RDS
  # does not expose the external-procedure agent to the tenant. External-executable
  # restriction is inherited from the AWS platform. control-layers.yml classifies
  # the "$ORACLE_HOME/" / listener path as set_by: aws_inherited / verified_by:
  # not_applicable_rds. Override to N/A in BOTH postures.
  control 'SV-270557' do
    impact 0.0
    title 'Access to external executables must be disabled or restricted.'
    desc 'Not Applicable on managed AWS RDS. The DISA check is host/OS/' \
         'listener-level: locate the extproc executable under $ORACLE_HOME/bin ' \
         '(or the ORACLE_BASE path) and check its permissions; read ' \
         '$ORACLE_HOME/rdbms/admin/externaljob.ora (run_user/run_group) and ' \
         '$ORACLE_HOME/hs/admin/extproc.ora (EXTPROC_DLLS=ONLY:...); and inspect ' \
         'listener.ora/tnsnames.ora for any "extproc" references and a dedicated ' \
         'IPC listener. The fix stops the listener, edits listener.ora/' \
         'tnsnames.ora, and alters executable file permissions. All of this ' \
         'requires OS/filesystem and listener access the tenant does not have on ' \
         'managed RDS — the Oracle Home (bin/hs/rdbms) and the AWS-managed listener ' \
         'are unreachable, and RDS does not expose the external-procedure agent to ' \
         'the tenant. The inherited baseline reads ' \
         'file("$ORACLE_HOME/rdbms/admin/externaljob.ora") and ' \
         'file("$ORACLE_HOME/hs/admin/extproc.ora") (`should exist`), which on RDS ' \
         'resolve against the InSpec runner host and would falsely fail. ' \
         'External-executable restriction is inherited from the AWS platform ' \
         '(control-layers.yml: set_by aws_inherited / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270557 (disable/restrict access to external executables, CM-7 a) ' \
             'is Not Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check inspects the extproc ' \
           'executable, externaljob.ora/extproc.ora under $ORACLE_HOME, and ' \
           'listener.ora/tnsnames.ora extproc references; the Oracle Home and ' \
           'listener are AWS-managed on RDS with no tenant access, and the ' \
           'inherited file() assertions reflect the runner host, not the DB ' \
           'server. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270578 (SC-4 / CCI-001090) — access to the Oracle Database files (data
  # files, log files, backup files) must be limited to relevant processes and
  # authorized administrative users. The DISA check is entirely OS/filesystem:
  # `ls -ld [pathname]` on the oradata / audit / fast_recovery_area directories on
  # Unix (finding on world access or any non-authorized reader), or Windows
  # Explorer directory ACLs. The fix sets those filesystem permissions. Both need
  # OS/filesystem access to the DB host, which the tenant lacks on managed RDS —
  # the database files, redo/archive logs, and backup files live on AWS-managed,
  # Oracle-Managed-Files storage that is not tenant-reachable, and RDS backups are
  # AWS-managed snapshots. The inherited baseline body has no SQL (it is a
  # documentation/manual control on the file permissions), so there is no valid
  # tenant signal. File-level access protection is inherited from the AWS platform.
  # Override to N/A in BOTH postures.
  control 'SV-270578' do
    impact 0.0
    title 'Access to Oracle Database files must be limited to relevant processes ' \
          'and to authorized, administrative users.'
    desc 'Not Applicable on managed AWS RDS. The DISA check is OS/filesystem-only: ' \
         'on Unix `ls -ld [pathname]` against the database file, log, and backup ' \
         'directories (e.g. .../oradata/db_name, .../oradata/db_name/audit, ' \
         '.../fast_recovery_area/db_name) — a finding on world access or any ' \
         'non-authorized reader — or the equivalent Windows Explorer directory ' \
         'ACLs; the fix sets those filesystem permissions. Both require OS/' \
         'filesystem access to the DB host, which the tenant does not have on ' \
         'managed RDS: the data files, redo/archive logs, and backup files reside ' \
         'on AWS-managed Oracle-Managed-Files storage that is not tenant-reachable, ' \
         'and RDS backups are AWS-managed snapshots. The inherited baseline is a ' \
         'documentation/manual control on file permissions with no SQL body, so ' \
         'there is no valid tenant signal. File-level access protection is ' \
         'inherited from the AWS platform (control-layers.yml: set_by ' \
         'aws_inherited / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270578 (limit access to Oracle Database files, SC-4) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check is OS filesystem ' \
           'permissions (`ls -ld`) on the data/log/backup directories and the fix ' \
           'sets those permissions; on managed RDS the database files, logs, and ' \
           'backups are AWS-managed (Oracle-Managed Files / RDS snapshots) with no ' \
           'tenant OS access. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270579 (SC-8(1)/SC-8(2) / CCI-002420/002421) — the database must employ
  # cryptographic mechanisms preventing unauthorized disclosure of information
  # during transmission. The DISA check reads $ORACLE_HOME/network/admin/sqlnet.ora
  # for the network-encryption / crypto-checksum parameters
  # (SQLNET.ENCRYPTION_TYPES_* = AES256, SQLNET.CRYPTO_CHECKSUM_TYPES_* = SHA384,
  # etc.), and the inherited baseline body asserts those same strings in that file.
  # On managed RDS sqlnet.ora is AWS-managed and unreachable, so the inherited
  # file() assertion resolves against the InSpec RUNNER host, not the DB server —
  # a misleading signal. Encryption in transit on RDS Oracle is delivered by the
  # broker SSL option group (a TCPS 2484 listener; TLS 1.2 with a FedRAMP/FIPS
  # cipher, FIPS.SSLFIPS_140=TRUE), configured in the AWS-managed sqlnet.ora /
  # fips.ora layer (aws-broker#564). Evidence is the option-group config + a
  # client-side TCPS handshake, not a tenant SQL query. control-layers.yml already
  # classifies the "during transmission" text_pattern as set_by:
  # aws_rds_option_group / verified_by: not_applicable_rds and names this control.
  # Override to N/A in BOTH postures. NOTE: a true TLS-only posture also depended
  # on the platform blocking 1521 (terraform-provision#2351, implemented).
  control 'SV-270579' do
    impact 0.0
    title 'Oracle Database must employ cryptographic mechanisms preventing the ' \
          'unauthorized disclosure of information during transmission unless the ' \
          'transmitted data is otherwise protected by alternative physical ' \
          'measures.'
    desc 'Not Applicable on managed AWS RDS (satisfied by the platform). The DISA ' \
         'check reads $ORACLE_HOME/network/admin/sqlnet.ora for the ' \
         'network-encryption / crypto-checksum parameters (SQLNET.ENCRYPTION_' \
         'TYPES_* = AES256, SQLNET.CRYPTO_CHECKSUM_TYPES_* = SHA384, ' \
         'SQLNET.CRYPTO_CHECKSUM_SERVER = required, etc.), and the inherited ' \
         'baseline body asserts those same strings in that file. On managed RDS ' \
         'sqlnet.ora is AWS-managed and unreachable, so the inherited file() ' \
         'assertion resolves against the InSpec runner host, not the DB server — a ' \
         'misleading signal. Encryption in transit is delivered by the broker SSL ' \
         'option group: a TCPS 2484 listener running TLS 1.2 with a FedRAMP/FIPS ' \
         'cipher (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) and FIPS.SSLFIPS_140=TRUE, ' \
         'configured in the AWS-managed sqlnet.ora / fips.ora layer (aws-broker ' \
         'options.yml, aws-broker#564). Evidence is the option-group config + a ' \
         'client-side TCPS handshake, not a tenant SQL query. In-transit ' \
         'encryption is inherited from the AWS platform (control-layers.yml: ' \
          'set_by aws_rds_option_group / verified_by not_applicable_rds). A true ' \
          'TLS-only posture also depended on the platform blocking 1521 ' \
          '(terraform-provision#2351, implemented).'
    tag responsibility: 'platform'
    describe 'SV-270579 (encrypt information in transit, SC-8(1)/SC-8(2)) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check/fix target ' \
           'SQLNET.ENCRYPTION_* / CRYPTO_CHECKSUM_* in sqlnet.ora, which is ' \
           'AWS-managed on RDS (the inherited file assertion reflects the runner ' \
           'host, not the DB server). Encryption in transit is provided by the ' \
           'broker SSL option group (TCPS 2484, TLS 1.2, FIPS cipher), evidenced by ' \
           'option-group config + a client TCPS handshake, not tenant SQL. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end


  # SV-270559 (IA-2(5)) — users must be authenticated with an individual
  # authenticator PRIOR to using a shared authenticator. The DISA check is
  # procedural and explicitly opens "If shared accounts do not exist, this is Not
  # Applicable"; otherwise it reviews DBMS/OS/enterprise auth mechanism settings
  # (and, optionally, Oracle Access Manager X.509 policy) for individual-before-
  # shared authentication. There is no pass/fail SQL query. On brokered Cloud.gov
  # RDS the broker provisions the database with a SINGLE customer user account via
  # `cf create-service` (not a shared account) — the same "no shared accounts"
  # basis that makes SV-270501 a platform disposition — so the DISA Not Applicable
  # clause is satisfied at provision. If the customer later creates shared accounts,
  # requiring individual authentication before their use (e.g. via OAM X.509 or an
  # enterprise mechanism) is a customer/documentation responsibility. This is a
  # documentation/policy determination, not a tenant SQL assertion; the inherited
  # baseline body is a manual-review skip. Override to Manual (impact 0.0) so an RDS
  # run reports it honestly rather than as a zero-test pass.
  control 'SV-270559' do
    impact 0.0
    title 'Oracle Database must ensure users are authenticated with an ' \
          'individual authenticator prior to using a shared authenticator.'
    desc 'Manual disposition. The DISA check is procedural and opens "If shared ' \
         'accounts do not exist, this is Not Applicable"; otherwise it reviews ' \
         'DBMS/OS/enterprise authentication settings (optionally Oracle Access ' \
         'Manager X.509 policy) to confirm individual authentication is required ' \
         'before a shared authenticator is used — there is no pass/fail SQL query. ' \
         'On brokered Cloud.gov RDS the broker provisions the database with a ' \
         'single customer user account via `cf create-service` (not a shared ' \
         'account), the same "no shared accounts" basis as SV-270501, so the DISA ' \
         'Not Applicable clause is satisfied at provision. If the customer later ' \
         'creates shared accounts, requiring individual authentication before ' \
         'their use (OAM X.509 or an enterprise mechanism) is a ' \
         'customer/documentation responsibility. A documentation/policy ' \
         'determination, not a tenant SQL assertion. See docs/RESPONSIBILITY.md ' \
         'and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, ensuring users are ' \
             '"authenticated with an individual authenticator prior to using a ' \
             'shared authenticator", is a manual/documentation determination: the ' \
             'broker issues a single customer user account (no shared account), ' \
             'satisfying the DISA check\'s "if shared accounts do not exist, this ' \
             'is Not Applicable" clause. If the customer creates shared accounts, ' \
             'individual-before-shared authentication for them is a ' \
             'customer/documentation responsibility.' do
      skip 'Manual review: the broker provisions a single customer user account ' \
           '(no shared account) at provision, satisfying the DISA "no shared ' \
           'accounts = Not Applicable" clause; no SQL assertion is applicable on ' \
           'managed RDS. Customer-created shared accounts are the customer\'s ' \
           'responsibility (docs/RESPONSIBILITY.md).'
    end
  end

  # SV-270560 (IA-2) — the DBMS must uniquely identify and authenticate
  # organizational users (or processes acting on their behalf). The DISA check is
  # purely procedural: "Review DBMS settings, OS settings, ... and site practices,
  # to determine whether organizational users are uniquely identified and
  # authenticated" — there is no pass/fail SQL query. On brokered Cloud.gov RDS
  # database accounts are provisioned and authenticated through the standard
  # CloudFoundry brokered-credentials model (each service binding issues a distinct
  # credential), the FedRAMP-authorized enterprise-level authentication mechanism
  # that is part of the Cloud.gov ATO — the same model that makes SV-270499 a
  # platform disposition. Unique identification/authentication of organizational
  # users is satisfied by that platform model plus the Cloud.gov SSP (IA-2), not by
  # a tenant SQL assertion. If the customer creates additional users, giving each a
  # separate account is a customer responsibility. Override to Manual (impact 0.0)
  # so an RDS run reports it honestly rather than as a zero-test pass.
  control 'SV-270560' do
    impact 0.0
    title 'Oracle Database must uniquely identify and authenticate ' \
          'organizational users (or processes acting on behalf of organizational ' \
          'users).'
    desc 'Manual disposition. The DISA check is procedural: review DBMS/OS/' \
         'enterprise-mechanism settings and site practices to determine whether ' \
         'organizational users are uniquely identified and authenticated — there ' \
         'is no pass/fail SQL query. On brokered Cloud.gov RDS database accounts ' \
         'are provisioned and authenticated through the FedRAMP-authorized ' \
         'CloudFoundry brokered-credentials model (each binding issues a distinct ' \
         'credential), the enterprise-level authentication mechanism that is part ' \
         'of the Cloud.gov ATO — the same model behind SV-270499. Unique ' \
         'identification and authentication of organizational users is satisfied ' \
         'by that platform model plus the Cloud.gov SSP (IA-2), not by a tenant ' \
         'SQL assertion. If the customer creates additional users, issuing each a ' \
         'separate account is a customer responsibility. See docs/RESPONSIBILITY.md ' \
         'and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, uniquely identifying and ' \
             'authenticating "organizational users (or processes acting on behalf ' \
             'of organizational users)", is satisfied by the FedRAMP-authorized ' \
             'CloudFoundry brokered-credentials model (part of the Cloud.gov ATO) ' \
             'and the Cloud.gov SSP (IA-2), which provision and authenticate ' \
             'distinct database credentials — not by a tenant SQL assertion.' do
      skip 'Manual review: database accounts are uniquely identified and ' \
           'authenticated via the FedRAMP-authorized CloudFoundry ' \
           'brokered-credentials model (part of the Cloud.gov ATO); no tenant SQL ' \
           'assertion is applicable on managed RDS. Customer-created users are the ' \
           'customer\'s responsibility (docs/RESPONSIBILITY.md).'
    end
  end

  # SV-270589 (SC-17 b / CCI-004909) — the database must include only approved
  # trust anchors in trust/certificate stores managed by the organization. The
  # DISA check opens "If all accounts are authenticated by the OS or an
  # enterprise-level authentication/access mechanism and not by Oracle, this is not
  # a finding," then verifies TLS trust anchors by inspecting the Oracle Wallet and
  # $ORACLE_HOME/network/admin/sqlnet.ora (WALLET_LOCATION, SSL_CIPHER_SUITES,
  # SSL_VERSION, SSL_CLIENT_AUTHENTICATION). The wallet and sqlnet.ora are the same
  # AWS-managed Oracle Net / SSL layer as SV-270579 — unreachable by the tenant on
  # managed RDS. The TLS trust store / wallet is provisioned and managed by the
  # broker SSL option group; approved-trust-anchor content is a platform
  # responsibility evidenced by the option-group config, not a tenant SQL query.
  # The inherited baseline has no SQL body (manual/documentable control). Override
  # to N/A in BOTH postures.
  control 'SV-270589' do
    impact 0.0
    title 'Oracle Database must include only approved trust anchors in trust ' \
          'stores or certificate stores managed by the organization.'
    desc 'Not Applicable on managed AWS RDS. The DISA check first notes it is Not ' \
         'a Finding when accounts are authenticated by the OS or an ' \
         'enterprise-level mechanism rather than by Oracle, then verifies TLS ' \
         'trust anchors by inspecting the Oracle Wallet and ' \
         '$ORACLE_HOME/network/admin/sqlnet.ora (WALLET_LOCATION, ' \
         'SSL_CIPHER_SUITES, SSL_VERSION, SSL_CLIENT_AUTHENTICATION). The wallet ' \
         'and sqlnet.ora are the same AWS-managed Oracle Net / SSL layer as ' \
         'SV-270579 — unreachable by the tenant on managed RDS with no OS access. ' \
         'The TLS trust store / Oracle Wallet is provisioned and managed by the ' \
         'broker SSL option group (the TCPS 2484 / TLS 1.2 posture); which trust ' \
         'anchors are present is a platform responsibility evidenced by the ' \
         'option-group configuration, not a tenant SQL query. The inherited ' \
         'baseline is a documentation/manual control with no SQL body. Trust-anchor ' \
         'management is inherited from the AWS platform (control-layers.yml: ' \
         'set_by aws_rds_option_group / verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270589 (only approved trust anchors, SC-17 b) is Not Applicable ' \
             'on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check inspects the Oracle ' \
           'Wallet and SSL_* entries in sqlnet.ora, which are AWS-managed on RDS ' \
           'with no tenant OS access; the TLS trust store is provisioned by the ' \
           'broker SSL option group and evidenced by its config, not tenant SQL. ' \
           'See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270569 (IA-7 / CCI-000803) — the database must use NIST-validated FIPS
  # 140-2/140-3 compliant cryptography for AUTHENTICATION mechanisms. The DISA
  # check opens $ORACLE_HOME/ldap/admin/fips.ora (or the FIPS_HOME location) in an
  # editor and is a finding if the line "SSLFIPS_140=TRUE" is not present. The fix
  # edits that same fips.ora file. Both require host/OS access to read and edit a
  # file under the Oracle Home, which the tenant does not have on managed RDS —
  # fips.ora lives in the AWS-managed Oracle Net / SSL layer (the same layer as the
  # broker SSL option group), and the inherited baseline body
  # `file("#{oracle_home}/ldap/admin/fips.ora")` resolves ORACLE_HOME on the InSpec
  # RUNNER host, not the DB server, so its `should include 'SSLFIPS_140=TRUE'` and
  # `should exist` assertions reflect the runner and are a misleading signal. On
  # RDS FIPS-mode SSL/TLS for the listener is set by the broker SSL option group
  # (FIPS.SSLFIPS_140=TRUE on the TCPS 2484 / TLS 1.2 listener — the same posture
  # SV-270579 documents), evidenced by the option-group config, not tenant SQL.
  # control-layers.yml classifies the SSLFIPS_140 / fips.ora path as set_by
  # aws_rds_option_group / verified_by not_applicable_rds. Override to N/A.
  control 'SV-270569' do
    impact 0.0
    title 'Oracle Database must use NIST-validated FIPS 140-2/140-3 compliant ' \
          'cryptography for authentication mechanisms.'
    desc 'Not Applicable on managed AWS RDS (satisfied by the platform). The DISA ' \
         'check opens fips.ora (default $ORACLE_HOME/ldap/admin/, or the FIPS_HOME ' \
         'location) and is a finding if "SSLFIPS_140=TRUE" is not present; the fix ' \
         'edits that same file. Both require host/OS access to a file under the ' \
         'Oracle Home, which the tenant does not have on managed RDS — fips.ora is ' \
         'in the AWS-managed Oracle Net / SSL layer, and the inherited baseline ' \
         'file("#{oracle_home}/ldap/admin/fips.ora") assertion resolves ORACLE_HOME ' \
         'on the InSpec runner host, not the DB server, so it is a misleading ' \
         'signal. FIPS-mode SSL/TLS for authentication is provided by the broker ' \
         'SSL option group (FIPS.SSLFIPS_140=TRUE on the TCPS 2484 / TLS 1.2 ' \
         'listener — the SV-270579 posture), evidenced by the option-group config, ' \
         'not tenant SQL. FIPS authentication cryptography is inherited from the ' \
         'AWS platform (control-layers.yml: set_by aws_rds_option_group / ' \
         'verified_by not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270569 (FIPS 140 cryptography for authentication, IA-7) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the check/fix target ' \
           'SSLFIPS_140=TRUE in $ORACLE_HOME/ldap/admin/fips.ora, an AWS-managed ' \
           'file with no tenant OS access (the inherited file() assertion reflects ' \
           'the runner host). FIPS-mode SSL/TLS is set by the broker SSL option ' \
           'group (the SV-270579 TCPS/TLS posture), evidenced by option-group ' \
           'config, not tenant SQL. See control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270571 (SC-13 b / CCI-002450) — the database must implement NIST FIPS
  # 140-2/140-3 validated cryptographic modules to protect unclassified data
  # requiring confidentiality, per the data owner's requirements. The DISA check
  # opens "If encryption is not required for the database, this is not a finding,"
  # then verifies FIPS mode across three layers: DBFIPS_140 (V$PARAMETER) for TDE /
  # DBMS_CRYPTO, SSLFIPS_140=TRUE in fips.ora for SSL/TLS, and SQLNET.FIPS_140=TRUE
  # in sqlnet.ora for Native Network Encryption. The fips.ora and sqlnet.ora legs
  # are host/OS files in the AWS-managed Oracle Net / SSL layer, unreachable by the
  # tenant on managed RDS (same layer as SV-270579 / SV-270569). The DBFIPS_140
  # parameter governing at-rest / DBMS_CRYPTO FIPS mode is set at the instance
  # level by AWS (RDS parameter group / option group), not a tenant ALTER SYSTEM,
  # and storage encryption at rest is already provided by the broker (encrypted:
  # true, KMS — control-layers.yml "at rest" entry). The generic baseline is a
  # needs_dev stub (no SQL body). The cryptographic-module posture for both in-
  # transit (broker SSL option group) and at-rest (broker KMS storage encryption)
  # is a platform fact evidenced by AWS metadata / option-group config, not a
  # tenant SQL assertion. Override to N/A (platform).
  control 'SV-270571' do
    impact 0.0
    title 'Oracle Database must implement NIST FIPS 140-2/140-3 validated ' \
          'cryptographic modules to protect unclassified information requiring ' \
          "confidentiality and cryptographic protection, in accordance with the " \
          "data owner's requirements."
    desc 'Not Applicable on managed AWS RDS (satisfied by the platform). The DISA ' \
         'check is Not a Finding if encryption is not required, and otherwise ' \
         'verifies FIPS mode across three layers: DBFIPS_140 (V$PARAMETER) for TDE ' \
         '/ DBMS_CRYPTO, SSLFIPS_140=TRUE in fips.ora for SSL/TLS, and ' \
         'SQLNET.FIPS_140=TRUE in sqlnet.ora for Native Network Encryption. The ' \
         'fips.ora and sqlnet.ora legs are host/OS files in the AWS-managed Oracle ' \
         'Net / SSL layer, unreachable by the tenant on managed RDS (the same layer ' \
         'as SV-270579 / SV-270569). DBFIPS_140 is set at the instance level by AWS ' \
         '(RDS parameter/option group), not a tenant ALTER SYSTEM. The validated ' \
         'cryptographic-module posture is provided by the platform on both axes: ' \
         'in transit by the broker SSL option group (TCPS 2484 / TLS 1.2 / ' \
         'FIPS.SSLFIPS_140=TRUE, aws-broker#564) and at rest by broker storage ' \
         'encryption (encrypted:true, KMS — control-layers.yml "at rest" entry), ' \
         'evidenced by option-group config + AWS metadata, not a tenant SQL query. ' \
         'The generic baseline is a needs_dev stub with no SQL body. FIPS ' \
         'cryptographic modules are inherited from the AWS platform ' \
         '(control-layers.yml: set_by aws_rds_option_group / verified_by ' \
         'not_applicable_rds).'
    tag responsibility: 'platform'
    describe 'SV-270571 (FIPS 140 validated cryptographic modules, SC-13 b) is Not ' \
             'Applicable on managed AWS RDS' do
      skip 'Not Applicable (not_applicable_rds): the FIPS mode checks target ' \
           'fips.ora / sqlnet.ora (AWS-managed, no tenant OS access) and DBFIPS_140 ' \
           '(instance-level, set by AWS parameter/option group). Validated crypto ' \
           'modules are platform-provided in transit (broker SSL option group) and ' \
           'at rest (broker KMS storage encryption), evidenced by option-group ' \
           'config + AWS metadata, not tenant SQL. See control-layers.yml and ' \
           'docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270574 (SC-28 / CCI-002476) — the database must protect data at rest and
  # ensure confidentiality and integrity of application data. The DISA check is
  # procedural: review the system documentation for whether encryption of data at
  # rest is required, and — key clause — "If full-disk encryption is being used,
  # this is not a finding." Only if the AO requires it and full-disk encryption is
  # NOT in use does it fall back to verifying Oracle TDE (dba_encrypted_columns /
  # v$encrypted_tablespaces). On managed Cloud.gov RDS, storage encryption at rest
  # is enabled by the broker at provision (StorageEncrypted set from the
  # catalog plan's encrypted:true — control-layers.yml "at rest" entry /
  # aws-broker), which uses an AWS-managed KMS key by default and is the
  # full-disk / storage-volume encryption the check's not-a-finding clause
  # names. That encryption is a platform/broker fact evidenced by AWS metadata
  # (the DB instance StorageEncrypted flag), NOT a tenant SQL assertion. Cloud.gov
  # has no data-at-rest encryption requirement beyond that full-disk/volume
  # encryption (managed separately by the broker), so no TDE fallback applies. The
  # inherited baseline TDE queries are not tenant-verifiable on RDS; we override to
  # a platform Not Applicable disposition (impact 0.0). If a site's data owner/AO
  # specifically requires column/tablespace TDE beyond volume encryption,
  # deploying/verifying TDE for that data becomes the customer's responsibility.
  control 'SV-270574' do
    impact 0.0
    title 'Oracle Database must take steps to protect data at rest and ensure ' \
          'confidentiality and integrity of application data.'
    desc 'Not Applicable on managed AWS RDS (satisfied by the platform). The DISA ' \
         'check is procedural and states "If full-disk encryption is being used, ' \
         'this is not a finding"; only if data-at-rest encryption is required and ' \
         'full-disk encryption is not in use does it fall back to Oracle TDE ' \
         '(dba_encrypted_columns / v$encrypted_tablespaces). On managed Cloud.gov ' \
         'RDS, storage encryption at rest is enabled by the broker at provision ' \
         '(StorageEncrypted set from the catalog plan\'s encrypted:true — ' \
         'control-layers.yml "at rest" entry), which uses an AWS-managed KMS key ' \
         'by default and is the full-disk / storage-volume encryption named by the ' \
         'check; Cloud.gov defines no data-at-rest encryption requirement beyond ' \
         'that volume encryption, so the TDE fallback never applies. That ' \
         'encryption is a platform/broker fact evidenced by AWS metadata (the DB ' \
         'instance StorageEncrypted flag), not a tenant SQL assertion — ' \
         'the inherited TDE queries would report no encrypted tablespaces and ' \
         'mislead even though volume-level encryption satisfies the control. ' \
         'Data-at-rest confidentiality is inherited from the AWS platform ' \
         '(control-layers.yml: set_by broker_infra / verified_by aws_inherited); ' \
         'because the queried target is not tenant-reachable on RDS the overlay ' \
         'overrides to Not Applicable (impact 0.0). If a data owner/AO requires ' \
         'column/tablespace TDE beyond volume encryption, deploying and verifying ' \
         'that TDE is the customer\'s responsibility.'
    tag responsibility: 'platform'
    describe 'SV-270574 (protect data at rest, SC-28) is Not Applicable on ' \
             'managed AWS RDS' do
      skip 'Not Applicable (platform): storage encryption at rest is enabled by ' \
           'the broker at provision (StorageEncrypted from the plan\'s ' \
           'encrypted:true, AWS-managed KMS key by default) — the full-disk ' \
           'encryption the DISA check treats as not-a-finding — evidenced by AWS ' \
           'metadata (StorageEncrypted flag), not tenant SQL, and Cloud.gov ' \
           'has no data-at-rest requirement beyond it. The inherited TDE queries ' \
           'are not tenant-verifiable on RDS. Customer-required column/tablespace ' \
           'TDE beyond volume encryption is a customer responsibility. See ' \
           'control-layers.yml and docs/RESPONSIBILITY.md.'
    end
  end

  # SV-270575 (SC-28(1)) — cryptographic mechanisms to prevent unauthorized
  # MODIFICATION of organization-defined data at rest (PII/classified). The DISA
  # check is procedural and opens "If no information is identified as requiring
  # such protection, this is not a finding," otherwise reviewing whether the
  # DBMS/OS/filesystem encryption in use provides the required integrity
  # protection. Whether data requires integrity protection at rest is an
  # organization documentation/policy determination governed by the Cloud.gov SSP
  # (SC-28(1)); there is no pass/fail SQL predicate. Where such protection is
  # required, it is delivered by the same broker-provisioned storage encryption
  # that satisfies SV-270574 (StorageEncrypted / AWS-managed KMS, evidenced by AWS
  # metadata, not tenant SQL). The inherited baseline is a manual-review skip.
  control 'SV-270575' do
    impact 0.0
    title 'Oracle Database must implement cryptographic mechanisms to prevent ' \
          'unauthorized modification of organization-defined information at rest ' \
          '(to include, at a minimum, PII and classified information) on ' \
          'organization-defined information system components.'
    desc 'Manual disposition. The DISA check is procedural: "If no information is ' \
         'identified as requiring such protection [from modification], this is not ' \
         'a finding"; otherwise review whether the DBMS/OS/filesystem encryption ' \
         'in use provides the required level of integrity protection. Whether data ' \
         'at rest requires cryptographic modification-protection is an ' \
         'organization documentation/policy determination governed by the ' \
         'Cloud.gov SSP (SC-28(1)), not a tenant SQL assertion. Where such ' \
         'protection is required, it is delivered by the broker-provisioned ' \
         'storage encryption that also satisfies SV-270574 (StorageEncrypted, ' \
         'AWS-managed KMS key), evidenced by AWS metadata rather than SQL — a ' \
         'platform fact, the same mechanism behind SV-270574. The inherited ' \
         'baseline is a manual-review skip. See docs/RESPONSIBILITY.md and ' \
         'control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, cryptographic protection ' \
             'against unauthorized modification of organization-defined data at ' \
             'rest, is a manual/documentation determination: per the DISA check, ' \
             'if no information is identified as requiring such protection this is ' \
             'Not a Finding. It is satisfied by the Cloud.gov SSP ' \
             'data-classification posture (SC-28(1)) plus, where required, the ' \
             'broker-provisioned storage encryption (SV-270574), not by an ' \
             'automated SQL assertion.' do
      skip 'Manual review: satisfied by system documentation / SSP (SC-28(1)) and ' \
           'broker-provisioned storage encryption (see SV-270574); no SQL ' \
           'assertion is applicable on managed RDS.'
    end
  end

  # SV-270576 (SC-3 / SC-2) — isolate security functions from nonsecurity
  # functions via separate security domains. The DISA check is procedural: verify
  # that objects/code implementing security functionality live in a separate
  # security domain (a dedicated database or schema). The check itself notes this
  # is Oracle's DEFAULT behavior — roles, permissions, profiles, and password
  # complexity requirements are stored in separate data-dictionary schemas — and
  # directs the reviewer to inspect only site-specific security modules. There is
  # no pass/fail SQL predicate; it is a design/documentation determination. The
  # inherited baseline is a manual-review skip.
  control 'SV-270576' do
    impact 0.0
    title 'Oracle Database must isolate security functions from nonsecurity ' \
          'functions by means of separate security domains.'
    desc 'Manual disposition. The DISA check is procedural: verify that objects ' \
         'or code implementing security functionality are located in a separate ' \
         'security domain (a separate database or schema). Per the check, this is ' \
         'the DEFAULT behavior for Oracle — roles, permissions, profiles, and ' \
         'password-complexity requirements are stored in separate Oracle Data ' \
         'Dictionary schemas — and the reviewer inspects only any site-specific ' \
         'security modules. There is no pass/fail SQL predicate; it is a ' \
         'design/documentation determination governed by the Cloud.gov SSP ' \
         '(SC-3/SC-2), and the broker provisions the database with distinct ' \
         'privileged versus application accounts. The inherited baseline is a ' \
         'manual-review skip. See docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, isolating security functions ' \
             'from nonsecurity functions via separate security domains, is a ' \
             'design/documentation determination: Oracle by default stores ' \
             'security functionality (roles, permissions, profiles) in separate ' \
             'data-dictionary schemas, and no site-specific security module ' \
             'commingles it with application logic. Satisfied by the Cloud.gov ' \
             'SSP (SC-3/SC-2), not by an automated SQL assertion.' do
      skip 'Manual review: Oracle isolates security functionality in separate ' \
           'data-dictionary schemas by default; satisfied by system documentation ' \
           '/ SSP (SC-3/SC-2). No SQL assertion is applicable on managed RDS.'
    end
  end

  # SV-270577 (SC-4) — protect DB contents from unauthorized/unintended transfer
  # by enforcing a data-transfer policy. The DISA check is procedural: review the
  # procedures and any scripts/code used to refresh dev/test data from production,
  # confirming copies of production data are not left in unprotected locations and
  # that sensitive data is de-sensitized or access-authorized before import. There
  # is no pass/fail SQL predicate; it is an organizational policy/procedure
  # determination (data-transfer / dev-test-refresh policy) governed by the
  # Cloud.gov SSP (SC-4). Managing production-to-nonproduction data movement for
  # customer-owned data is a customer responsibility. The inherited baseline is a
  # manual-review skip.
  control 'SV-270577' do
    impact 0.0
    title 'Oracle Database contents must be protected from unauthorized and ' \
          'unintended information transfer by enforcement of a data-transfer ' \
          'policy.'
    desc 'Manual disposition. The DISA check is procedural: review the procedures ' \
         'and any scripts/code that move production data to dev/test systems (or ' \
         'elsewhere), verifying copies are not left in unprotected locations and ' \
         'that sensitive data is de-sensitized or access-authorized before import. ' \
         'There is no pass/fail SQL predicate; it is an organizational ' \
         'policy/procedure determination (a data-transfer / dev-test-refresh ' \
         'policy) governed by the Cloud.gov SSP (SC-4). For brokered RDS, ' \
         'controlling how customer-owned production data is copied to ' \
         'non-production environments is a customer responsibility. The inherited ' \
         'baseline is a manual-review skip. See docs/RESPONSIBILITY.md and ' \
         'control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, protecting database contents ' \
             'from unauthorized/unintended transfer by enforcing a data-transfer ' \
             'policy, is a policy/procedure determination: review of dev/test ' \
             'data-refresh procedures and data-movement code to ensure production ' \
             'data is not left unprotected. Satisfied by the Cloud.gov SSP (SC-4) ' \
             'and customer data-handling procedures, not by an automated SQL ' \
             'assertion.' do
      skip 'Manual review: satisfied by the organizational data-transfer policy / ' \
           'SSP (SC-4) and customer dev-test-refresh procedures; no SQL assertion ' \
           'is applicable on managed RDS.'
    end
  end

  # SV-270580 (SI-10) — the DBMS must check the validity of data inputs. The DISA
  # check is a procedural source-code/schema review: inspect DBMS code, field
  # definitions, constraints, and triggers to confirm data input is validated, and
  # the fix adds field definitions and enabled constraints to the application
  # schema. Which inputs require validation and how is an application-design fact
  # of the customer-owned application schema; there is no portable pass/fail SQL
  # predicate (a generic query cannot decide whether every required constraint
  # exists across arbitrary customer tables). It is a documentation/application
  # determination governed by the Cloud.gov SSP (SI-10) and the customer's
  # application. The inherited baseline is a manual-review skip.
  control 'SV-270580' do
    impact 0.0
    title 'Oracle Database must check the validity of data inputs.'
    desc 'Manual disposition. The DISA check is a procedural source-code/schema ' \
         'review: inspect DBMS code, field definitions, constraints, and triggers ' \
         'to determine whether input data is validated, and the fix adds field ' \
         'definitions and enabled constraints to the application schema. Which ' \
         'inputs require validation, and the constraints/field definitions that ' \
         'enforce it, are application-design facts of the customer-owned schema — ' \
         'there is no portable pass/fail SQL predicate (a generic query cannot ' \
         'decide whether every required constraint exists across arbitrary ' \
         'customer tables). It is a documentation/application determination ' \
         'governed by the Cloud.gov SSP (SI-10); designing and enforcing input ' \
         'validation in the customer application schema is a customer ' \
         'responsibility. The inherited baseline is a manual-review skip. See ' \
         'docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, checking the validity of data ' \
             'inputs, is a source-code/schema-design determination reviewed ' \
             'against the customer-owned application schema (field definitions, ' \
             'constraints, triggers). It has no portable SQL predicate and is ' \
             'satisfied by the Cloud.gov SSP (SI-10) and customer application ' \
             'design, not by an automated assertion.' do
      skip 'Manual review: input validation is an application schema-design fact ' \
           '(constraints/field definitions/triggers) with no portable SQL ' \
           'predicate; satisfied by system documentation / SSP (SI-10) and ' \
           'customer application design. No SQL assertion is applicable on ' \
           'managed RDS.'
    end
  end

  # SV-270581 (SI-10) — reserve dynamic code execution for situations that require
  # it. The DISA check is a procedural source-code review of stored procedures,
  # functions, triggers, and application code to identify dynamic code execution
  # that could practically be replaced by static execution with strongly typed
  # parameters; the fix rewrites such code. This is a customer-owned
  # application/PL/SQL design determination with no portable pass/fail SQL
  # predicate. It is governed by the Cloud.gov SSP (SI-10) and the customer's
  # secure-coding practices. The inherited baseline is a manual-review skip.
  control 'SV-270581' do
    impact 0.0
    title 'The database management system (DBMS) and associated applications ' \
          'must reserve the use of dynamic code execution for situations that ' \
          'require it.'
    desc 'Manual disposition. The DISA check is a procedural source-code review — ' \
         'inspect stored procedures, functions, triggers, and application code to ' \
         'find dynamic code execution employed where the objective could ' \
         'practically be met by static execution with strongly typed parameters — ' \
         'and the fix rewrites that code. This is a customer-owned ' \
         'application/PL/SQL secure-coding determination with no portable ' \
         'pass/fail SQL predicate. It is governed by the Cloud.gov SSP (SI-10) and ' \
         'the customer\'s secure-coding practices; reviewing and remediating ' \
         'dynamic code in the customer application is a customer responsibility. ' \
         'The inherited baseline is a manual-review skip. See ' \
         'docs/RESPONSIBILITY.md and control-layers.yml.'
    tag responsibility: 'customer'
    describe 'The implementation of this control, reserving dynamic code ' \
             'execution for situations that require it, is a source-code review ' \
             'of customer-owned stored procedures/functions/triggers and ' \
             'application code. It has no portable SQL predicate and is satisfied ' \
             'by the Cloud.gov SSP (SI-10) and customer secure-coding practices, ' \
             'not by an automated assertion.' do
      skip 'Manual review: dynamic-code-execution usage is a customer ' \
           'application/PL/SQL secure-coding fact with no portable SQL predicate; ' \
           'satisfied by system documentation / SSP (SI-10) and customer ' \
           'secure-coding practices. No SQL assertion is applicable on managed RDS.'
    end
  end
end
