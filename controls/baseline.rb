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
end
