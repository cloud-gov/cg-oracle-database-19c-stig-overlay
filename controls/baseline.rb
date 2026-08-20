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
