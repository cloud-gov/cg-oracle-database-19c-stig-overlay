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
end
