control 'SV-270505' do
  title 'Oracle Database must include organization-defined additional, more detailed information in the audit records for audit events identified by type, location, or subject.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

In addition, the application must have the capability to include organization-defined additional, more detailed information in the audit records for audit events. These events may be identified by type, location, or subject.

An example of detailed information the organization may require in audit records is full-text recording of privileged commands or the individual identities of shared account users.

Some organizations may determine that more detailed information is required for specific database event types. If this information is not available, it could negatively impact forensic investigations into user actions or other malicious events.'
  desc 'check', "Review the system documentation to identify additional site-specific information not covered by the default audit options, the organization has determined to be necessary. If there are none, this is not a finding.

If any additional information is defined, compare those auditable events that are not covered by unified auditing with the existing Fine-Grained Auditing (FGA) specifications returned by the following query:

SELECT COUNT(*)
FROM audsys.unified_audit_trail
WHERE audit_type = 'FineGrainedAudit';

If any such auditable event is not covered by the existing FGA specifications, this is a finding."
  desc 'fix', 'If the site-specific audit requirements are not covered by the default audit options, deploy and configure FGA. For details, refer to Oracle documentation, at the location below.

For more information on the configuration of fine-grained auditing, refer to the following documents:
https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-audit-policies.html#GUID-88DA3AF8-5F6A-4C6E-80EE-F65071E5BF46.'
  impact 0.5
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag gid: 'V-270505'
  tag rid: 'SV-270505r1167742_rule'
  tag stig_id: 'O19C-00-005600'
  tag fix_id: 'F-74439r1064792_fix'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)', 'Rev_4']
  tag 'false_negatives'
  tag 'false_positives'
  tag 'documentable'
  tag 'mitigations'
  tag 'severity_override_guidance'
  tag 'potential_impacts'
  tag 'third_party_tools'
  tag 'mitigation_controls'
  tag 'responsibility'
  tag 'ia_controls'
  tag 'check'
  tag 'fix'

  # OVERLAY (#9): the upstream check queries SYS/AUDSYS.UNIFIED_AUDIT_TRAIL, which
  # ERRORED on the local Oracle 23ai Free harness (ORA-00942 — view not accessible
  # to the connecting user in that config). Rather than GUESS at a rewrite that
  # might be wrong for RDS SE2, this control is deferred to evaluation against a
  # LIVE brokered RDS SE2 instance (aws-broker#558), where unified-auditing views
  # + the master user's audit-role grants reflect the real target. Do NOT silently
  # pass. See control-layers.yml (verified_by: requires_live_rds).
  describe 'Audit-record detail (unified/FGA) — requires evaluation on a live RDS SE2 instance (#558); UNIFIED_AUDIT_TRAIL not accessible on the local 23ai harness' do
    skip 'Deferred to live RDS SE2 proof (aws-broker#558): UNIFIED_AUDIT_TRAIL access + master audit-role grants must be confirmed on the real instance; not evaluated locally to avoid a version-specific false result.'
  end
end
