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

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  standard_auditing_used = input('standard_auditing_used')
  unified_auditing_used = input('unified_auditing_used')

  describe.one do
    describe 'Standard auditing is in use for audit purposes' do
      subject { standard_auditing_used }
      it { should be true }
    end

    describe 'Unified auditing is in use for audit purposes' do
      subject { unified_auditing_used }
      it { should be true }
    end
  end

  audit_trail = sql.query("select value from v$parameter where name = 'audit_trail';").column('value')
  audit_info_captured = sql.query('SELECT EVENT_TIMESTAMP FROM UNIFIED_AUDIT_TRAIL ORDER BY EVENT_TIMESTAMP DESC FETCH FIRST 10 ROWS ONLY;').column('event_timestamp')
  fga_audit_events = sql.query(" SELECT * FROM SYS.UNIFIED_AUDIT_TRAIL WHERE AUDIT_TYPE = 'FineGrainedAudit';").column('TIMESTAMP')

  if standard_auditing_used
    describe 'The oracle database audit_trail parameter' do
      subject { audit_trail }
      it { should_not cmp 'NONE' }
    end
  end

  unified_auditing = sql.query("SELECT value FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';").column('value')

  if unified_auditing_used
    describe 'The oracle database unified auditing parameter' do
      subject { unified_auditing }
      it { should_not cmp 'FALSE' }
    end

    describe 'The oracle database unified auditing events captured' do
      subject { audit_info_captured }
      it { should_not be_empty }
    end

    describe 'The oracle database fine grained  auditing events captured' do
      subject { fga_audit_events }
      it { should_not be_empty }
    end

  end
end
