control 'SV-270540' do
  title 'Changes to configuration options must be audited.'
  desc 'When standard auditing is in use, the AUDIT_SYS_OPERATIONS parameter is used to enable auditing of actions taken by the user SYS. The SYS user account is a shared account by definition and holds all privileges in the Oracle database. It is the account accessed by users connecting to the database with SYSDBA or SYSOPER privileges.'
  desc 'check', "For Unified or mixed auditing, from SQL*Plus:

select count(*) from audit_unified_enabled_policies where entity_name = 'SYS';

If the count is less than one row, this is a finding.

For Standard auditing, from SQL*Plus:

select value from v$parameter where name = 'audit_sys_operations';

If the value returned is FALSE, this is a finding."
  desc 'fix', 'For Standard auditing, from SQL*Plus:

alter system set audit_sys_operations = TRUE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.

If Unified Auditing is used, to ensure auditable events are captured:
Link the oracle binary with uniaud_on, and then restart the database. Oracle Database Upgrade Guide describes how to enable unified auditing.

For additional information on creating audit policies, refer to the Oracle Database Security Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-audit-policies.html'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270540'
  tag rid: 'SV-270540r1064898_rule'
  tag stig_id: 'O19C-00-011300'
  tag fix_id: 'F-74474r1064897_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
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

  parameter = sql.query("select value from v$parameter where name = 'audit_sys_operations';").column('value')

  describe 'The oracle database AUDIT_SYS_OPERATIONS parameter' do
    subject { parameter }
    it { should_not cmp 'FALSE' }
  end
end
