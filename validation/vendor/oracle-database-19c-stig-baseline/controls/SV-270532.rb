control 'SV-270532' do
  title 'Application role permissions must not be assigned to the Oracle PUBLIC
  role.'
  desc 'Permissions granted to PUBLIC are granted to all users of the
  database. Custom roles must be used to assign application permissions to
  functional groups of application users. The installation of Oracle does not
  assign role permissions to PUBLIC.'
  desc 'check', "From SQL*Plus:

  select granted_role from dba_role_privs where grantee = 'PUBLIC';

  If any roles are listed, this is a finding."
  desc 'fix', 'Revoke role grants from PUBLIC.

  Do not assign role privileges to PUBLIC.

  From SQL*Plus:

  revoke [role name] from PUBLIC;'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270532'
  tag rid: 'SV-270532r1064874_rule'
  tag stig_id: 'O19C-00-010000'
  tag fix_id: 'F-74466r1064873_fix'
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

  describe sql.query("select granted_role from dba_role_privs where grantee = 'PUBLIC';").row(0).column('granted_role') do
    its('value') { should be_empty }
  end
end
