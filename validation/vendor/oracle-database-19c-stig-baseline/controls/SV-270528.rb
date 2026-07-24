control 'SV-270528' do
  title 'System Privileges must not be granted to PUBLIC.'
  desc 'System privileges can be granted to users and roles and to the user
  group PUBLIC. All privileges granted to PUBLIC are accessible to every user in
  the database. Many of these privileges convey considerable authority over the
  database and should be granted only to those persons responsible for
  administering the database. In general, these privileges should be granted to
  roles and then the appropriate roles should be granted to users. System
  privileges must never be granted to PUBLIC as this could allow users to
  compromise the database.'
  desc 'check', "From SQL*Plus:

Select privilege from dba_sys_privs where grantee = 'PUBLIC';

If any records are returned, this is a finding."
  desc 'fix', 'Revoke any system privileges assigned to PUBLIC:

  From SQL*Plus:

  revoke [system privilege] from PUBLIC;

  Replace [system privilege] with the named system privilege.

  Note:  System privileges are not granted to PUBLIC by default and would
  indicate a custom action.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270528'
  tag rid: 'SV-270528r1064862_rule'
  tag stig_id: 'O19C-00-009600'
  tag fix_id: 'F-74462r1064861_fix'
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

  describe sql.query("select privilege from dba_sys_privs where grantee = 'PUBLIC';").row(0).column('privilege') do
    its('value') { should be_empty }
  end
end
