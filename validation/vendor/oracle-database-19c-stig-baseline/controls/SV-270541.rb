control 'SV-270541' do
  title 'The /diag subdirectory under the directory assigned to the
  DIAGNOSTIC_DEST parameter must be protected from unauthorized access.'
  desc '<DIAGNOSTIC_DEST> /diag indicates the directory where trace, alert, core, and incident directories and files are located. The files may contain sensitive data or information that could prove useful to potential attackers.'
  desc 'check', %q(From SQL*Plus:

select value from v$parameter where name='diagnostic_dest';

On Unix Systems:

ls -ld [pathname]/diag

Substitute [pathname] with the directory path listed from the above SQL command, and append "/diag" to it, as shown.

If permissions are granted for world access, this is a finding.

If any groups that include members other than the Oracle process and software owner accounts, DBAs, auditors, or backup accounts are listed, this is a finding.

On Windows Systems (from Windows Explorer):

Browse to the \diag directory under the directory specified.

Select and right-click on the directory >> Properties >> Security tab.

If permissions are granted to everyone, this is a finding.

If any account other than the Oracle process and software owner accounts, administrators, database administrators (DBAs), system group or developers authorized to write and debug applications on this database are listed, this is a finding.)
  desc 'fix', 'Alter host system permissions to the <DIAGNOSTIC_DEST>/diag directory to the Oracle process and software owner accounts, DBAs, system administrators (SAs) (if required), and developers or other users that may specifically require access for debugging or other purposes.

Authorize and document user access requirements to the directory outside of the Oracle, DBA, and SA account list.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270541'
  tag rid: 'SV-270541r1065276_rule'
  tag stig_id: 'O19C-00-011500'
  tag fix_id: 'F-74475r1065244_fix'
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

  get_diagnostic_dest = sql.query("select value from v$parameter where name = 'diagnostic_dest';").column('value')

  diagnostic_dest = get_diagnostic_dest.to_s.delete('[""]')

  describe command("ls -ld #{diagnostic_dest}/diag |awk '{ print $1; }'") do
    its('stdout') { should match /\w*---.$/ }
  end
end
