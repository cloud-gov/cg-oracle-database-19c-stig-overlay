control 'SV-270515' do
  title 'The OS must limit privileges to change the database management system (DBMS) software resident within software libraries (including privileged programs).'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review permissions that control access to the DBMS software libraries. The software library location may be determined from vendor documentation or service/process executable paths.

Typically, only the DBMS software installation/maintenance account or system administrator (SA) account requires access to the software library for operational support such as backups. Any other accounts should be scrutinized and the reason for access documented. Accounts should have the least amount of privilege required to accomplish the job.

Below is one example for how to review accounts with access to software libraries for a Linux-based system:
cat /etc/group |grep -i dba
--Example output:
dba:x:102: 

--take above number and input in below grep command
cat /etc/passwd |grep 102

If any accounts are returned that are not required and authorized to have access to the software library location do have access, this is a finding.'
  desc 'fix', 'Restrict access to the DBMS software libraries to accounts that
  require access based on job function.'
  impact 0.5
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag gid: 'V-270515'
  tag rid: 'SV-270515r1065210_rule'
  tag stig_id: 'O19C-00-007900'
  tag fix_id: 'F-74449r1064822_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)', 'Rev_4']
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

  dba_users = sql.query("select * from dba_role_privs where granted_role = 'DBA';").column('grantee').uniq
  if dba_users.empty?
    impact 0.0
    describe "There are no oracle DBA's, control N/A" do
      skip "There are no oracle DBA's, control N/A"
    end
  else
    dba_users.each do |user|
      describe "oracle DBA's users: #{user}" do
        subject { user }
        it { should be_in input('oracle_dbas') }
      end
    end
  end
end
