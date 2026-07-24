control 'SV-270544' do
  title 'Database administrator (DBA) OS accounts must be granted only those host system privileges necessary for the administration of the Oracle Database.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and nonprivileged account.

DBAs, if assigned excessive OS privileges, could perform actions that could endanger the information system or hide evidence of malicious activity.'
  desc 'check', 'Review host system privileges assigned to the Oracle DBA group and all individual Oracle DBA accounts.

Note: Do not include the Oracle software installation account in any results for this check.

For Unix systems (as root):
cat /etc/group | grep -i dba
groups root

If "root" is returned in the first list, this is a finding.

If any accounts listed in the first list are also listed in the second list, this is a finding.

Investigate any user account group memberships other than DBA or root groups that are returned by the following command (also as root):

groups [dba user account]

Replace [dba user account] with the user account name of each DBA account.

If individual DBA accounts are assigned to groups that grant access or privileges for purposes other than DBA responsibilities, this is a finding.

For Windows systems, click Start >> Settings >> Control Panel >> Administrative Tools >> Computer Management >> Local Users and Groups >> Groups >> ORA_DBA.

Start >> Settings >> Control Panel >> Administrative Tools >> Computer Management >> Local Users and Groups >> Groups >> ORA_[SID]_DBA (if present).

Note: Users assigned DBA privileges on a Windows host are granted membership in the ORA_DBA and/or ORA_[SID]_DBA groups. The ORA_DBA group grants DBA privileges to any database on the system. The ORA_[SID]_DBA groups grant DBA privileges to specific Oracle instances only.

Make a note of each user listed. For each user, click Start >> Settings >> Control Panel >> Administrative Tools >> Computer Management >> Local Users and Groups >> Users >> [DBA username] >> Member of.

If DBA users belong to any groups other than DBA groups and the Windows Users group, this is a finding.

Examine User Rights assigned to DBA groups or group members by clicking Start >> Settings >> Control Panel >> Administrative Tools >> Local Security Policy >> Security Settings >> Local Policies >> User Rights Assignments.

If any User Rights are assigned directly to the DBA group(s) or DBA user accounts, this is a finding.'
  desc 'fix', 'Revoke all host system privileges from the DBA group accounts and DBA user accounts not required for database management system (DBMS) administration.

Revoke all OS group memberships that assign excessive privileges to the DBA group accounts and DBA user accounts.

Remove any directly applied permissions or user rights from the DBA group accounts and DBA user accounts.

Document all DBA group accounts and individual DBA account-assigned privileges in the system documentation.'
  impact 0.7
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270544'
  tag rid: 'SV-270544r1065278_rule'
  tag stig_id: 'O19C-00-011800'
  tag fix_id: 'F-74478r1064909_fix'
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

  get_dba_users = command('cat /etc/group | grep -i dba').stdout.strip.split("\n")
  get_members_root_group = command('groups root').stdout.strip.split("\n")

  get_dba_users.each do |user|
    describe "The dba user: #{user} in /etc/group" do
      subject { user }
      it { should_not cmp 'root' }
    end

    get_members_root_group.each do |member|
      describe "The user: #{member} in the root group" do
        subject { member }
        it { should_not cmp user.to_s }
      end
    end
  end
  if get_dba_users.empty?
    describe 'There are no dba users, therefore this control is NA' do
      skip 'There are no dba users, therefore this control is NA'
    end
  end
end
