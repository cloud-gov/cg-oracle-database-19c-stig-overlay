control 'SV-270512' do
  title 'Oracle Database must support enforcement of logical access restrictions associated with changes to the database management system (DBMS) configuration and to the database itself.'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review access restrictions associated with changes to the configuration of the DBMS or database(s).

On Unix Systems:
ls -ld [pathname]

Replace [pathname] with the directory path where the Oracle Database software is installed (e.g., /u01/app/oracle/product/19.0.0/dbhome_1).

If permissions are granted for world access, this is a finding.

If any groups that include members other than the software owner account, database administrators (DBAs), or any accounts not listed as authorized, this is a finding.

For Windows Systems:
Review the permissions that control access to the Oracle installation software directories (e.g., \\Program Files\\Oracle\\).

If access is given to members other than the software owner account, DBAs, or any accounts not listed as authorized, this is a finding.

Compare the access control employed with that documented in the system documentation.

If access does not match the documented requirement, this is a finding.'
  desc 'fix', 'For Unix Systems:
Set the umask of the Oracle software owner account to 022. Determine the shell being used for the Oracle software owner account:

  env | grep -i shell

Startup files for each shell are as follows (located in users $HOME directory):

  C-Shell (CSH) = .cshrc
  Bourne Shell (SH) = .profile
  Korn Shell (KSH) = .kshrc
  TC Shell (TCS) = .tcshrc
  BASH Shell = .bash_profile or .bashrc

Edit the shell startup file for the account and add or modify the line:

  umask 022

Log off and log on, then enter the umask command to confirm the setting.

Note: To effect this change for all Oracle processes, a reboot of the DBMS server may be required.

For Windows Systems:
Restrict access to the DBMS software libraries to the fewest accounts that clearly require access based on job function.

Document authorized access controls and justify any access grants that do not fall under DBA, DBMS process, ownership, or system administrator (SA) accounts.'
  impact 0.5
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag gid: 'V-270512'
  tag rid: 'SV-270512r1065305_rule'
  tag stig_id: 'O19C-00-007300'
  tag fix_id: 'F-74446r1065304_fix'
  tag cci: ['CCI-000345', 'CCI-001813']
  tag nist: ['CM-5', 'Rev_4', 'CM-5 (1) (a)']
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

  umask = command('umask').stdout.strip

  describe 'The system umask' do
    subject { umask }
    it { should be >= '0022' }
  end
end
