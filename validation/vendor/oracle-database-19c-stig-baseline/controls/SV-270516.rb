control 'SV-270516' do
  title 'The Oracle Database software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system. 

If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications.

Database administrator (DBA) and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on database security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them.

This requirement is particularly important because Oracle equates the installation account with the SYS account - the super-DBA. Once logged on to the operating system, this account can connect to the database AS SYSDBA without further authentication. It is very powerful and, by virtue of not being linked to any one person, cannot be audited to the level of the individual.'
  desc 'check', 'Review procedures for controlling and granting access to use of the database management system (DBMS) software installation account.

If access or use of this account is not restricted to the minimum number of personnel required, or if unauthorized access to the account has been granted, this is a finding.'
  desc 'fix', 'Develop, document, and implement procedures to restrict use of
  the DBMS software installation account.'
  impact 0.7
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag gid: 'V-270516'
  tag rid: 'SV-270516r1064826_rule'
  tag stig_id: 'O19C-00-008000'
  tag fix_id: 'F-74450r1064825_fix'
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

  describe 'A manual review is required to ensure the DBMS software installation account is restricted to
    authorized users' do

    skip 'A manual review is required to ensure the DBMS software installation account is restricted to
    authorized users'
  end
end
