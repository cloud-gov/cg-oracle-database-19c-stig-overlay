control 'SV-270542' do
  title 'Remote administration must be disabled for the Oracle connection
  manager.'
  desc 'Remote administration provides a potential opportunity for malicious
  users to make unauthorized changes to the Connection Manager configuration or
  interrupt its service.'
  desc 'check', 'View the cman.ora file in the ORACLE_HOME/network/admin
  directory.

  If the file does not exist, the database is not accessed via Oracle Connection
  Manager and this check is not a finding.

  If the entry and value for REMOTE_ADMIN is not listed or is not set to a value
  of NO (REMOTE_ADMIN = NO), this is a finding.'
  desc 'fix', 'View the cman.ora file in the ORACLE_HOME/network/admin directory
  of the Connection Manager.

  Include the following line in the file:

  REMOTE_ADMIN = NO'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270542'
  tag rid: 'SV-270542r1064904_rule'
  tag stig_id: 'O19C-00-011600'
  tag fix_id: 'F-74476r1064903_fix'
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

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/cman.ora" do
    its('content') { should include 'REMOTE_ADMIN = NO' }
    it { should exist }
  end
end
