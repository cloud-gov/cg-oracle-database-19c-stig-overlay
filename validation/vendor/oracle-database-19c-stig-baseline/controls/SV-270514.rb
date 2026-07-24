control 'SV-270514' do
  title 'Database software, applications, and configuration files must be
  monitored to discover unauthorized changes.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review monitoring procedures and implementation evidence to
  verify that monitoring of changes to database software libraries, related
  applications, and configuration files is done.

  Verify that the list of files and directories being monitored is complete. If
  monitoring does not occur or is not complete, this is a finding.'
  desc 'fix', 'Implement procedures to monitor for unauthorized changes to database management system (DBMS) software libraries, related software application libraries, and configuration files. If a third-party automated tool is not employed, an automated job that reports file information on the directories and files of interest and compares them to the baseline report for the same will meet the requirement.

File hashes or checksums should be used for comparisons since file dates may be manipulated by malicious users.'
  impact 0.5
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag gid: 'V-270514'
  tag rid: 'SV-270514r1064820_rule'
  tag stig_id: 'O19C-00-007700'
  tag fix_id: 'F-74448r1064819_fix'
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

  describe command('grep aide /etc/crontab /etc/cron.*/*') do
    its('stdout.strip') { should_not be_empty }
  end
end
