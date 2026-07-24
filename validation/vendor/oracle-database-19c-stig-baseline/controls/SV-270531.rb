control 'SV-270531' do
  title 'The Oracle Listener must be configured to require administration
  authentication.'
  desc 'Oracle listener authentication helps prevent unauthorized administration of the Oracle listener. Unauthorized administration of the listener could lead to denial-of-service (DoS) exploits, loss of connection audit data, unauthorized reconfiguration, or other unauthorized access. This is a Category I finding because privileged access to the listener is not restricted to authorized users. Unauthorized access can result in stopping of the listener (DoS) and overwriting of listener audit logs.'
  desc 'check', 'If a listener is not running on the local database host server, this check is not a finding.

Note: Complete this check only once per host system and once per listener. Multiple listeners may be defined on a single host system. They must all be reviewed, but only once per database home review.

For subsequent database home reviews on the same host system, this check is not a finding.

Determine all listeners running on the host.

For Windows hosts, view all Windows services with TNSListener embedded in the service name:

- The service name format is:
Oracle[ORACLE_HOME_NAME]TNSListener

For Unix hosts, the Oracle Listener process will indicate the TNSLSNR executable.

At a command prompt, issue the command:
ps -ef | grep tnslsnr | grep -v grep

The alias for the listener follows tnslsnr in the command output.

Must be logged on the host system using the account that owns the tnslsnr executable (Unix). If the account is denied local logon, have the system administrator (SA) assist in this task by adding "su" to the listener account from the root account. On Windows platforms, log on using an account with administrator privileges to complete the check.

From a system command prompt, execute the listener control utility:

lsnrctl status [LISTENER NAME]

Review the results for the value of Security.

If "Security = OFF" is displayed, this is a finding.

If "Security = ON: Password or Local OS Authentication", this is a finding (Instead, use Local OS Authentication).

If "Security = ON: Local OS Authentication" is displayed, this is not a finding.

Repeat the execution of the lsnrctl utility for all active listeners.'
  desc 'fix', 'By default, Oracle Net Listener permits only local administration for security reasons. As a policy, the listener can be administered only by the user who started it. 

Oracle Listener authentication is enforced through local operating system authentication. For example, if user1 starts the listener, then only user1 can administer it. Any other user trying to administer the listener receives an error. The super user is the only exception.

Remote administration of the listener must not be permitted. If listener administration from a remote system is required, granting secure remote access to the Oracle database management system (DBMS) server and performing local administration is preferred. Authorize and document this requirement in the system documentation.

Refer to Oracle Database Net Services Reference for additional information.'
  impact 0.7
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270531'
  tag rid: 'SV-270531r1065272_rule'
  tag stig_id: 'O19C-00-009900'
  tag fix_id: 'F-74465r1064870_fix'
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

  listener_name = command("ps -ef | grep tnslsnr | grep -v grep|awk '{ print $9; }'").stdout.strip

  listener_status = command("lsnrctl status #{listener_name}").stdout.strip

  describe 'The Oracle Listener status' do
    subject { listener_status }
    it { should_not include 'Security                  OFF' }
    it { should_not include 'Security                  ON: Password or Local OS Authentication' }
  end
  describe listener_status do
    it { should_not be_empty }
  end
end
