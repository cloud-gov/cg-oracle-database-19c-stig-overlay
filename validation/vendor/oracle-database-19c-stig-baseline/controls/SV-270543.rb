control 'SV-270543' do
  title 'Network client connections must be restricted to supported versions.'
  desc 'Unsupported Oracle network client installations may introduce
  vulnerabilities to the database. Restriction to use of supported versions helps
  to protect the database and helps to enforce newer, more robust security
  controls.'
  desc 'check', 'Note: The SQLNET.ALLOWED_LOGON_VERSION parameter is deprecated in earlier Oracle Database versions. This parameter has been replaced with two new Oracle Net Services parameters:

SQLNET.ALLOWED_LOGON_VERSION_SERVER
SQLNET.ALLOWED_LOGON_VERSION_CLIENT

View the SQLNET.ORA file in the ORACLE_HOME/network/admin directory or the directory specified in the TNS_ADMIN environment variable. 

Locate the following entries:

SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12
SQLNET.ALLOWED_LOGON_VERSION_CLIENT = 12

If the parameters do not exist, this is a finding.

If the parameters are not set to a value of 12 or 12a, this is a finding.

Note: Attempting to connect with a client version lower than specified in these parameters may result in a misleading error:
ORA-01017: invalid username/password: logon denied'
  desc 'fix', 'Edit the SQLNET.ORA file to add or edit the entries:

SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12
SQLNET.ALLOWED_LOGON_VERSION_CLIENT = 12

Set the value to 12 or higher.
Valid values for SQLNET.ALLOWED_LOGON_VERSION_SERVER are: 12 and 12a

Valid values for SQLNET.ALLOWED_LOGON_VERSION_CLIENT are: 12 and 12a

For more information on sqlnet.ora parameters refer to the following document:
https://docs.oracle.com/en/database/oracle/oracle-database/19/netrf/parameters-for-the-sqlnet.ora.html'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270543'
  tag rid: 'SV-270543r1064907_rule'
  tag stig_id: 'O19C-00-011700'
  tag fix_id: 'F-74477r1064906_fix'
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

  describe.one do
    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'sqlnet.allowed_logon_version_server=11' }
      its('content') { should include 'sqlnet.allowed_logon_version_client=11' }
    end

    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'sqlnet.allowed_logon_version_server=12' }
      its('content') { should include 'sqlnet.allowed_logon_version_client=12' }
    end

    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'sqlnet.allowed_logon_version_server=12a' }
      its('content') { should include 'sqlnet.allowed_logon_version_client=12a' }
    end
  end
end
