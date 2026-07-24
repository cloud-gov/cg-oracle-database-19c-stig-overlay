control 'SV-270524' do
  title 'The Oracle REMOTE_OS_ROLES parameter must be set to FALSE.'
  desc 'Setting REMOTE_OS_ROLES to TRUE allows operating system groups to control Oracle roles. The default value of FALSE causes roles to be identified and managed by the database. If REMOTE_OS_ROLES is set to TRUE, a remote user could impersonate another operating system user over a network connection. 
 
DOD requires the REMOTE_OS_ROLES to be set to FALSE.'
  desc 'check', "To verify the current status of the remote_os_roles parameter use the SQL statement: 

If using a non-CDB database:

From SQL*Plus:
 
COLUMN name format a20 
COLUMN parameter_value format a20 

SELECT name, con_id, value AS PARAMETER_VALUE 
FROM sys.v_$parameter 
WHERE vp.name = 'remote_os_roles' 
ORDER BY 1; 

If the PARAMETER_VALUE is not FALSE, that is a finding.

If using a CDB database:

From SQL*Plus (in the CDB database):
 
COLUMN name format a20 
COLUMN parameter_value format a20 

SELECT name, inst_id, con_id, value AS PARAMETER_VALUE 
FROM sys.gv_$parameter 	
WHERE vp.name = 'remote_os_roles' 
ORDER BY 1; 

In the CDB database, if the PARAMETER_VALUE is not FALSE, that is a finding."
  desc 'fix', "Set the parameter to FALSE for all instances. If using Oracle Multitenant, set the value to FALSE for the container database and all pluggable databases will be set to FALSE as well. 

ALTER SYSTEM SET remote_os_roles = FALSE scope=spfile; 

sid='container_name' is optional 

Restart the database for the change to take effect."
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270524'
  tag rid: 'SV-270524r1112471_rule'
  tag stig_id: 'O19C-00-009200'
  tag fix_id: 'F-74458r1064849_fix'
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

  parameter = sql.query("select value from v$parameter where name = 'remote_os_roles';").column('value')

  describe 'The oracle database REMOTE_OS_ROLES parameter' do
    subject { parameter }
    it { should cmp 'FALSE' }
  end
end
