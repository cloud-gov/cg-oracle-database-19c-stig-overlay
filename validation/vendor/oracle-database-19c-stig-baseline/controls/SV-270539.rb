control 'SV-270539' do
  title 'Network access to Oracle Database must be restricted to authorized personnel.'
  desc 'Restricting remote access to specific, trusted systems helps prevent
  access by unauthorized and potentially malicious users.'
  desc 'check', 'IP address restriction may be defined for the database listener, by use of the Oracle Connection Manager or by an external network device.

Identify the method used to enforce address restriction (interview database administrator [DBA]) or review system documentation).

If enforced by the database listener, then review the SQLNET.ORA file located in the ORACLE_HOME/network/admin directory (this assumes that a single sqlnet.ora file, in the default location, is in use; SQLNET.ORA could also be the directory indicated by the TNS_ADMIN environment variable or registry setting).

If the following entries do not exist, then restriction by IP address is not configured and is a finding.

tcp.validnode_checking=YES
tcp.invited_nodes=(IP1, IP2, IP3)

If enforced by an Oracle Connection Manager, then review the CMAN.ORA file for the Connection Manager (located in the TNS_ADMIN or ORACLE_HOME/network/admin directory for the connection manager).

If a RULE entry allows all addresses ("/32") or does not match the address range specified in the system documentation, this is a finding.

(rule=(src=[IP]/27)(dst=[IP])(srv=*)(act=accept))

Note: An IP address with a "/" indicates acceptance by subnet mask where the number after the "/" is the left most number of bits in the address that must match for the rule to apply.'
  desc 'fix', 'Configure the database listener to restrict access by IP address or set up an external device to restrict network access to the DBMS.

More information can be found at https://docs.oracle.com/en/database/oracle/oracle-database/19/netrf/parameters-for-the-sqlnet.ora.html#GUID-5C3AB641-7541-4CE9-BC9E-BA5DD30616A8.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270539'
  tag rid: 'SV-270539r1064895_rule'
  tag stig_id: 'O19C-00-011200'
  tag fix_id: 'F-74473r1064894_fix'
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

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'tcp.validnode_checking=YES' }
    its('content') { should match /tcp.invited_nodes=(\W*)/ }
  end
end
