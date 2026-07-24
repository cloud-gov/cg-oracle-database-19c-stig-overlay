control 'SV-270521' do
  title 'Oracle instance names must not contain Oracle version numbers.'
  desc 'Service names may be discovered by unauthenticated users. If the
  service name includes version numbers or other database product information, a
  malicious user may use that information to develop a targeted attack.'
  desc 'check', 'If using a non-CDB database:

From SQL*Plus:

select instance_name, version from v$instance;

If using a CDB database:

To check the container database (CDB):

From SQL*Plus:

select instance_name, version from v$instance;

To check the pluggable databases (PDBs) within the CDB:

select name from v$pdbs;

Check Instance Name:

If the instance name returned references the Oracle release number, this is a finding.

Numbers used that include version numbers by coincidence are not a finding.

The database administrator (DBA) should be able to relate the significance of the presence of a digit in the SID.'
  desc 'fix', 'Follow the instructions in Oracle MetaLink Note 15390.1 (and related documents) to change the SID for the database without recreating the database to a value that does not identify the Oracle version.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270521'
  tag rid: 'SV-270521r1112467_rule'
  tag stig_id: 'O19C-00-008600'
  tag fix_id: 'F-74455r1064840_fix'
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

  version = sql.query('select version from v$instance;').column('version')
  db_instance_name = sql.query('select instance_name from v$instance;').column('instance_name')

  describe 'The oracle database instance name' do
    subject { db_instance_name }
    it { should_not include version.to_s }
  end
end
