control 'V-270521' do
  title "Oracle instance names must not contain Oracle version numbers."
  desc "Service names may be discovered by unauthenticated users. If the service
      name includes version numbers or other database product information, a
      malicious user may use that information to develop a targeted attack."
  impact 0.5
  tag 'benchmark_id': 494
  tag 'title': 'SRG-APP-000516-DB-000363'
  tag 'rule_title': 'Oracle instance names must not contain Oracle version numbers'
  tag 'group_id': 'V-270521'
  tag 'rule_id': 'SV-270521r1112467_rule'
  tag 'rule_weight': "10.0"
  tag 'rule_severity': 'medium'
  tag "rule_version": "O19C-00-008600"
  tag "stig_id": 'O121-BP-021300'
  tag 'fix_id': 'F-74455r1064840_fix'
  tag "rule_ident": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "rule_vuln_discussion": "Service names may be discovered by unauthenticated users. If the service name includes version numbers or other database product information, a malicious user may use that information to develop a targeted attack."
  tag "rule_fix_text": "Follow the instructions in Oracle MetaLink Note 15390.1 (and related documents) to change the SID for the database without recreating the database to a value that does not identify the Oracle version."
  tag "rule_fix_id": "F-74455r1064840_fix"
  tag "rule_check_system": "C-74554r1112466_chk"

  tag "check_12c": "From SQL*Plus:

  select instance_name from v$instance;
  select version from v$instance;

  If the instance name returned references the Oracle release number, this is a
  finding.

  Numbers used that include version numbers by coincidence are not a finding.

  The DBA should be able to relate the significance of the presence of a digit in
  the SID."

  tag "check": "If using a non-CDB database:

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

  The database administrator (DBA) should be able to relate the significance of the presence of a digit in the SID."

  tag "fix": "Follow the instructions in Oracle MetaLink Note 15390.1 (and related documents) to change the SID for the database without recreating the database to a value that does not identify the Oracle version."

  # NOTE: Check content has changed from 12c to 19c - Ruby code may need to be updated
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  version = sql.query('select version from v$instance;').column('version')
  db_instance_name = sql.query('select instance_name from v$instance;').column('instance_name')

  describe 'The oracle database instance name' do
    subject { db_instance_name }
    it { should_not include version.to_s }
  end

end
