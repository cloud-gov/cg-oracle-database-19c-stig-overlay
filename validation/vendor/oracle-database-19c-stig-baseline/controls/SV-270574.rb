control 'SV-270574' do
  title 'Oracle Database must take steps to protect data at rest and ensure confidentiality and integrity of application data.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in nonmobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use.

User-generated data and application-specific configuration data must be protected. Configurations and/or rule sets for firewalls, gateways, intrusion detection/prevention systems, and filtering routers and authenticator content are examples of system information likely requiring protection. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate.

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', %q(Review system documentation to determine whether the system handles classified information. If the system does not handle classified information, the severity of this check is downgraded to CAT II. 
 
If the application owner and authorizing official (AO) have determined that encryption of data at rest is required, verify the data on secondary devices is encrypted. 
 
If full-disk encryption is being used, this is not a finding. 

If data encryption is required, verify that the data is encrypted before being put on the secondary device. To ensure that the appropriate controls are in place, discuss the precautions taken with the site database administrators (DBAs) and system administrators (SAs) and try to modify data at rest.

Oracle recommends using Transparent Data Encryption, which is part of Oracle Advanced Security Option, to protect data.

To verify the data is encrypted, upon an auditor's request, Oracle provides views that document the encryption status of the database. For TDE column encryption, use the view "dba_encrypted_columns", which lists the owner, table name, column name, encryption algorithm, and salt for all encrypted columns. For TDE tablespace encryption, the following SQL statement lists all encrypted tablespaces with their encryption algorithm and corresponding, encrypted, data files. Issue the following commands to verify the data at rest is encrypted.

$ sqlplus connect as sysdba

SQL> SELECT t.name "TSName",
e.encryptionalg "Algorithm",
d.file_name "File Name"
FROM v$tablespace t,
v$encrypted_tablespaces e,
dba_data_files d
WHERE t.ts# = e.ts#
and t.name = d.tablespace_name;

The next SQL statement lists the table owner, tables within encrypted tablespaces, and the encryption algorithm:

SQL> SELECT a.owner "Owner",
a.table_name "Table Name",
e.encryptionalg "Algorithm"
FROM dba_tables a,
v$encrypted_tablespaces e
WHERE a.tablespace_name in (select t.name from v$tablespace t, v$encrypted_tablespaces e where t.ts# = e.ts#);

For each database where encryption is required, verify that encryption is in effect. If it is not, this is a finding.)
  desc 'fix', 'Apply appropriate controls to protect the confidentiality and integrity of data at rest in the database.

If no site-specific precautions are in place, use Oracle Advanced Security Option to encrypt data at rest.

If Oracle Advanced Security Option is not an option, use site-specific procedures to secure data at rest.'
  impact 0.7
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag gid: 'V-270574'
  tag rid: 'SV-270574r1192921_rule'
  tag stig_id: 'O19C-00-016800'
  tag fix_id: 'F-74508r1064999_fix'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28', 'Rev_4']
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

  parameter = sql.query("select * from v$parameter where name = 'DBFIPS_140c';").column('value')

  describe 'The oracle database DBFIPS_140c parameter' do
    subject { parameter }
    it { should_not be_empty }
  end
end
