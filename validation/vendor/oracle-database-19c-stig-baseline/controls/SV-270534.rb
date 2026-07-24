control 'SV-270534' do
  title 'The directories assigned to the LOG_ARCHIVE_DEST* parameters must be
  protected from unauthorized access.'
  desc 'The LOG_ARCHIVE_DEST parameter is used to specify the directory to which Oracle archive logs are written. Where the database management system (DBMS) availability and recovery to a specific point in time is critical, the protection of archive log files is critical. Archive log files may also contain unencrypted sensitive data. If written to an inadequately protected or invalidated directory, the archive log files may be accessed by unauthorized persons or processes.'
  desc 'check', "From SQL*Plus:

select log_mode from v$database;
select value from v$parameter where name = 'log_archive_dest';
select value from v$parameter where name = 'log_archive_duplex_dest';
select name, value from v$parameter where name LIKE 'log_archive_dest_%';
select value from v$parameter where name = 'db_recovery_file_dest';

If the value returned for LOG_MODE is NOARCHIVELOG, this check is not a finding.

If a value is not returned for LOG_ARCHIVE_DEST and no values are returned for any of the LOG_ARCHIVE_DEST_[1-10] parameters, and no value is returned for DB_RECOVERY_FILE_DEST, this is a finding.

Note: LOG_ARCHIVE_DEST and LOG_ARCHIVE_DUPLEX_DEST are incompatible with the LOG_ARCHIVE_DEST_n parameters, and must be defined as the null string (' ') when any LOG_ARCHIVE_DEST_n parameter has a value other than a null string.

On Unix Systems:

ls -ld [pathname]

Substitute [pathname] with the directory paths listed from the above SQL statements for log_archive_dest and log_archive_duplex_dest.

If permissions are granted for world access, this is a finding.

On Windows systems (from Windows Explorer):

Browse to the directory specified.

Select and right-click on the directory >> Properties >> Security tab.

If permissions are granted to everyone, this is a finding.

If any account other than the Oracle process and software owner accounts, administrators, database administrators (DBAs), system group, or developers authorized to write and debug applications on this database are listed, this is a finding."
  desc 'fix', 'Specify a valid and protected directory for archive log files.

  Restrict access to the Oracle process and software owner accounts, DBAs, and
  backup operator accounts.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270534'
  tag rid: 'SV-270534r1065274_rule'
  tag stig_id: 'O19C-00-010400'
  tag fix_id: 'F-74468r1064879_fix'
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

  log_archive_dest = sql.query("select value from v$parameter where name = 'log_archive_dest';").column('value')

  describe 'The oracle database log_archive_dest parameter' do
    subject { log_archive_dest }
    it { should_not cmp [' '] }
  end

  parameter = sql.query("select DISTINCT value from v$parameter where name LIKE 'log_archive_dest_%';").column('value')

  describe 'The oracle database value for log_archive_dest parameter' do
    subject { parameter }
    it { should_not cmp [' '] }
  end

  db_recovery_file_dest = sql.query("select value from v$parameter where name = 'db_recovery_file_dest';").column('value').uniq

  describe 'The oracle database db_recovery_file_dest parameter' do
    subject { db_recovery_file_dest }
    it { should_not cmp [' '] }
  end
end
