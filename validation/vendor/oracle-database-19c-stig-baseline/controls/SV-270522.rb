control 'SV-270522' do
  title 'Fixed user and PUBLIC Database links must be authorized for use.'
  desc 'Database links define connections that may be used by the local Oracle database to access remote Oracle databases (homogenous links) and non-Oracle Databases (heterogeneous links). These links provide a means for a compromise to the local database to spread to remote databases and for a compromise of a remote database to the local database in a distributed database environment. Limiting or eliminating the use of database links, where they are not required to support the operational system, can help isolate compromises, mitigate risk, and reduce the potential attack surface.'
  desc 'check', "If using a non-CDB database:
Use the following query to get a list of database links.

From SQL*Plus:

select owner||': '||db_link from dba_db_links;

If using a CDB database:
Use the following query to get a list of database links.

select con_id_to_con_name(con_id) con_id, owner, db_link, username, host from cdb_db_links order by 1,2,3;

Check Results:

If no rows are returned from the first SQL statement, this check is not a finding.

If there are rows returned, verify the database links are required. If they are required and exist, this is not a finding."
  desc 'fix', 'Document all authorized connections from the database to remote databases.

Remove all unauthorized remote database connection definitions from the database.

From SQL*Plus:

drop database link [link name];
OR
drop public database link [link name];

Review remote database connection definitions periodically and confirm their use is still required and authorized.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270522'
  tag rid: 'SV-270522r1115956_rule'
  tag stig_id: 'O19C-00-008700'
  tag fix_id: 'F-74456r1064843_fix'
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

  db_links = sql.query('SELECT DB_LINK FROM DBA_DB_LINKS;').column('db_link').uniq
  if db_links.empty?
    impact 0.0
    describe 'There are no oracle database links defined, control N/A' do
      skip 'There are no oracle database links defined, control N/A'
    end
  else
    db_links.each do |link|
      describe "The defined oracle database link: #{link}" do
        subject { link }
        it { should be_in input('allowed_db_links') }
      end
    end
  end
end
