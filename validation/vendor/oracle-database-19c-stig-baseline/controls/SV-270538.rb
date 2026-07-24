control 'SV-270538' do
  title 'The Oracle Database data files, transaction logs and audit files must be stored in dedicated directories or disk partitions separate from software or other application files.'
  desc "Protection of database management system (DBMS) data, transaction and audit data files stored by the host operating system is dependent on OS controls. When different applications share the same database, resource contention and security controls are required to isolate and protect an application's data from other applications. In addition, it is an Oracle best practice to separate data, transaction logs, and audit logs into separate physical directories according to Oracle's Optimal Flexible Architecture (OFA). And finally, DBMS software libraries and configuration files also require differing access control lists."
  desc 'check', 'Review the disk/directory specification where database data, transaction log and audit files are stored.

If DBMS data, transaction log or audit data files are stored in the same directory, this is a finding.

If multiple applications are accessing the database and the database data files are stored in the same directory, this is a finding.

If multiple applications are accessing the database and database data is separated into separate physical directories according to application, this check is not a finding.'
  desc 'fix', 'Specify dedicated host system disk directories to store database data, transaction and audit files.

Example directory structure:
/*/app/oracle/oradata/db_name
/*/app/oracle/admin/db_name/arch/*
/*/app/oracle/oradata/db_name/audit
/*/app/oracle/fast_recovery_area/db_name/

When multiple applications are accessing a single database, configure DBMS default file storage according to application to use dedicated disk directories. 

/*/app/oracle/oradata/db_name/app_name

Refer to Oracle Optimal Flexible Architecture:
https://docs.oracle.com/en/database/oracle/oracle-database/19/ladbi/optimal-flexible-architecture.html'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270538'
  tag rid: 'SV-270538r1064892_rule'
  tag stig_id: 'O19C-00-010800'
  tag fix_id: 'F-74472r1064891_fix'
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

  describe 'A manual review is required to ensure the DBMS data files, transaction logs and audit files are stored
    in dedicated directories or disk partitions separate from software or other
    application files' do
    skip 'A manual review is required to ensure the DBMS data files, transaction logs and audit files are stored
    in dedicated directories or disk partitions separate from software or other
    application files'
  end
end
