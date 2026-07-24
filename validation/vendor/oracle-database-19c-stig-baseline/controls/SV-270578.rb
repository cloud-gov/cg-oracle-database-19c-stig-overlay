control 'SV-270578' do
  title 'Access to Oracle Database files must be limited to relevant processes and to authorized, administrative users.'
  desc 'Applications, including database management systems (DBMSs), must prevent unauthorized and unintended information transfer via shared system resources. Permitting only DBMS processes and authorized, administrative users to have access to the files where the database resides helps ensure that those files are not shared inappropriately and are not open to backdoor access and manipulation.'
  desc 'check', 'Review the permissions granted to users by the operating system/file system on the database files, database log files, and database backup files.

On Unix Systems:

  ls -ld [pathname]

Substitute [pathname] with the directory path where the database files, logs, and database backup files are located.
(examples: /*/app/oracle/oradata/db_name, /*/app/oracle/oradata/db_name/audit, and /*/app/oracle/fast_recovery_area/db_name) 

If permissions are granted for world access, this is a finding.

If any user/role who is not an authorized system administrator with a need to know or database administrator with a need to know, or a system account for running DBMS processes, is permitted to read/view any of these files, this is a finding.

On Windows Systems (from Windows Explorer):

Browse to the directory specified (example: %ORACLE_BASE%\\oradata and %ORACLE_BASE%\\fast_recovery_area). Select and right-click on the directory >> Properties >> Security tab. On Windows hosts, records are also written to the Windows application event log. The location of the application event log is listed under Properties for the log under the Windows console. The default location is C:\\WINDOWS\\system32\\config\\EventLogs\\AppEvent.Evt.

Select and right-click on the directory >> Properties >> Security tab.

If permissions are granted to everyone, this is a finding.

If any user/role who is not an authorized system administrator with a need to know or database administrator with a need to know, or a system account for running DBMS processes permitted to read/view any of these files, this is a finding.'
  desc 'fix', 'Configure the permissions of the database files, database log files, and database backup files so that only relevant system accounts and authorized system administrators and database administrators with a need to know are permitted to read/view these files.'
  impact 0.5
  tag check_id: 'C-74611r1115959_chk'
  tag severity: 'medium'
  tag gid: 'V-270578'
  tag rid: 'SV-270578r1137658_rule'
  tag stig_id: 'O19C-00-017600'
  tag gtitle: 'SRG-APP-000243-DB-000374'
  tag fix_id: 'F-74512r1065011_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  # OVERLAY-ADDED (NOT-APPLICABLE-RDS, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'N/A on AWS RDS: OS/filesystem permissions on datafiles/logs; no host access on managed RDS' do
    skip 'N/A on AWS RDS: OS/filesystem permissions on datafiles/logs; no host access on managed RDS'
  end
end
