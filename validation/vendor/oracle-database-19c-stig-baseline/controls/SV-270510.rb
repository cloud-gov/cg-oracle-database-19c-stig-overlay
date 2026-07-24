control 'SV-270510' do
  title 'The audit information produced by the Oracle Database must be protected from unauthorized access, modification, or deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions using file system protections and limiting log data location.

Additionally, applications with user interfaces to audit records must not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Modification or deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.

'
  desc 'check', %q(Review locations of audit logs, both internal to the database and database audit logs located at the operating system level. Verify there are appropriate controls and permissions to protect the audit information from unauthorized access.

If appropriate controls and permissions do not exist, this is a finding.

- - - - -
From SQL*Plus or SQL Developer:

select value from v$parameter where name = 'audit_trail';
select value from v$parameter where name = 'audit_file_dest';

If audit_trail is set to OS, XML or XML EXTENDED, this means logs are stored at the operating system level.

If audit_trail is set to OS, but the audit records are routed directly to a separate log server without writing to the local file system, this is not a finding.

If audit_trail is set to DB or "DB, EXTENDED" this means logs are stored in the database.

If any logs are written to the database, DBA_TAB_PRIVS describes all object grants in the database. 

If standard auditing is in use, follow the below, check permissions on the AUD$ table. 

sqlplus connect as sysdba;

SQL> SELECT GRANTEE, TABLE_NAME, PRIVILEGE
FROM DBA_TAB_PRIVS where table_name = 'AUD$';

If Unified Auditing is used, check permissions on the AUDSYS tables.

sqlplus connect as sysdba;

SQL> SELECT GRANTEE, TABLE_NAME, PRIVILEGE
FROM DBA_TAB_PRIVS where owner='AUDSYS';

If appropriate controls and permissions are not implemented, this is a finding.

If audit logs located at the operating system level:
On Unix Systems:

  ls -ld [pathname]

Substitute [pathname] with the directory paths listed from the above SQL statements for audit_file_dest.

If permissions are granted for world access, this is a finding.

If any groups that include members other than software owner accounts, DBAs, auditors, oracle processes, or any account not listed as authorized, this is a finding.

On Windows Systems (from Windows Explorer):

Browse to the directory specified. Select and right-click on the directory >> Properties >> Security tab. On Windows hosts, records are also written to the Windows application event log. The location of the application event log is listed under Properties for the log under the Windows console. The default location is C:\WINDOWS\system32\config\EventLogs\AppEvent.Evt.

Select and right-click on the directory >> Properties >> Security tab.

If permissions are granted to everyone, this is a finding.

If any accounts other than the administrators, software owner accounts, DBAs, auditors, Oracle processes, or any account not listed as authorized, this is a finding.

Compare path to %ORACLE_HOME%. If audit_file_dest is a subdirectory of %ORACLE_HOME%, this is a finding.)
  desc 'fix', 'Add controls and modify permissions to protect database audit log data from unauthorized modification, whether stored in the database itself or at the OS level.

Logs are stored in the database:
For Standard Auditing, Revoke access to the AUD$ table to anyone who should not have access to it.
For Unified Auditing, Revoke access to the tables with AUDSYS as the owner.

Use the REVOKE statement to remove permissions from a specific user or from all users to perform actions on database objects.

REVOKE privilege-type ON [ TABLE ] { table-Name | view-Name } FROM grantees

Use the ALL PRIVILEGES privilege type to revoke all of the permissions from the user for the specified table. Can also revoke one or more table privileges by specifying a privilege-list.

Use the DELETE privilege type to revoke permission to delete rows from the specified table.

Use the INSERT privilege type to revoke permission to insert rows into the specified table.

Use the REFERENCES privilege type to revoke permission to create a foreign key reference to the specified table. If a column list is specified with the REFERENCES privilege, the permission is revoked on only the foreign key reference to the specified columns.

Use the SELECT privilege type to revoke permission to perform SELECT statements on a table or view. If a column list is specified with the SELECT privilege, the permission is revoked on only those columns. If no column list is specified, then the privilege is valid on all of the columns in the table.

Use the TRIGGER privilege type to revoke permission to create a trigger on the specified table.

Use the UPDATE privilege type to revoke permission to use the UPDATE statement on the specified table. If a column list is specified, the permission is revoked only on the specified columns.

For file-based/OS level auditing, establish an audit file directory separate from the Oracle Home.

Alter host system permissions to the AUDIT_FILE_DEST directory to the Oracle process and software owner accounts, DBAs, backup accounts, SAs (if required), and auditors.

Authorize and document user access requirements to the directory outside of the Oracle, DBA, and SA account list in the system documentation.'
  impact 0.5
  tag check_id: 'C-74543r1068293_chk'
  tag severity: 'medium'
  tag gid: 'V-270510'
  tag rid: 'SV-270510r1068294_rule'
  tag stig_id: 'O19C-00-006600'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-74444r1064807_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  # PORTED FROM 12c V-61653 (overlay #6). AUDSYS object privileges must only be
  # granted to authorized audit users (protect audit data).
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  grantees = sql.query("SELECT GRANTEE FROM DBA_TAB_PRIVS WHERE owner='AUDSYS';").column('grantee').uniq
  if grantees.empty?
    describe 'No AUDSYS object-privilege grantees' do
      subject { grantees }
      it { should be_empty }
    end
  else
    grantees.each do |g|
      describe "AUDSYS object-privilege grantee #{g}" do
        subject { g }
        it { should be_in input('allowed_audit_users') }
      end
    end
  end
end
