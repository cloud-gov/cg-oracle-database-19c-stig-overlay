control 'SV-270519' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be restricted to authorized users.'
  desc 'If the database management system (DBMS) were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', "Review accounts for direct assignment of administrative privileges. Connected as SYSDBA, run the query:

SELECT grantee, privilege
FROM dba_sys_privs
WHERE grantee IN 
(
SELECT username
FROM dba_users
WHERE username NOT IN 
(
'XDB', 'SYSTEM', 'SYS', 'LBACSYS',
'DVSYS', 'DVF', 'SYSMAN_RO',
'SYSMAN_BIPLATFORM', 'SYSMAN_MDS',
'SYSMAN_OPSS', 'SYSMAN_STB', 'DBSNMP',
'SYSMAN', 'APEX_040200', 'WMSYS',
'SYSDG', 'SYSBACKUP', 'SPATIAL_WFS_ADMIN_USR',
'SPATIAL_CSW_ADMIN_US', 'GSMCATUSER',
'OLAPSYS', 'SI_INFORMTN_SCHEMA',
'OUTLN', 'ORDSYS', 'ORDDATA', 'OJVMSYS',
'ORACLE_OCM', 'MDSYS', 'ORDPLUGINS',
'GSMADMIN_INTERNAL', 'MDDATA', 'FLOWS_FILES',
'DIP', 'CTXSYS', 'AUDSYS',
'APPQOSSYS', 'APEX_PUBLIC_USER', 'ANONYMOUS',
'SPATIAL_CSW_ADMIN_USR', 'SYSKM',
'SYSMAN_TYPES', 'MGMT_VIEW',
'EUS_ENGINE_USER', 'EXFSYS', 'SYSMAN_APM'
)
)
AND privilege NOT IN ('UNLIMITED TABLESPACE'
, 'REFERENCES', 'INDEX', 'SYSDBA', 'SYSOPER', 'CREATE SESSION'
)
ORDER BY 1, 2;

If any administrative privileges have been assigned directly to a database account, this is a finding.

The list of special accounts that are excluded from this requirement may not be complete. It is expected that the database administrator (DBA) will edit the list to suit local circumstances, adding other special accounts as necessary, and removing any that are not supposed to be in use in the Oracle deployment that is under review."
  desc 'fix', 'Create roles for administrative function assignments. Assign the necessary privileges for the administrative functions to a role. Do not assign administrative privileges directly to users, except for those that Oracle does not permit to be assigned via roles.'
  impact 0.5
  tag check_id: 'C-74552r1112462_chk'
  tag severity: 'medium'
  tag gid: 'V-270519'
  tag rid: 'SV-270519r1112463_rule'
  tag stig_id: 'O19C-00-008300'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-74453r1064834_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  # PORTED FROM 12c V-61591 (overlay #6). System privileges granted directly to
  # non-admin users must be limited. NOTE: 19c title references DB-structure
  # roles but the check SQL follows V-61591's direct-sys-priv query; confirm
  # against DISA V1R5 text.
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  grantees = sql.query(%{
    SELECT grantee FROM dba_sys_privs
    WHERE grantee IN (SELECT username FROM dba_users)
      AND privilege NOT IN ('UNLIMITED TABLESPACE','REFERENCES','INDEX','SYSDBA','SYSOPER')
  }).column('grantee').uniq
  grantees = grantees - input('allowed_users_with_admin_privs')
  describe 'Non-admin users with directly-granted system privileges (excluding allow-list)' do
    subject { grantees }
    it { should be_empty }
  end
end
