control 'SV-270527' do
  title 'System privileges granted using the WITH ADMIN OPTION must not be
  granted to unauthorized user accounts.'
  desc "The WITH ADMIN OPTION allows the grantee to grant a privilege to another database account. Best security practice restricts the privilege of assigning privileges to authorized personnel. Authorized personnel include database administrators (DBAs), object owners, and, where designed and included in the application's functions, application administrators. Restricting privilege-granting functions to authorized accounts can help decrease mismanagement of privileges and wrongful assignments to unauthorized accounts."
  desc 'check', "A default Oracle Database installation provides a set of predefined administrative accounts and nonadministrative accounts. These are accounts that have special privileges required to administer areas of the database, such as the CREATE ANY TABLE or ALTER SESSION privilege or EXECUTE privileges on packages owned by the SYS schema. The default tablespace for administrative accounts is either SYSTEM or SYSAUX. Nonadministrative user accounts only have the minimum privileges needed to perform their jobs. Their default tablespace is USERS.

To protect these accounts from unauthorized access, the installation process expires and locks most of these accounts, except where noted below. The database administrator is responsible for unlocking and resetting these accounts, as required.

Nonadministrative Accounts - Expired and locked:
APEX_PUBLIC_USER, DIP, FLOWS_040100*, FLOWS_FILES, MDDATA, SPATIAL_WFS_ADMIN_USR, XS$NULL

Administrative Accounts - Expired and Locked:
ANONYMOUS, CTXSYS, EXFSYS, LBACSYS, MDSYS, OLAPSYS, ORACLE_OCM, ORDDATA, OWBSYS, ORDPLUGINS, ORDSYS, OUTLN, SI_INFORMTN_SCHEMA, SPATIAL_CSW_ADMIN_USR, WK_TEST, WK_SYS, WKPROXY, WMSYS, XDB

Administrative Accounts - Open:
DBSNMP, MGMT_VIEW, SYS, SYSMAN, SYSTEM, SYSKM

*Subject to change based on version installed.

Run the SQL query:

From SQL*Plus:
select grantee, privilege from dba_sys_privs 
where grantee not in (<list of nonapplicable accounts>)
and admin_option = 'YES'
and grantee not in
(select grantee from dba_role_privs where granted_role = 'DBA');

(With respect to the list of special accounts that are excluded from this requirement, it is expected that the DBA will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.)

If any accounts that are not authorized to have the ADMIN OPTION are listed, this is a finding."
  desc 'fix', 'Revoke assignment of privileges with the WITH ADMIN OPTION from unauthorized users and regrant them without the option.

From SQL*Plus:

revoke [privilege name] from user [username];

Replace [privilege name] with the named privilege and [username] with the named user.

Restrict use of the WITH ADMIN OPTION to authorized administrators.

Document authorized privilege assignments with the WITH ADMIN OPTION in the system documentation.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270527'
  tag rid: 'SV-270527r1065266_rule'
  tag stig_id: 'O19C-00-009500'
  tag fix_id: 'F-74461r1064858_fix'
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

  dba_users = sql.query("select grantee from dba_sys_privs
  where admin_option = 'YES' and grantee not in (select grantee from dba_role_privs where granted_role = 'DBA');").column('grantee').uniq
  if dba_users.empty?
    impact 0.0
    describe 'There are no oracle DBA users, control N/A' do
      skip 'There are no oracle DBA users, control N/A'
    end
  else
    dba_users.each do |user|
      describe "oracle DBA users: #{user}" do
        subject { user }
        it { should be_in input('allowed_dbadmin_users') }
      end
    end
  end
end
