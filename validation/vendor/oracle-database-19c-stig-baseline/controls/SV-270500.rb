control 'SV-270500' do
  title 'Oracle Database must enforce approved authorizations for logical access to the system in accordance with applicable policy.'
  desc 'Authentication with a DOD-approved public key infrastructure (PKI) certificate does not necessarily imply authorization to access the database management system (DBMS). To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', %q(Check DBMS settings to determine whether users are restricted from accessing objects and data they are not authorized to access. If appropriate access controls are not implemented to restrict access to authorized users and to restrict the access of those users to objects and data they are authorized to verify, this is a finding.

One option to isolate access is by using the Oracle Database Vault. To check to verify the Oracle Database Vault is installed, issue the following query:

SQL> SELECT * FROM sys.v_$option WHERE parameter = 'Oracle Database Vault';

If Oracle Database Vault is installed, review its settings for appropriateness and completeness of the access it permits and denies to each type of user. If appropriate and complete, this is not a finding.

If Oracle Database Vault is not installed, review the roles and profiles in the database and the assignment of users to these for appropriateness and completeness of the access permitted and denied each type of user. If appropriate and complete, this is not a finding.

If the access permitted and denied each type of user is inappropriate or incomplete, this is a finding.

Following are code examples for reviewing roles, profiles, etc.

Find out what role the users have:

select * from sys.cdb_role_privs where granted_role = '<role>'

List all roles given to a user:

select * from sys.cba_role_privs where grantee = '<username>';

List all roles for all users:

column grantee format a32
column granted_role format a32
break on grantee

SELECT con_id, grantee, granted_role
FROM sys.cdb_role_privs
ORDER BY 1,2,3;

Use the following query to list all privileges given to a user:

SELECT LPAD(' ', 2*level) || granted_role "User roles and privileges"
FROM (
/* THE USERS */
SELECT con_id, NULL AS grantee, username granted_role
FROM sys.cdb_users
WHERE username LIKE UPPER('<enter_username>')
/* THE ROLES TO ROLES RELATIONS */
UNION SELECT con_id, grantee, granted_role
FROM sys.cdb_role_privs
/* THE ROLES TO PRIVILEGE RELATIONS */
UNION
SELECT con_id, grantee, privilege
FROM sys.cdb_sys_privs)
START WITH grantee IS NULL
CONNECT BY grantee = PRIOR granted_role;

List which tables a certain role gives SELECT and READ access to using the query:

SELECT * FROM sys.role_tab_privs WHERE role = '<role>'
AND privilege IN ('READ', 'SELECT');

List all tables a user can SELECT and READ from using the query:

SELECT * FROM sys.cdb_tab_privs
WHERE grantee ='<username>' AND privilege IN ('READ', 'SELECT');

List all users who can SELECT on a particular table (either through being given a relevant role or through a direct grant, e.g., grant select on a table to Joe). The result of this query should also show through which role the user has this access or whether it was a direct grant.

SELECT grantee,'Granted Through Role' as Grant_Type, role, table_name
FROM CONTAINERS(sys.role_tab_privs) rtp, sys.cdb_role_privs crp
WHERE rtp.role = crp.granted_role
AND rtp.con_id = crp.con_id
AND table_name = '<TABLENAME>'
UNION
SELECT grantee, 'Direct Grant' as Grant_Type, NULL AS role, table_name
FROM sys.cdb_tab_privs
WHERE table_name = '<TABLENAME>';)
  desc 'fix', "If Oracle Database Vault is in use, use it to configure the correct access privileges for each type of user.

If Oracle Database Vault is not in use, configure the correct access privileges for each type of user using Roles and Profiles.

Oracle recommends using Database Vault.

For more information on the configuration of Database Vault, refer to the Database Vault Administrator's Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/dvadm/database-vault-administrators-guide.pdf."
  impact 0.7
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag gid: 'V-270500'
  tag rid: 'SV-270500r1167734_rule'
  tag stig_id: 'O19C-00-001000'
  tag fix_id: 'F-74434r1167444_fix'
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'Rev_4', 'AC-6 (10)']
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

  describe 'A manual review is required to ensure the DBMS enforces approved authorizations for logical access to
    the system in accordance with applicable policy' do
    skip 'A manual review is required to ensure the DBMS enforces approved authorizations for logical access to
    the system in accordance with applicable policy'
  end
end
