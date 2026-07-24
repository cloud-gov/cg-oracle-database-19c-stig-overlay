control 'SV-270523' do
  title 'The Oracle WITH GRANT OPTION privilege must be limited when granted to nondatabase administrator (DBA) or nonapplication administrator user accounts.'
  desc 'Specifying WITH GRANT OPTION enables the grantee to grant the object privileges to other users and roles. An account permission to grant privileges within the database is an administrative function. Minimizing the number and privileges of administrative accounts reduces the chances of privileged account exploitation. Application user accounts limit WITH GRANT OPTION privileges since, by definition, they require only privileges to execute procedures or view/edit data.'
  desc 'check', "Execute the query:

select grantee||': '||owner||'.'||table_name
from dba_tab_privs 
where grantable = 'YES' 
and grantee not in (select distinct owner from dba_objects)
and grantee not in (select grantee from dba_role_privs where granted_role = 'DBA')
and table_name not like 'SYS_PLSQL_%'
order by grantee;

If any accounts are listed, verify accounts are documented and approved for the WITH GRANT option.
If non-DBA interactive user or application accounts have WITH GRANT without being documented and approved, this is a finding."
  desc 'fix', 'Revoke privileges granted the WITH GRANT OPTION from non-DBA and accounts that do not own application objects or document the need for WITH GRANT OPTION and get approval.

Re-grant privileges without specifying WITH GRANT OPTION.

Note: Do not revoke the system-generated grants such as those found on SYS_PLSQL_% objects. They are system generated object types (aka ShadowTypes), created internally by Oracle when using the Pipelined Table Functions. This can result in (incorrect) compilation failures and/or invalidations when the users who are supposed to have access to the shadow types find themselves without access.'
  impact 0.5
  tag check_id: 'C-74556r1167460_chk'
  tag severity: 'medium'
  tag gid: 'V-270523'
  tag rid: 'SV-270523r1167746_rule'
  tag stig_id: 'O19C-00-009000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-74457r1167745_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # PORTED FROM 12c V-61421 (overlay #6). WITH GRANT OPTION must be limited to
  # DBA/app-admin accounts. (19c adds the SYS_PLSQL_% exclusion.)
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  rows = sql.query(%{
    SELECT grantee||': '||owner||'.'||table_name AS ent FROM dba_tab_privs
    WHERE grantable = 'YES'
      AND grantee NOT IN (SELECT DISTINCT owner FROM dba_objects)
      AND grantee NOT IN (SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA')
      AND table_name NOT LIKE 'SYS_PLSQL_%'
    ORDER BY grantee
  }).column('ent')
  describe 'Non-admin grants WITH GRANT OPTION' do
    subject { rows }
    it { should be_empty }
  end
end
