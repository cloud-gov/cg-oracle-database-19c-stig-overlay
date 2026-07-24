control 'SV-270525' do
  title 'The Oracle SQL92_SECURITY parameter must be set to TRUE.'
  desc 'The configuration option SQL92_SECURITY specifies whether table-level SELECT privileges are required to execute an update or delete those references table column values. If this option is disabled (set to FALSE), the UPDATE privilege can be used to determine values that should require SELECT privileges.

The SQL92_SECURITY setting of TRUE prevents the exploitation of user credentials with only DELETE or UPDATE privileges on a table from being able to derive column values in that table by performing a series of update/delete statements using a where clause, and rolling back the change. In the following example, with SQL92_SECURITY set to FALSE, a user with only delete privilege on the scott.emp table is able to derive that there is one employee with a salary greater than 3000. With SQL92_SECURITY set to TRUE, that user is prevented from attempting to derive a value.

SQL92_SECURITY = FALSE
SQL> delete from scott.emp where sal > 3000;
1 row deleted
SQL> rollback;
Rollback complete

SQL92_SECURITY = TRUE
SQL> delete from scott.emp where sal > 3000;
delete from scott.emp where sal > 3000
*
ERROR at line 1:
ORA-01031: insufficient privileges'
  desc 'check', "To verify the current status of the SQL92_SECURITY parameter use the SQL statement: 

If using a non-CDB database: 
From SQL*Plus:

select value from v$parameter where name = 'sql92_security';

If using a CDB database:
From SQL*Plus:

column name format a20
column parameter_value format a20

SELECT name, inst_id, con_id, value AS PARAMETER_VALUE 
FROM sys.gv_$parameter 
WHERE name = 'sql92_security' 
ORDER BY 1;

Check Result:

The CDB database and all PDBs must be checked.

If the value returned is set to FALSE, this is a finding.

If the parameter is set to TRUE or does not exist, this is not a finding.

In any instance or container, if the PARAMETER_VALUE is not TRUE, that is a finding."
  desc 'fix', 'Enable SQL92 security.

  From SQL*Plus:

  alter system set sql92_security = TRUE scope = spfile;

  The above SQL*Plus command will set the parameter to take effect at next system
  startup.'
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270525'
  tag rid: 'SV-270525r1112473_rule'
  tag stig_id: 'O19C-00-009300'
  tag fix_id: 'F-74459r1064852_fix'
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

  parameter = sql.query("select value from v$parameter where name = 'sql92_security';").column('value')

  describe 'The oracle database SQL92_SECURITY parameter' do
    subject { parameter }
    it { should cmp 'TRUE' }
  end
end
