control 'SV-270526' do
  title 'The Oracle password file ownership and permissions should be limited and the REMOTE_LOGIN_PASSWORDFILE parameter must be set to EXCLUSIVE or NONE.'
  desc 'It is critically important to the security of the system to protect the password file and the environment variables that identify the location of the password file. Any user with access to these could potentially compromise the security of the connection. 

The REMOTE_LOGIN_PASSWORDFILE setting of "NONE" disallows remote administration of the database. The REMOTE_LOGIN_PASSWORDFILE setting of "EXCLUSIVE" allows for auditing of individual database administrator (DBA) logons to the SYS account. If not set to "EXCLUSIVE", remote connections to the database as "internal" or "as SYSDBA" are not logged to an individual account.'
  desc 'check', "To verify the current status of the REMOTE_LOGIN_PASSWORDFILE parameter: 

If using a non-CDB database:

From SQL*Plus:

select value from v$parameter where upper(name) = 'REMOTE_LOGIN_PASSWORDFILE';

If the value returned does not equal 'EXCLUSIVE' or 'NONE', this is a finding.

If using a CDB database:

From SQL*Plus:

To verify the current status of the remote_login_passwordfile parameter use the SQL statement:

column name format a25
column parameter_value format a25

SELECT name, inst_id, con_id, value AS PARAMETER_VALUE 
FROM sys.gv_$parameter 
WHERE name = 'REMOTE_LOGIN_PASSWORDFILE' 
ORDER BY 1;

In any instance or container, if the PARAMETER_VALUE is set to SHARED, or to a value other than EXCLUSIVE or NONE, that is a finding.

Check the security permissions on password file within the OS.

On Unix Systems:

ls -ld $ORACLE_HOME/dbs/orapw${ORACLE_SID}

Substitute ${ORACLE_SID} with the name of the ORACLE_SID for the database.

If permissions are granted for world access, this is a finding.

On Windows Systems (from Windows Explorer), browse to the %ORACLE_HOME%\\database\\directory.

Select and right-click on the PWD%ORACLE_SID%.ora file, select Properties, then select the Security tab.

Substitute %ORACLE_SID% with the name of the ORACLE_SID for the database.

If permissions are granted to everyone, this is a finding.

If any account other than the database management system (DBMS) software installation account is listed, this is a finding."
  desc 'fix', "Disable use of the REMOTE_LOGIN_PASSWORDFILE where remote administration is not authorized by specifying a value of NONE.

If authorized, restrict use of a password file to exclusive use by each database by specifying a value of EXCLUSIVE.

From SQL*Plus:

alter system set REMOTE_LOGIN_PASSWORDFILE = 'EXCLUSIVE' scope = spfile;

OR

alter system set REMOTE_LOGIN_PASSWORDFILE = 'NONE' scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.

Restrict ownership and permissions on the Oracle password file to exclude world (Unix) or everyone (Windows).

More information regarding the ORAPWD file and the REMOTE_LOGIN_PASSWORDFILE parameter can be found here:
https://docs.oracle.com/en/database/oracle/oracle-database/19/refrn/REMOTE_LOGIN_PASSWORDFILE.html"
  impact 0.5
  tag check_id: 'C-74559r1115965_chk'
  tag severity: 'medium'
  tag gid: 'V-270526'
  tag rid: 'SV-270526r1115966_rule'
  tag stig_id: 'O19C-00-009400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-74460r1115957_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # PORTED FROM 12c V-61431 (overlay #6). REMOTE_LOGIN_PASSWORDFILE must be
  # EXCLUSIVE or NONE. (The OS password-file-permission half of the STIG is
  # host-level and N/A on managed RDS.)
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  value = sql.query("SELECT value FROM v$parameter WHERE upper(name) = 'REMOTE_LOGIN_PASSWORDFILE';").column('value')
  describe 'REMOTE_LOGIN_PASSWORDFILE' do
    subject { value.first.to_s.upcase }
    it { should be_in %w(EXCLUSIVE NONE) }
  end
end
