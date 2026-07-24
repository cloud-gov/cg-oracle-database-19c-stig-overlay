control 'SV-270557' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'The Oracle external procedure capability provides use of the Oracle process account outside the operation of the database management system (DBMS) process. It can be used to submit and execute applications stored externally from the database under operating system controls. The external procedure process is the subject of frequent and successful attacks as it allows unauthenticated use of the Oracle process account on the operating system. As of Oracle version 11.1, the external procedure agent may be run directly from the database and not require use of the Oracle listener. This reduces the risk of unauthorized access to the procedure from outside of the database process.'
  desc 'check', 'Review the system documentation to determine if the use of the external procedure agent is authorized.

Review the ORACLE_HOME/bin directory or search the ORACLE_BASE path for the executable extproc (Unix) or extproc.exe (Windows).

If external procedure agent is not authorized for use in the system documentation and the executable file does not exist or is restricted, this is not a finding.

If external procedure agent is not authorized for use in the system documentation and the executable file exists and is not restricted, this is a finding.

If use of the external procedure agent is authorized, ensure extproc is restricted to execution of authorized applications.

External jobs are run using the account "nobody" by default.

Review the contents of the file ORACLE_HOME/rdbms/admin/externaljob.ora for the lines run_user= and run_group=.

If the user assigned to these parameters is not "nobody", this is a finding.

The external procedure agent (extproc executable) is available directly from the database and does not require definition in the listener.ora file for use.

Review the contents of the file ORACLE_HOME/hs/admin/extproc.ora.

If the file does not exist, this is a finding.

If the following entry does not appear in the file, this is a finding:

EXTPROC_DLLS=ONLY:[dll full file name1]:[dll full file name2]:..

[dll full file name] represents a full path and file name.

This list of file names is separated by ":".

Note: If "ONLY" is specified, then the list is restricted to allow execution of only the DLLs specified in the list and is not a finding. If "ANY" is specified, then there are no restrictions for execution except what is controlled by operating system permissions and is a finding. If no specification is made, any files located in the %ORACLE_HOME%\\bin directory on Windows systems or $ORACLE_HOME/lib directory on Unix systems can be executed (the default) and is a finding.

Ensure that EXTPROC is not accessible from the listener.

Review the listener.ora file. If any entries reference "extproc", this is a finding.

Determine if the external procedure agent is in use per Oracle 10.x conventions.

Review the listener.ora file.

If any entries reference "extproc", then the agent is in use.

If external procedure agent is not authorized for use in the system documentation and references to "extproc" exist, this is a finding.

Sample listener.ora entries with extproc included:

LISTENER =
(DESCRIPTION =
(ADDRESS = (PROTOCOL = TCP)(HOST = 127.0.0.1)(PORT = 1521))
)
EXTLSNR =
(DESCRIPTION =
(ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC))
)
SID_LIST_LISTENER =
(SID_LIST =
(SID_DESC =
(GLOBAL_DBNAME = ORCL)
(ORACLE_HOME = /home/oracle/app/oracle/product/19.0/db_1)
(SID_NAME = ORCL)
)
)
SID_LIST_EXTLSNR =
(SID_LIST =
(SID_DESC =
(PROGRAM = extproc)
(SID_NAME = PLSExtProc)
(ORACLE_HOME = /home/oracle/app/oracle/product/19.0/db_1)
(ENVS="EXTPROC_DLLS=ONLY:/home/app1/app1lib.so:/home/app2/app2lib.so,
LD_LIBRARY_PATH=/private/app2/lib:/private/app1,
MYPATH=/usr/fso:/usr/local/packages")
)
)

Sample tnsnames.ora entries with extproc included:

ORCL =
(DESCRIPTION =
(ADDRESS_LIST =
(ADDRESS = (PROTOCOL = TCP)(HOST = 127.0.0.1)(PORT = 1521))
)
(CONNECT_DATA =
(SERVICE_NAME = ORCL)
)
)
EXTPROC_CONNECTION_DATA =
(DESCRIPTION =
(ADDRESS_LIST =
(ADDRESS = (PROTOCOL = IPC)(KEY = extproc))
)
(CONNECT_DATA =
(SERVER = DEDICATED)
(SERVICE_NAME = PLSExtProc)
)
)

If EXTPROC is in use, confirm that a listener is dedicated to serving the external procedure agent (as shown above).

View the protocols configured for the listener.

For the listener to be dedicated, the only entries will be to specify extproc.

If there is not a dedicated listener in use for the external procedure agent, this is a finding.

If the PROTOCOL= specified is other than IPC, this is a finding.

Verify and ensure extproc is restricted executing authorized external applications only and extproc is restricted to execution of authorized applications.

Review the listener.ora file.

If the following entry does not exist, this is a finding:

EXTPROC_DLLS=ONLY:[dll full file name1]:[dll full file name2]:...

Note: [dll full file name] represents a full path and file name. This list of file names is separated by ":".

Note: If "ONLY" is specified, then the list is restricted to allow execution of only the DLLs specified in the list and is not a finding. If "ANY" is specified, then there are no restrictions for execution except what is controlled by operating system permissions and is a finding. If no specification is made, any files located in the %ORACLE_HOME%\\bin directory on Windows systems or $ORACLE_HOME/lib directory on Unix systems can be executed (the default) and is a finding.

View the listener.ora file (usually in ORACLE_HOME/network/admin or directory specified by the TNS_ADMIN environment variable).

If multiple listener processes are running, then the listener.ora file for each must be viewed.

For each process, determine the directory specified in the ORACLE_HOME or TNS_ADMIN environment variable defined for the process account to locate the listener.ora file.'
  desc 'fix', 'If use of the external procedure agent is required, then authorize and document the requirement in the system documentation.

If the external procedure agent must be accessible to the Oracle listener, then specify this and authorize it in the system documentation.

If use of the Oracle External Procedure agent is not required:

1. Stop the Oracle Listener process.
2. Remove all references to extproc in the listener.ora and tnsnames.ora files.
3. Alter the permissions on the executable files:
Unix: Remove read/write/execute permissions from owner, group, and world.
Windows: Remove Groups/Users from the executable (except groups SYSTEM and ADMINISTRATORS) and allow READ [only] for SYSTEM and ADMINISTRATORS groups.

If required:

1. Restrict extproc execution to only authorized applications.
2. Specify EXTPROC_DLLS=ONLY: [list of authorized DLLS] in the extproc.ora and the listener.ora files.
3. Create a separate, dedicated listener for use by the external procedure agent.

Refer to the Oracle Net Services Administrators Guides, External Procedures section for detailed configuration information.'
  impact 0.5
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag gid: 'V-270557'
  tag rid: 'SV-270557r1065281_rule'
  tag stig_id: 'O19C-00-013400'
  tag fix_id: 'F-74491r1065280_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/rdbms/admin/externaljob.ora" do
    its('content') { should_not include 'run_user = nobody' }
    its('content') { should_not include 'run_group = nobody' }
  end

  describe file "#{oracle_home}/hs/admin/extproc.ora" do
    it { should exist }
    its('content') { should match /^EXTPROC_DLLS=ONLY:\s*\w*/ }
  end
end
