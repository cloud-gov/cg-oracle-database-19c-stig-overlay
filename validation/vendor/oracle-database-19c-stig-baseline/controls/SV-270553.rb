control 'SV-270553' do
  title 'Unused database components, database management system (DBMS) software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plug-ins not related to requirements or providing a wide array of functionality not required for the mission.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the database management system (DBMS) and host system.

Unused and unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.'
  desc 'check', "Run this query to produce a list of components and features installed with the database:

SELECT comp_id, comp_name, version, status from dba_registry
WHERE comp_id not in ('CATJAVA','CATALOG','CATPROC','SDO','DV','XDB')
AND status <> 'OPTION OFF';

Review the list. If unused components are installed and are not documented and authorized, this is a finding."
  desc 'fix', 'If any components are required for operation of applications that will be accessing the DBMS, include them in the system documentation.

Components cannot be removed via Database Configuration Assistant (DBCA) or manually once the database has been created, either from a container or a noncontainer database.

However DBCA can be used to create a noncontainer database and remove components during the creation process before the database is created.

When using DBCA to create a custom noncontainer database, select:
creation mode = advanced
Database Template = Custom
Database Options..Database Component

Components that can be selected or deselected are Oracle JVM, Oracle Text, Oracle Multimedia, Oracle OLAP, Oracle Spatial, Oracle Label Security, Oracle Application Express, and Oracle Database Vault.

For a container database (CDB), the CDB$ROOT must have all possible database components available. When a pluggable database (PDB) is plugged into the CDB, the CDB must have the same components installed as the PDB. Since it is unknown what components the PDBS may have, the CDB must be able to support all possible PDB configurations.

Components installed in the CDB$ROOT do not need to be licensed. Components are only considered to be used if they are installed in the PDB.

To configure a PDB to only use specific components:

1. Create a non-CDB 19.0 database and configure that database with the components desired.

2. Plug the non-CDB database into a CDB database, creating a new PDB. Then if desired, create additional clones from the new PDB.'
  impact 0.5
  tag check_id: 'C-74586r1064935_chk'
  tag severity: 'medium'
  tag gid: 'V-270553'
  tag rid: 'SV-270553r1064937_rule'
  tag stig_id: 'O19C-00-013000'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-74487r1064936_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # PORTED FROM 12c V-61679 (overlay #6). Installed DB components must be among
  # the authorized set.
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  comps = sql.query("SELECT comp_name FROM dba_registry;").column('comp_name').uniq
  if comps.empty?
    describe 'No optional DB components installed' do
      subject { comps }
      it { should be_empty }
    end
  else
    comps.each do |c|
      describe "Installed DB component #{c}" do
        subject { c }
        it { should be_in input('allowed_oracledb_components') }
      end
    end
  end
end
