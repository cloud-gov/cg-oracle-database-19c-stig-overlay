control 'SV-270504' do
  title 'Oracle Database must generate audit records for the DOD-selected list of auditable events, when successfully accessed, added, modified, or deleted, to the extent such information is available.'
  desc 'Audit records can be generated from various components within the information system, such as network interfaces, hard disks, modems, etc. From an application perspective, certain specific application functionalities may be audited, as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked).

Organizations may define the organizational personnel accountable for determining which application components must provide auditable events.

Auditing provides accountability for changes made to the database management system (DBMS) configuration or its objects and data. It provides a means to discover suspicious activity and unauthorized changes. Without auditing, a compromise may go undetected and without a means to determine accountability.

The Department of Defense has established the following as the minimum set of auditable events:
- When privileges/permissions are retrieved, added, modified or deleted.
- When unsuccessful attempts to retrieve, add, modify, delete privileges/permissions occur.
- Enforcement of access restrictions associated with changes to the configuration of the database(s).
- When security objects are accessed, modified, or deleted.
- When unsuccessful attempts to access, modify, or delete security objects occur.
- When categories of information (e.g., classification levels/security levels) are accessed, created, modified, or deleted.
- When unsuccessful attempts to access, create, modify, or delete categorized information occur.
- All privileged activities or other system-level access.
- When unsuccessful attempts to execute privileged activities or other system-level access occurs.
- When successful or unsuccessful access to any other objects occur as specifically defined by the site.

'
  desc 'check', %q(Check Oracle Database settings to determine if auditing is being performed on the DOD-required list of auditable events supplied in the discussion.

If Standard Auditing is used:
To verify Oracle is configured to capture audit data, enter the following SQL*Plus command:

SHOW PARAMETER AUDIT_TRAIL

Or the following SQL query:

col display_value format a10
col default_value format a10
SELECT inst_id, con_id, display_value, default_value, isdefault
FROM sys.gv_$parameter WHERE name = 'audit_trail';

If Oracle returns the value "NONE", this is a finding.

To confirm Oracle audit is capturing information on the required events, review the contents of the SYS.AUD$ table or the audit file, whichever is in use. If auditable events are not listed, this is a finding.

If Unified Auditing is used:
To verify Oracle is configured to capture audit data, enter the following SQL*Plus command:

col value format a10
SELECT inst_id, con_id, value
FROM sys.gv_$option
WHERE parameter = 'Unified Auditing';

If Oracle returns a value something other than "TRUE", this is a finding.

Unified Audit supports named audit policies, which are defined using the CREATE AUDIT POLICY statement. A policy specifies the actions that should be audited and the objects to which it should apply. If no specific objects are included in the policy definition, it applies to all objects.

A named policy is enabled using the AUDIT POLICY statement. It can be enabled for all users, for specific users only, or for all except a specified list of users. The policy can audit successful actions, unsuccessful actions, or both.

Verifying existing audit policy: existing Unified Audit policies are listed in the view AUDIT_UNIFIED_POLICIES. The AUDIT_OPTION column contains one of the actions specified in a CREATE AUDIT POLICY statement. The AUDIT_OPTION_TYPE column contains "STANDARD ACTION" for a policy that applies to all objects or "OBJECT ACTION" for a policy that audits actions on a specific object.

SELECT policy_name
FROM sys.audit_unified_policies
WHERE audit_option = 'GRANT'
AND audit_option_type= 'STANDARD ACTION';


To find policies that audit privilege grants on specific objects:

col policy_name format a20
col object_schema format a20
col object_name format a30
SELECT policy_name, object_schema, object_name 
FROM sys.audit_unified_policies 
WHERE audit_option = 'GRANT'
AND audit_option_type = 'OBJECT ACTION';


The view AUDIT_UNIFIED_ENABLED_POLICIES shows which Unified Audit policies are enabled. The ENABLED_OPT and USER_NAME columns show the users for whom the policy is enabled or "ALL USERS". The SUCCESS and FAILURE columns indicate if the policy is enabled for successful or unsuccessful actions, respectively.

col entity_name format a30
SELECT policy_name, enabled_option, entity_name, success, failure
FROM sys.audit_unified_enabled_policies;

If auditing is not being performed for all the events listed above, this is a finding.)
  desc 'fix', "Both Standard and Unified Auditing are allowed in Oracle Database 19c.
The default is mixed auditing mode.
The predefined policy ORA_SECURECONFIG is enabled by default in mixed mode.

Configure the DBMS's auditing settings to include auditing of events on the DOD-selected list of auditable events.

1. Successful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels).

To audit granting and revocation of any privilege:
CREATE AUDIT POLICY <policy_name> ACTIONS GRANT;
CREATE AUDIT POLICY <policy_name> ACTIONS REVOKE;

To audit grants of object privileges on a specific object:
CREATE AUDIT POLICY <policy_name> ACTIONS GRANT ON <schema>.<object>;

If Oracle Label Security is enabled, this will audit all OLS administrative actions:
CREATE AUDIT POLICY <policy_name> ACTIONS COMPONENT = OLS ALL;

2. Successful and unsuccessful logon attempts, privileged activities or other system-level access.
 
To audit all user logon attempts:
CREATE AUDIT POLICY <policy_name> ACTIONS LOGON;

To audit only logon attempts using administrative privileges (e.g., AS SYSDBA):
AUDIT POLICY <policy_name> BY sys, sysoper, sysbackup, sysdg, syskm;

3. Starting and ending time for user access to the system, concurrent logons from different workstations.

This policy will audit all logon and logoff events. An individual session is identified in the UNIFIED_AUDIT_TRAIL by the tuple (DBID, INSTANCE_ID, SESSIONID) and the start and end time will be indicated by the EVENT_TIMESTAMP of the logon and logoff events:

CREATE AUDIT POLICY <policy_name> ACTIONS logon, logoff;

4. Successful and unsuccessful accesses to objects.

To audit all accesses to a specific table:
CREATE AUDIT POLICY <policy_name> ACTIONS select, insert, delete, alter ON <schema>.<object>; 

Different actions are defined for other object types. To audit all supported actions on a specific object:
CREATE AUDIT POLICY <policy_name> ACTIONS all ON <schema>.<object>;
 
5. All program initiations.

To audit execution of any PL/SQL program unit:
CREATE AUDIT POLICY <policy_name> ACTIONS execute;

To audit execution of a specific function, procedure, or package:
CREATE AUDIT POLICY <policy_name> ACTIONS execute ON <schema>.<object>;

6. All direct access to the information system.
[Not applicable to Database audit. Monitor using OS auditing.]

7. All account creations, modifications, disabling, and terminations.

To audit all user administration actions:
CREATE AUDIT POLICY <policy_name> actions create user, alter user, drop user, change password;

8. All kernel module loads, unloads, and restarts.
[Not applicable to Database audit. Monitor using OS auditing.]
 
9. All database parameter changes.

To audit any database parameter changes, dynamic or static:
CREATE AUDIT POLICY <policy_name> ACTIONS alter database, alter system, create spfile;

Applying the Policy:

The following command will enable the policy in all database sessions and audit both successful and unsuccessful actions:
AUDIT POLICY <policy_name>;

To audit only unsuccessful actions, add the WHENEVER NOT SUCCESSFUL modifier:
AUDIT POLICY <policy_name> WHENEVER NOT SUCCESSFUL;

Either command above can be limited to only database sessions started by a specific user as follows:
AUDIT POLICY <policy_name> BY <user>;
AUDIT POLICY <policy_name> BY <user> WHENEVER NOT SUCCESSFUL;"
  impact 0.5
  tag check_id: 'C-74537r1167739_chk'
  tag severity: 'medium'
  tag gid: 'V-270504'
  tag rid: 'SV-270504r1167741_rule'
  tag stig_id: 'O19C-00-002000'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-74438r1167740_fix'
  tag satisfies: ['SRG-APP-000091-DB-000066', 'SRG-APP-000091-DB-000325', 'SRG-APP-000492-DB-000333', 'SRG-APP-000494-DB-000344', 'SRG-APP-000494-DB-000345', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000498-DB-000346', 'SRG-APP-000498-DB-000347', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000502-DB-000348', 'SRG-APP-000502-DB-000349', 'SRG-APP-000503-DB-000350', 'SRG-APP-000503-DB-000351', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355', 'SRG-APP-000505-DB-000352', 'SRG-APP-000506-DB-000353', 'SRG-APP-000507-DB-000357', 'SRG-APP-000508-DB-000358']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  # PORTED FROM 12c V-61625 (overlay #6). Audit-record generation capability:
  # auditing must be enabled (unified auditing or audit_trail != NONE).
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  unified = sql.query("SELECT value FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';").column('value')
  audit_trail = sql.query("SELECT value FROM v$parameter WHERE name = 'audit_trail';").column('value')
  describe.one do
    describe 'Unified Auditing enabled' do
      subject { unified.first.to_s.upcase }
      it { should eq 'TRUE' }
    end
    describe 'audit_trail parameter' do
      subject { audit_trail.first.to_s.upcase }
      it { should_not eq 'NONE' }
    end
  end
end
