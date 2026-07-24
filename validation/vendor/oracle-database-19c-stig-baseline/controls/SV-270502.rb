control 'SV-270502' do
  title 'Oracle Database must provide audit record generation capability for organization-defined auditable events within the database.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the database management system (DBMS) (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DOD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful login attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logins from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', %q(Using vendor and system documentation, if necessary, verify the DBMS is configured to use Oracle's auditing features, or that a third-party product or custom code is deployed and configured to satisfy this requirement.

If a third-party product or custom code is used, compare its current configuration with the audit requirements. If any of the requirements is not covered by the configuration, this is a finding.

The remainder of this Check is applicable specifically where Oracle auditing is in use.

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

If the query returns something other than "TRUE", this is a finding.

To confirm Oracle audit is capturing information on the required events, review the contents of the SYS.UNIFIED_AUDIT_TRAIL view.

If auditable events are not listed, this is a finding.)
  desc 'fix', %q(Configure the DBMS's auditing to audit organization-defined auditable events. If preferred, use a third-party tool. The tool must provide the minimum capability to audit the required events.

If using a third-party product, proceed in accordance with the product documentation. If using Oracle's capabilities, proceed as follows.

If Standard Auditing is used:
Use this process to ensure auditable events are captured:

ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SID='*' SCOPE=SPFILE;

Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.

After executing this statement, it may be necessary to shut down and restart the Oracle database.

If the site-specific audit requirements are not covered by the default audit options, deploy and configure Fine-Grained Auditing. For details, refer to Oracle documentation at the locations below.

If Unified Auditing is used:
Use this process to ensure auditable events are captured:

Link the oracle binary with uniaud_on, and then restart the database. Oracle Database Upgrade Guide describes how to enable unified auditing.
For more information on the configuration of auditing, refer to the following documents:

"Auditing Database Activity" in the Oracle Database 2 Day + Security Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/index.html

"Monitoring Database Activity with Auditing" in the Oracle Database Security Guide: 
https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/index.html

"DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/

Oracle Database Upgrade Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/upgrd/index.html

If the site-specific audit requirements are not covered by the default audit options, deploy and configure Fine-Grained Auditing. For details, refer to Oracle documentation at the locations above.)
  impact 0.5
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag gid: 'V-270502'
  tag rid: 'SV-270502r1167738_rule'
  tag stig_id: 'O19C-00-001800'
  tag fix_id: 'F-74436r1167450_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a', 'Rev_4']
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

  standard_auditing_used = input('standard_auditing_used')
  unified_auditing_used = input('unified_auditing_used')

  describe.one do
    describe 'Standard auditing is in use for audit purposes' do
      subject { standard_auditing_used }
      it { should be true }
    end

    describe 'Unified auditing is in use for audit purposes' do
      subject { unified_auditing_used }
      it { should be true }
    end
  end

  audit_trail = sql.query("select value from v$parameter where name = 'audit_trail';").column('value')
  audit_info_captured = sql.query('SELECT EVENT_TIMESTAMP FROM UNIFIED_AUDIT_TRAIL ORDER BY EVENT_TIMESTAMP DESC FETCH FIRST 10 ROWS ONLY;').column('event_timestamp')

  if standard_auditing_used
    describe 'The oracle database audit_trail parameter' do
      subject { audit_trail }
      it { should_not cmp 'NONE' }
    end
  end

  unified_auditing = sql.query("SELECT value FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';").column('value')

  if unified_auditing_used
    describe 'The oracle database unified auditing parameter' do
      subject { unified_auditing }
      it { should_not cmp 'FALSE' }
    end

    describe 'The oracle database unified auditing events captured' do
      subject { audit_info_captured }
      it { should_not be_empty }
    end

  end
end
