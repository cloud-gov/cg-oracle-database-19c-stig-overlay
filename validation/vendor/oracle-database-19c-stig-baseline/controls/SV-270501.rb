control 'SV-270501' do
  title 'Oracle Database must protect against an individual who uses a shared account falsely denying having performed a particular action.'
  desc 'Nonrepudiation of actions taken is required to maintain application integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.

Nonrepudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. 

Authentication via shared accounts does not provide individual accountability for actions taken on the database management system (DBMS) or data. Whenever a single database account is used to connect to the database, a secondary authentication method that provides individual accountability is required. This scenario most frequently occurs when an externally hosted application authenticates individual users to the application and the application uses a single account to retrieve or update database information on behalf of the individual users.

When shared accounts are used without another means of identifying individual users, users may deny having performed a particular action.

This calls for inspection of application source code, which requires collaboration with the application developers. In many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', %q(If there are no shared accounts available to more than one user, this is not a finding.

Review database, application, and/or OS settings to determine whether users can be identified as individuals when using shared accounts. 

If the individual user of a shared account cannot be identified, this is a finding.

If Standard Auditing is used:
To ensure user activities other than SELECT, INSERT, UPDATE, and DELETE are also monitored and attributed to individuals, verify that Oracle auditing is enabled. To verify Oracle is configured to capture audit data, enter the following SQL*Plus command:

SHOW PARAMETER AUDIT_TRAIL

Or run the following SQL query:

col display_value format a10
col default_value format a10
SELECT inst_id, con_id, display_value, default_value, isdefault
FROM sys.gv_$parameter WHERE name = 'audit_trail';

If the query returns the display_value "NONE", for any instance or container, this is a finding.

If Unified Auditing is used:
To ensure that user activities other than SELECT, INSERT, UPDATE, and DELETE are also monitored and attributed to individuals, verify that Oracle auditing is enabled. To verify Oracle is configured to capture audit data, enter the following SQL*Plus query:

col value format a10
SELECT inst_id, con_id, value
FROM sys.gv_$option
WHERE parameter = 'Unified Auditing';

If the query returns something other than "TRUE", for any instance or container, this is a finding.)
  desc 'fix', %q(Use accounts assigned to individual users. Configure DBMS to provide individual accountability at the DBMS level, and in audit logs, for actions performed under a shared database account.

Modify applications and data tables that are not capturing individual user identity to do so.

Create and enforce the use of individual user IDs for logging on to Oracle tools and third-party products.

If Oracle auditing is not already enabled, enable it.

If Standard Auditing is used:
If Oracle (or third-party) auditing is not already enabled, enable it. For Oracle auditing, use this query:

ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SID='*' SCOPE=SPFILE;

Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.

After executing this statement, it may be necessary to shut down and restart the Oracle database.

If Unified Auditing is used:
Link the oracle binary with uniaud_on, and then restart the database. Oracle Database Upgrade Guide describes how to enable unified auditing.

For more information on the configuration of auditing, refer to the following documents:

"Auditing Database Activity" in the Oracle Database 19c Security Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/index.html

"Monitoring Database Activity with Auditing" in the Oracle Database Security Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/index.html

"DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/

Oracle Database Upgrade Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/upgrd/index.html

If the site-specific audit requirements are not covered by the default audit options, deploy and configure Fine-Grained Auditing. For details, refer to Oracle documentation at the locations above.

If this level of auditing does not meet site-specific requirements, consider deploying the Oracle Audit Vault. The Audit Vault is a highly configurable option from Oracle made specifically for performing the audit functions. It has reporting capabilities as well as user-defined rules that provide additional flexibility for complex auditing requirements.)
  impact 0.3
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag gid: 'V-270501'
  tag rid: 'SV-270501r1167736_rule'
  tag stig_id: 'O19C-00-001700'
  tag fix_id: 'F-74435r1167447_fix'
  tag cci: ['CCI-000166', 'CCI-004045']
  tag nist: ['AU-10', 'Rev_4', 'IA-2 (5)']
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
  end
end
