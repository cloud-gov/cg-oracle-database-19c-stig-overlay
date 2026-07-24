control 'SV-270506' do
  title 'Oracle Database must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "To ensure sufficient storage capacity for the audit logs, Oracle Database must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of the database management system (DBMS) and is closely associated with the database administrator (DBA) and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on the DBMS's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', "Review the DBMS settings to determine whether audit logging is configured to produce logs consistent with the amount of space allocated for logging. If auditing will generate excessive logs so that they may outgrow the space reserved for logging, this is a finding.

If file-based auditing is in use, check that sufficient space is available to support the file(s). If not, this is a finding.

If standard, table-based auditing is used, the audit logs are written to a table called AUD$; and if a Virtual Private Database is deployed, a table is created called FGA_LOG$. 

sqlplus connect as sysdba

SELECT table_name, tablespace_name
FROM dba_tables
WHERE table_name IN ('AUD$')
ORDER BY table_name;

TABLE_NAME                     TABLESPACE_NAME
-----------------------------  ------------------------------
AUD$                           SYSTEM

The AUD$ table should be in its own tablespace. If the tablespace name is SYSTEM, this is a finding.

Check the current location of the audit trail tables:

SELECT inst_id, con_id, name, value
FROM sys.gv_$parameter
WHERE name IN ('audit_file_dest', 'unified_audit_systemlog');

Verify adequate space is allocated for the audit trail location.

If Unified Auditing is used:

Audit logs are written to tables in the AUDSYS schema. The default tablespace for AUDSYS is USERS, and it should be in its own tablespace.
 
If the tablespace name is USERS, this is a finding. 

Investigate whether there have been any incidents where the DBMS ran out of audit log space since the last time the space was allocated or other corrective measures were taken. If there have been, this is a finding."
  desc 'fix', "Allocate sufficient audit file/table space to support peak demand.

If audit records are being written to the table sys.aud$, create a new tablespace dedicated to the AUD$ table and move AUD$ using the statement below:

exec sys.dbms_audit_mgmt.move_dbaudit_tables('<tablespace_name>');

Ensure that audit tables are in their own tablespaces and that the tablespaces have enough room for the volume of log data that will be produced.

Detailed procedures for how to alter the tablespace for audit logs can be found here:
https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/ALTER-TABLESPACE.html."
  impact 0.5
  tag check_id: 'C-74539r1167743_chk'
  tag severity: 'medium'
  tag gid: 'V-270506'
  tag rid: 'SV-270506r1167744_rule'
  tag stig_id: 'O19C-00-005700'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-74440r1167458_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'audit storage capacity is an operational/monitoring review' do
    skip 'audit storage capacity is an operational/monitoring review'
  end
end
