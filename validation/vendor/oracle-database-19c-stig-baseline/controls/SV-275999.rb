control 'SV-275999' do
  title 'A minimum of three Oracle Control Files must be created and each stored on a separate physical and logical device.'
  desc 'Oracle control files store information critical to Oracle database integrity. Oracle uses these files to maintain time synchronization of database files and verify the validity of system data and log files at system startup. Loss of access to the control files can affect database availability, integrity, and recovery.

Oracle Pluggable Databases (PDBs) do not contain their own control files; instead, all PDBs within a Container Database (CDB) share control files managed by the CDB.'
  desc 'check', 'Use the SQL statement below to obtain information on each currently existing Control File:

SELECT name
FROM sys.v$controlfile
ORDER BY 1;

Oracle Best Practice:
Oracle recommends a minimum of three Oracle Control Files and each stored on a separate physical and logical device (RAID 1 + 0).  

DOD guidance recommends:
Each control file must be located on a separate physical and logical (virtual) storage device.

Consult with the storage administrator, system administrator, or database administrator to determine whether the mount points or partitions referenced in the file paths indicate separate physical disks or directories on RAID devices.

Note: Distinct does not equal dedicated. May share directory space with other Oracle database instances if present.

If the minimum of three control files is not met, this is a finding.'
  desc 'fix', "To prevent loss of service during disk failure, multiple copies of Oracle control files must be maintained on separate disks in archived directories or on separate, archived directories within one or more RAID devices.

Adding or moving a control file requires careful planning and execution.

Consult and follow the instructions for creating control files in the Oracle Database Administrator's Guide, under Steps for Creating New Control Files."
  impact 0.5
  tag check_id: 'C-80137r1115961_chk'
  tag severity: 'medium'
  tag gid: 'V-275999'
  tag rid: 'SV-275999r1115962_rule'
  tag stig_id: 'O19C-00-020500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-80042r1112491_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # OVERLAY-ADDED (NOT-APPLICABLE-RDS, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'N/A on AWS RDS: control-file redundancy on separate physical devices requires OS storage inspection; N/A on managed RDS (AWS-managed storage)' do
    skip 'N/A on AWS RDS: control-file redundancy on separate physical devices requires OS storage inspection; N/A on managed RDS (AWS-managed storage)'
  end
end
