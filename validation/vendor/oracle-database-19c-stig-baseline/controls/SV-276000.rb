control 'SV-276000' do
  title 'A minimum of three Oracle redo log groups/files must be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID device. In addition, each Oracle redo log group must have a minimum of two Oracle redo log members (files).'
  desc 'The Oracle Database Redo Log files store detailed transactional information on changes made to the database using SQL Data Manipulation Language (DML), Data Definition Language (DDL), and Data Control Language (DCL), which is required for undo, backup, restoration, and recovery. 

A minimum of three Oracle redo log groups/files must be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID (mirrored) device. In addition, each Oracle redo log group must have a minimum to two Oracle redo log members (files). 

Each side of the Redo Log Mirror (group 1, member 1) is identical to its mirror image (group 1, member 2), making it possible to continue operations if one file or even one complete mirror is lost due to corruption or accidental deletion. Writing each mirror to a physically and logically separate storage device is an important part of minimizing single points of failure.

Oracle redo logs, which are crucial for database recovery, are managed at the CDB level, not at the PDB level.'
  desc 'check', 'From SQL*Plus:

-- Check to see how many Oracle redo log groups there are:
select group#, bytes, members, status, archived from v$log;

-- Check to see how many Oracle redo log members there are:
select * from v$logfile;

This is a finding if there are less than three Oracle redo log groups a RAID storage device, or equivalent storage system, is not being used.

If one or more groups (group#) has only a single member this is a finding.

If one or more groups (group#) have more than a single member but one or more of those members are located on the same physical or logical device this is a finding.

select count(*) from V$LOG;

If the value of the count returned is less than 3, this is a finding.

From SQL*Plus:

select count(*) from V$LOG where members > 1;

If the value of the count returned is less than 3 and a RAID storage device is not being used, this is a finding.'
  desc 'fix', "To define additional redo log file groups:

  From SQL*Plus (Example):

    alter database add logfile group 2
      ('diska:log2.log' ,
       'diskb:log2.log') size 50K;

  To add additional redo log file [members] to an existing redo log file group:

  From SQL*Plus (Example):

    alter database add logfile member 'diskc:log2.log'
    to group 2;

  Replace diska, diskb, diskc with valid, different disk drive specifications.

  Replace log#.log file with valid or custom names for the log files."
  impact 0.5
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-276000'
  tag rid: 'SV-276000r1112495_rule'
  tag stig_id: 'O19C-00-020600'
  tag fix_id: 'F-80043r1112494_fix'
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

  describe sql.query('select count(*) from V$LOG;').column('count(*)') do
    it { should cmp >= 2 }
  end
end
