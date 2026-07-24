control 'SV-270508' do
  title 'The Oracle Database, or the logging or alerting mechanism the application uses, must provide a warning when allocated audit record storage volume record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the database management system (DBMS) on its own server will not be an issue. However, space will still be required on the DBMS server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume usage reaching 75 percent, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the information system security officer (ISSO) and the database administrator (DBA)/system administrator (SA).'
  desc 'check', 'Review OS or third-party logging application settings to determine whether a warning will be provided when 75 percent of DBMS audit log storage capacity is reached.

If no warning will be provided, this is a finding.'
  desc 'fix', 'Modify DBMS, OS, or third-party logging application settings to alert appropriate personnel when 75 percent of log storage capacity is reached.

For ease of management, it is recommended that the audit tables be kept in a dedicated tablespace.

If Oracle Enterprise Manager is in use, the capability to issue such an alert is built in and configurable via the console so an email can be sent to a designated administrator.

If Enterprise Manager is unavailable, the following script can be used to monitor storage space; this can be combined with additional code to email the appropriate administrator so they can take action.

sqlplus connect as sysdba

set pagesize 300
set linesize 120
column sumb format 9,999,999,999,999
column extents format 999999
column bytes format 9,999,999,999,999
column largest format 9,999,999,999,999
column Tot_Size format 9,999,999,999,999
column Tot_Free format 9,999,999,999,999
column Pct_Free format 9,999,999,999,999
column Chunks_Free format 9,999,999,999,999
column Max_Free format 9,999,999,999,999
set echo off
spool TSINFO.txt
PROMPT SPACE AVAILABLE IN TABLESPACES
select a.tablespace_name,sum(a.tots) Tot_Size,
sum(a.sumb) Tot_Free,
sum(a.sumb)*100/sum(a.tots) Pct_Free, 
sum(a.largest) Max_Free,sum(a.chunks) Chunks_Free
from
(
select tablespace_name,0 tots,sum(bytes) sumb,
max(bytes) largest,count(*) chunks
from dba_free_space a
group by tablespace_name
union
select tablespace_name,sum(bytes) tots,0,0,0 from
dba_data_files
group by tablespace_name) a
group by a.tablespace_name;

Sample Output

SPACE AVAILABLE IN TABLESPACES

TABLESPACE_NAME     TOT_SIZE     TOT_FREE     PCT_FREE     MAX_FREE    CHUNKS_FREE
-----------------------------      --------------     --------------     ---------------    ----------------    --------------------- 
DES2                                   41,943,040      30,935,040             74             30,935,040                   1 
DES2_I                               31,457,280       23,396,352             74             23,396,352                   1 
RBS                                     60,817,408       57,085,952             94             52,426,752                16 
SYSTEM                             94,371,840        5,386,240                6               5,013,504                  3 
TEMP                                       563,200           561,152            100                  133,120                  5 
TOOLS                              120,586,240      89,407,488              74             78,190,592                12 
USERS                                  1,048,576             26,624                 3                   26,624                   1'
  impact 0.5
  tag check_id: 'C-74541r1064800_chk'
  tag severity: 'medium'
  tag gid: 'V-270508'
  tag rid: 'SV-270508r1065201_rule'
  tag stig_id: 'O19C-00-005900'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-74442r1064801_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe '75% audit-storage warning is an operational review' do
    skip '75% audit-storage warning is an operational review'
  end
end
