control 'SV-270556' do
  title 'Use of external executables must be authorized.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality not required for the mission.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Database management systems (DBMSs) may spawn additional external processes to execute procedures that are defined in the DBMS, but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than the DBMS and provide unauthorized access to the host system.'
  desc 'check', "Review the database for definitions of application executable objects stored external to the database.

Determine if there are methods to disable use or access, or to remove definitions for external executable objects.

Verify any application executable objects listed are authorized by the information system security officer (ISSO).

To check for external procedures, execute the following query, which will provide the libraries containing external procedures, the owners of those libraries, users that have been granted access to those libraries, and the privileges they have been granted. If there are owners other than the owners Oracle provides, then there might be executable objects stored either in the database or external to the database that are called by objects in the database. 

(connect as sysdba)
set linesize 130
column library_name format a25
column name format a15
column owner format a15
column grantee format a15
column privilege format a15
select library_name,owner, '' grantee, '' privilege
from dba_libraries 
where file_spec is not null
and owner not in ('SYS', 'ORDSYS')
minus
(
select library_name,o.name owner, '' grantee, '' privilege
from dba_libraries l,
sys.user$ o,
sys.user$ ge,
sys.obj$ obj,
sys.objauth$ oa
where l.owner=o.name
and obj.owner#=o.user#
and obj.name=l.library_name
and oa.obj#=obj.obj#
and ge.user#=oa.grantee#
and l.file_spec is not null
)
union all
select library_name,o.name owner, --obj.obj#,oa.privilege#,
ge.name grantee,
tpm.name privilege
from dba_libraries l,
sys.user$ o,
sys.user$ ge,
sys.obj$ obj,
sys.objauth$ oa,
sys.table_privilege_map tpm
where l.owner=o.name
and obj.owner#=o.user#
and obj.name=l.library_name
and oa.obj#=obj.obj#
and ge.user#=oa.grantee#
and tpm.privilege=oa.privilege#
and l.file_spec is not null
/

If any owners are returned other than those Oracle provides, ensure those owners are authorized to access those libraries. If there are users that have been granted access to libraries that are not authorized, this is a finding."
  desc 'fix', 'Disable use of or remove any external application executable
  object definitions that are not authorized.

  Revoke privileges granted to users that are not authorized access to external
  applications.'
  impact 0.5
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag gid: 'V-270556'
  tag rid: 'SV-270556r1064946_rule'
  tag stig_id: 'O19C-00-013300'
  tag fix_id: 'F-74490r1064945_fix'
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

  # OVERLAY (#9): the upstream check joins SYS.USER$ / SYS.OBJ$ / SYS.OBJAUTH$
  # (internal SYS tables). On managed RDS the master user does NOT get READ on
  # SYS.USER$ (ORA-41900 on the local 23ai harness confirmed this). Rather than
  # GUESS at a DBA_*-view rewrite that might not be equivalent for RDS SE2, this
  # control is deferred to evaluation against a LIVE brokered RDS SE2 instance
  # (aws-broker#558) where the master user's actual privilege set applies. Do NOT
  # silently pass. See control-layers.yml (verified_by: requires_live_rds).
  describe 'External-library owner/privilege review — requires evaluation on a live RDS SE2 instance (#558); SYS.USER$ not readable by the RDS master (ORA-41900) on the local harness' do
    skip 'Deferred to live RDS SE2 proof (aws-broker#558): the upstream query reads SYS.USER$/OBJ$/OBJAUTH$ which the RDS master user cannot READ; a DBA_*-view equivalent must be verified on the real instance, not guessed at locally.'
  end
end
