control 'SV-270518' do
  title 'Database objects must be owned by accounts authorized for ownership.'
  desc 'Within the database, object ownership implies full privileges to the
  owned object including the privilege to assign access to the owned objects to
  other subjects. Unmanaged or uncontrolled ownership of objects can lead to
  unauthorized object grants and alterations, and unauthorized modifications to
  data.

      If critical tables or other objects rely on unauthorized owner accounts,
  these objects can be lost when an account is removed.

      It may be the case that there are accounts that are authorized to own
  synonyms, but no other objects. If this is so, it should be documented.'
  desc 'check', 'Review system documentation to identify accounts authorized to own database objects. Review accounts in the database management systems (DBMSs) that own objects.

If any database objects are found to be owned by users not authorized to own database objects, this is a finding.

- - - - -
Query the object DBA_OBJECTS to show the users who own objects in the database. The query below will return all of the users who own objects.

sqlplus connect as sysdba

SQL>select owner, object_type, count(*) from dba_objects
group by owner, object_type
order by owner, object_type;

If these owners are not authorized owners, select all of the objects these owners have generated and decide who they should belong to. To make a list of all of the objects, the unauthorized owner has to perform the following query.

SQL>select * from dba_objects where owner =&unauthorized_owner;'
  desc 'fix', 'Update system documentation to include list of accounts authorized for object ownership.

Reassign ownership of authorized objects to authorized object owner accounts.'
  impact 0.5
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag gid: 'V-270518'
  tag rid: 'SV-270518r1064832_rule'
  tag stig_id: 'O19C-00-008200'
  tag fix_id: 'F-74452r1064831_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)', 'Rev_4']
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

  dba_object_owners = sql.query('select DISTINCT owner from dba_objects;').column('owner').uniq
  if dba_object_owners .empty?
    impact 0.0
    describe 'There are no oracle dba object owners, control N/A' do
      skip 'There are no oracle dba object owners, control N/A'
    end
  else
    dba_object_owners .each do |owner|
      describe "oracle datbase object owner: #{owner}" do
        subject { owner }
        it { should be_in input('allowed_dbaobject_owners') }
      end
    end
  end
end
