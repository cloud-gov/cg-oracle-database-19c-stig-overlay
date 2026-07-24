control 'SV-270577' do
  title 'Oracle Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.'
  desc 'Applications, including database management systems (DBMSs), must prevent unauthorized and unintended information transfer via shared system resources. 

Data used for the development and testing of applications often involves copying data from production. It is important that specific procedures exist for this process, to include the conditions under which such transfer may take place, where the copies may reside, and the rules for ensuring sensitive data are not exposed.

Copies of sensitive data must not be misplaced or left in a temporary location without the proper controls.'
  desc 'check', 'Review the procedures for the refreshing of development/test data from production.

Review any scripts or code that exists for the movement of production data to development/test systems, or to any other location or for any other purpose.

Verify that copies of production data are not left in unprotected locations. 

If the code that exists for data movement does not comply with the organization-defined data transfer policy and/or fails to remove any copies of production data from unprotected locations, this is a finding.

If sensitive data is included in the exports and no procedures are in place to remove or modify the data to render it not sensitive prior to import into a development database or policy and procedures are not in place to ensure authorization of development personnel to access sensitive information contained in production data, this is a finding.'
  desc 'fix', 'Restrict accessibility of Oracle system tables and other configuration information or metadata to database administrators (DBAs) or other authorized users.  

Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations.

Implement policy and procedures to modify or remove sensitive information in production exports prior to import into development databases.'
  impact 0.5
  tag check_id: 'C-74610r1065007_chk'
  tag severity: 'medium'
  tag gid: 'V-270577'
  tag rid: 'SV-270577r1137656_rule'
  tag stig_id: 'O19C-00-017400'
  tag gtitle: 'SRG-APP-000243-DB-000128'
  tag fix_id: 'F-74511r1065008_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'data-transfer/export policy is a procedural review' do
    skip 'data-transfer/export policy is a procedural review'
  end
end
