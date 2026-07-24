control 'SV-270536' do
  title 'Oracle Database production application and data directories must be protected from developers on shared production/development database management system (DBMS) host systems.'
  desc 'Developer roles must not be assigned DBMS administrative privileges to production DBMS application and data directories. The separation of production database administrator (DBA) and developer roles helps protect the production system from unauthorized, malicious, or unintentional interruption due to development activities.'
  desc 'check', 'If the DBMS or DBMS host is not shared by production and development activities, this check is not a finding.

Review OS DBA group membership.

If any developer accounts, as identified in the system documentation, have been assigned DBA privileges, this is a finding.

Note: Though shared production/nonproduction DBMS installations was allowed under previous database STIG guidance, doing so may place it in violation of OS, Application, Network, or Enclave STIG guidance. Ensure that any shared production/nonproduction DBMS installation meets STIG guidance requirements at all levels or mitigates any conflicts in STIG guidance with the authorizing official (AO).'
  desc 'fix', 'Create separate DBMS host OS groups for developer and production DBAs.

Do not assign production DBA OS group membership to accounts used for development.

Remove development accounts from production DBA OS group membership.

Recommend establishing a dedicated DBMS host for production DBMS installations. A dedicated host system in this case refers to an instance of the operating system at a minimum. The operating system may reside on a virtual host machine where supported by the DBMS vendor.'
  impact 0.5
  tag check_id: 'C-74569r1064884_chk'
  tag severity: 'medium'
  tag gid: 'V-270536'
  tag rid: 'SV-270536r1064886_rule'
  tag stig_id: 'O19C-00-010600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-74470r1064885_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'developer access on shared prod/dev host is a procedural review' do
    skip 'developer access on shared prod/dev host is a procedural review'
  end
end
