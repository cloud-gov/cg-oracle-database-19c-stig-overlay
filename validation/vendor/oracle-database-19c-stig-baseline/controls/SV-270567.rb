control 'SV-270567' do
  title 'Oracle Database must map the authenticated identity to the user account using public key infrastructure (PKI)-based authentication.'
  desc 'The DOD standard for authentication is DOD-approved PKI certificates. Once a PKI certificate has been validated, it must be mapped to a database management system (DBMS) user account for the authenticated identity to be meaningful to the DBMS and useful for authorization decisions.'
  desc 'check', 'Review DBMS configuration to verify DBMS user accounts are being mapped directly to unique identifying information within the validated PKI certificate.

If user accounts are not being mapped to authenticated identities, this is a finding.'
  desc 'fix', 'Configure the DBMS to map the authenticated identity directly to the DBMS user account.'
  impact 0.5
  tag check_id: 'C-74600r1064977_chk'
  tag severity: 'medium'
  tag gid: 'V-270567'
  tag rid: 'SV-270567r1064979_rule'
  tag stig_id: 'O19C-00-015300'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-74501r1064978_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'PKI-to-DB identity mapping is a configuration review' do
    skip 'PKI-to-DB identity mapping is a configuration review'
  end
end
