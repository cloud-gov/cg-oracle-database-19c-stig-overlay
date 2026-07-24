control 'SV-270560' do
  title 'Oracle Database must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To ensure accountability and prevent unauthorized access, organizational users must be identified and authenticated.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'Review database management system (DBMS) settings, OS settings, and/or enterprise-level authentication/access mechanism settings, and site practices, to determine whether organizational users are uniquely identified and authenticated when logging on to the system.

If organizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Configure the DBMS, OS, and/or enterprise-level authentication/access mechanism to uniquely identify and authenticate all organizational users who log on to the system. Ensure that each user has a separate account from all other users.'
  impact 0.5
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag gid: 'V-270560'
  tag rid: 'SV-270560r1065286_rule'
  tag stig_id: 'O19C-00-013800'
  tag fix_id: 'F-74494r1064957_fix'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2', 'Rev_4']
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

  describe 'A manual review is required to ensure the DBMS uniquely identifies and authenticates organizational users
    (or processes acting on behalf of organizational users).' do
    skip 'A manual review is required to ensure the DBMS uniquely identifies and authenticates organizational users
    (or processes acting on behalf of organizational users).'
  end
end
