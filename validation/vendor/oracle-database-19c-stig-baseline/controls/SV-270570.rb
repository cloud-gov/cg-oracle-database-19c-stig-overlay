control 'SV-270570' do
  title 'Oracle Database must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).'
  desc 'Nonorganizational users include all information system users other than organizational users which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Nonorganizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

Accordingly, a risk assessment is used in determining the authentication needs of the organization.

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the nation.'
  desc 'check', 'Review database management system (DBMS) settings to determine whether nonorganizational users are uniquely identified and authenticated when logging onto the system.

If nonorganizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Configure DBMS settings to uniquely identify and authenticate all nonorganizational users who log onto the system.'
  impact 0.5
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag gid: 'V-270570'
  tag rid: 'SV-270570r1065294_rule'
  tag stig_id: 'O19C-00-015600'
  tag fix_id: 'F-74504r1064987_fix'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8', 'Rev_4']
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

  describe 'A manual review is required to ensure the DBMS uniquely identifies and authenticates non-organizational
  users (or processes acting on behalf of non-organizational users).' do
    skip 'A manual review is required to ensure the DBMS uniquely identifies and authenticates non-organizational
    users (or processes acting on behalf of non-organizational users).'
  end
end
