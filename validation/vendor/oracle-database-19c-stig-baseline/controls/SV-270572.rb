control 'SV-270572' do
  title 'Oracle Database must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers, and typically requires privileged user access.

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate.

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources.

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding database management system (DBMS) management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Check DBMS settings and vendor documentation to verify
  administrative functionality is separate from user functionality.

  If administrator and general user functionality is not separated either
  physically or logically, this is a finding.'
  desc 'fix', "Configure DBMS settings to separate database administration and general user functionality. Provide those who have both administrative and general-user responsibilities with separate accounts for these separate functions.

This includes separation of duties for administrative users, schema owners, and application (general) users. Oracle's recommendation is Oracle Database Vault to solve this problem.

Oracle Database Vault provides controls to prevent unauthorized privileged users from accessing sensitive data and to prevent unauthorized database changes. Oracle Database Vault provides database roles that enable different users to perform specific tasks, based on separation-of-duty guidelines. One of the biggest benefits resulting from regulatory compliance has been security awareness. Oracle Database Vault helps DBAs design flexible security policies for their database."
  impact 0.5
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag gid: 'V-270572'
  tag rid: 'SV-270572r1137655_rule'
  tag stig_id: 'O19C-00-016100'
  tag fix_id: 'F-74506r1064993_fix'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2', 'Rev_4']
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

  describe 'A manual review is required to ensure the DBMS separates user functionality (including user interface
    services) from database management functionality' do
    skip 'A manual review is required to ensure the DBMS separates user functionality (including user interface
    services) from database management functionality'
  end
end
