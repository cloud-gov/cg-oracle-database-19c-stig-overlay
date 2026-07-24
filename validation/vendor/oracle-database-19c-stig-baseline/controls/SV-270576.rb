control 'SV-270576' do
  title 'Oracle Database must isolate security functions from nonsecurity functions by means of separate security domains.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database management systems (DBMSs) typically separate security functionality from nonsecurity functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and nonsecurity functionality are commingled, users who have access to nonsecurity functionality may be able to access security functionality.'
  desc 'check', 'Check DBMS settings to determine whether objects or code
  implementing security functionality are located in a separate security domain,
  such as a separate database or schema created specifically for security
  functionality.

  If security-related database objects or code are not kept separate, this is a
  finding.

  The Oracle elements of security functionality, such as the roles, permissions,
  and profiles, along with password complexity requirements, are stored in
  separate schemas in the database.  Review any site-specific applications
  security modules built into the database and determine what schema they are
  located in and take appropriate action.  The Oracle objects will be in the
  Oracle Data Dictionary.'
  desc 'fix', 'Locate security-related database objects and code in a separate
  database, schema, or other separate security domain from database objects and
  code implementing application logic.  (This is the default behavior for
  Oracle.)  Review any site-specific applications security modules built into the
  database:   determine what schema they are located in and take appropriate
  action.'
  impact 0.5
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag gid: 'V-270576'
  tag rid: 'SV-270576r1065006_rule'
  tag stig_id: 'O19C-00-017100'
  tag fix_id: 'F-74510r1065005_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3', 'Rev_4']
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

  describe 'A manual review is required to ensure the DBMS isolates security functions from nonsecurity functions by
    means of separate security domains' do
    skip 'A manual review is required to ensure the DBMS isolates security functions from nonsecurity functions by
    means of separate security domains'
  end
end
