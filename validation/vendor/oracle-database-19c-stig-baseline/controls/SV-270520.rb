control 'SV-270520' do
  title 'Oracle Database must be configured in accordance with the security configuration settings based on DOD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring the database management system (DBMS) to implement organizationwide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DOD that reflects the most restrictive security posture consistent with operational requirements. In addition to this SRG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. Oracle Database must be configured in compliance with guidance from all such relevant sources, with specific emphasis on the database security standards of each organization.'
  desc 'check', 'Oracle Database Security Assessment Tool (DBSAT) provides prioritized recommendations on how to mitigate identified security risks or gaps within Oracle Databases.

With DBSAT, DISA STIG rules that are process-related, such as review system documentation to identify accounts authorized to own database objects, are now included, and marked as "Evaluate" and display details that help customers validate compliance. DBSAT automates the STIG checks whenever possible, and if the checks are process-related, DBSAT provides visibility so they can be  tracked and manually validated.

Download the latest version of the Oracle Database Security Assessment Tool (DBSAT). DBSAT is provided by Oracle at no additional cost:
https://www.oracle.com/database/technologies/security/dbsat.html

DBSAT analyzes information on the database and listener configuration to identify configuration settings that may unnecessarily introduce risk. DBSAT goes beyond simple configuration checking, examining user accounts, privilege and role grants, authorization control, separation of duties, fine-grained access control, data encryption and key management, auditing policies, and OS file permissions. DBSAT applies rules to quickly assess the current security status of a database and produce findings in all the areas above. 

In addition, to the Oracle database STIG checks, DBSAT helps identify areas where your database configuration, operation, or implementation introduces risks and recommends changes and controls to mitigate those risks according Oracle database security best practices.

If there is evidence that the DBSAT tool is not used with the output reviewed regularly (annually), this is a finding.'
  desc 'fix', 'For each finding, DBSAT recommends remediation activities that follow best practices to reduce or mitigate risk. Review the security status, provided by the DBSAT report, check the categories (sections) and review the findings by risk level and recommendations. For each recommendation, each organization must determine which remediation activities to implement according to their security policies.'
  impact 0.5
  tag check_id: 'C-74553r1115963_chk'
  tag severity: 'medium'
  tag gid: 'V-270520'
  tag rid: 'SV-270520r1115964_rule'
  tag stig_id: 'O19C-00-008400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-74454r1064837_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'DBSAT/STIG-config compliance is a manual assessment' do
    skip 'DBSAT/STIG-config compliance is a manual assessment'
  end
end
