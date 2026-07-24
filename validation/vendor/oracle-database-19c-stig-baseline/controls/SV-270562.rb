control 'SV-270562' do
  title 'Procedures for establishing temporary passwords that meet DOD password requirements for new accounts must be defined, documented, and implemented.'
  desc "Password maximum lifetime is  the maximum period of time, (typically
  in days) a user's password may be in effect before the user is forced to change
  it.

      Passwords need to be changed at specific policy-based intervals as per
  policy. Any password, no matter how complex, can eventually be cracked.

      One method of minimizing this risk is to use complex passwords and
  periodically change them. If the application does not limit the lifetime of
  passwords and force users to change their passwords, there is the risk that the
  system and/or application passwords could be compromised.

      New accounts authenticated by passwords that are created without a password
  or with an easily guessed password are vulnerable to unauthorized access.
  Procedures for creating new accounts with passwords should include the required
  assignment of a temporary password to be modified by the user upon first use.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP  With respect to Oracle, this requirement applies to cases
  where it is necessary to have accounts directly managed by Oracle."
  desc 'check', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

Where accounts are authenticated using passwords, review procedures and implementation evidence for creation of temporary passwords.

If the procedures or evidence do not exist or do not enforce passwords to meet DOD password requirements, this is a finding.'
  desc 'fix', 'Implement procedures for assigning temporary passwords to user accounts.

Procedures should include instructions to meet current DOD password length and complexity requirements and provide a secure method to relay the temporary password to the user.'
  impact 0.5
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag gid: 'V-270562'
  tag rid: 'SV-270562r1064964_rule'
  tag stig_id: 'O19C-00-014600'
  tag fix_id: 'F-74496r1064963_fix'
  tag cci: ['CCI-000199', 'CCI-000192']
  tag nist: ['IA-5 (1) (d)', 'Rev_4', 'IA-5 (1) (a)']
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

  describe 'A manual review is required to ensure procedures for establishing temporary passwords that meet DoD password
    requirements for new accounts are defined, documented, and implemented' do
    skip 'A manual review is required to ensure procedures for establishing temporary passwords that meet DoD password
    requirements for new accounts are defined, documented, and implemented'
  end
end
