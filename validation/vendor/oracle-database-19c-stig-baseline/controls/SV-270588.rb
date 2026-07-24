control 'SV-270588' do
  title 'Oracle Database must, for password-based authentication, require immediate selection of a new password upon account recovery.'
  desc 'Password-based authentication applies to passwords regardless of whether they are used in single-factor or multifactor authentication (MFA). Long passwords or passphrases are preferable over shorter passwords. Enforced composition rules provide marginal security benefits while decreasing usability. However, organizations may choose to establish certain rules for password generation (e.g., minimum character length for long passwords) under certain circumstances and can enforce this requirement in IA-5(1)(h). Account recovery can occur, for example, in situations when a password is forgotten. Cryptographically protected passwords include salted one-way cryptographic hashes of passwords. The list of commonly used, compromised, or expected passwords includes passwords obtained from previous breach corpuses, dictionary words, and repetitive or sequential characters. The list includes context-specific words, such as the name of the service, username, and derivatives thereof.'
  desc 'check', "Verify the database management system (DBMS) is configured to require immediate selection of a new password upon account recovery.

All scripts, functions, triggers, and stored procedures that are used to create a user or reset a user's password should include a line similar to the following:
alter user <username> password expire;

If they do not, this is a finding.

If the DBMS is not configured to require immediate selection of a new password upon account recovery, this is a finding."
  desc 'fix', "Configure the DBMS to require immediate selection of a new password upon account recovery.

One way to configure this is to ensure that all scripts, functions, triggers, and stored procedures that are used to create a user or reset a user's password should include a line similar to the following:
alter user <username> password expire;"
  impact 0.5
  tag check_id: 'C-74621r1065040_chk'
  tag severity: 'medium'
  tag gid: 'V-270588'
  tag rid: 'SV-270588r1065042_rule'
  tag stig_id: 'O19C-00-019900'
  tag gtitle: 'SRG-APP-000855-DB-000240'
  tag fix_id: 'F-74522r1065041_fix'
  tag 'documentable'
  tag cci: ['CCI-004063']
  tag nist: ['IA-5 (1) (e)']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'password-reset-on-recovery requires reviewing scripts/procedures' do
    skip 'password-reset-on-recovery requires reviewing scripts/procedures'
  end
end
