control 'SV-270561' do
  title 'Oracle Database must enforce the DOD standards for password complexity.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native database management system (DBMS) authentication may be used only when circumstances make it unavoidable; and must be documented and authorizing official (AO)-approved.

The DOD standard for authentication is DOD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, the DOD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.'
  desc 'check', "If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism and not by Oracle, this is not a finding.

For each profile that can be applied to accounts where authentication is under Oracle's control, determine the password verification function that is in use:

SELECT * FROM SYS.DBA_PROFILES 
WHERE RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'
ORDER BY PROFILE;

Note: Profiles can inherit settings from another profile so some password functions could be set to DEFAULT. If so, review the DEFAULT profile function name. 

If the function name is null for any profile, this is a finding.

Review the password verification functions specified for the PASSWORD_VERIFY_FUNCTION settings for each profile. Determine whether the following rules are enforced by the code in those functions. 
a. Minimum of 15 characters, including at least one of each of the following character sets:
- Uppercase
- Lowercase
- Numeric
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight.

If any of the above password requirements are not included in the function, this is a finding."
  desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

If any user accounts are managed by Oracle, develop, test, and implement a password verification function that enforces DOD requirements.

Oracle supplies a sample function called ORA12C_STIG_VERIFY_FUNCTION. This can be used as the starting point for a customized function. The script file is found in the following location on the server depending on OS:

Windows:
%ORACLE_HOME%\\RDBMS\\ADMIN\\catpvf.sql

Unix/Linux:
$ORACLE_HOME/rdbms/admin/catpvf.sql'
  impact 0.5
  tag check_id: 'C-74594r1065287_chk'
  tag severity: 'medium'
  tag gid: 'V-270561'
  tag rid: 'SV-270561r1112485_rule'
  tag stig_id: 'O19C-00-013900'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-74495r1112484_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  # PORTED FROM 12c V-61729 (overlay #6). PASSWORD_VERIFY_FUNCTION must be set
  # (not NULL) on each profile — DoD password-complexity enforcement.
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  query = %{SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE = '%<profile>s' AND RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION'}
  user_profiles = sql.query('SELECT profile FROM dba_users;').column('profile').uniq
  user_profiles.each do |profile|
    verify_fn = sql.query(format(query, profile: profile)).column('limit')
    describe "PASSWORD_VERIFY_FUNCTION for profile #{profile}" do
      subject { verify_fn.first.to_s.upcase }
      it { should_not eq 'NULL' }
    end
  end
  if user_profiles.empty?
    describe 'No user profiles found; control N/A' do
      skip 'No user profiles found; control N/A'
    end
  end
end
