control 'SV-270545' do
  title 'Oracle Database default accounts must be assigned custom passwords.'
  desc "Password maximum lifetime is the maximum period of time, (typically in days) a user's password may be in effect before the user is forced to change it.

Passwords need to be changed at specific policy-based intervals as per policy. Any password, no matter how complex, can eventually be cracked.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

Database management system (DBMS) default passwords provide a commonly known and exploited means for unauthorized access to database installations."
  desc 'check', 'Use this query to identify the Oracle-supplied accounts that still have their default passwords:

SELECT * FROM SYS.DBA_USERS_WITH_DEFPWD;

If any accounts other than XS$NULL are listed, this is a finding.

XS$NULL is an internal account that represents the absence of a user in a session. Because XS$NULL is not a user, this account can only be accessed by the Oracle Database instance. XS$NULL has no privileges and no one can authenticate as XS$NULL, nor can authentication credentials ever be assigned to XS$NULL.'
  desc 'fix', 'Change passwords for database management system (DBMS) accounts to nondefault values. Where necessary, unlock or enable accounts to change the password, and then return the account to disabled or locked status.'
  impact 0.7
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag gid: 'V-270545'
  tag rid: 'SV-270545r1064913_rule'
  tag stig_id: 'O19C-00-011900'
  tag fix_id: 'F-74479r1064912_fix'
  tag cci: ['CCI-000199', 'CCI-000366']
  tag nist: ['IA-5 (1) (d)', 'Rev_4', 'CM-6 b']
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

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  sys_dba_users_with_defpwd = sql.query(' SELECT username FROM SYS.DBA_USERS_WITH_DEFPWD;').column('username').uniq

  describe.one do
    sys_dba_users_with_defpwd.each do |user|
      describe "The oracle system database user: #{user} with a default password" do
        subject { user }
        it { should cmp 'XS$NULL' }
      end
    end
    
    describe sys_dba_users_with_defpwd do
      it { should be_empty }
    end
  end
end
