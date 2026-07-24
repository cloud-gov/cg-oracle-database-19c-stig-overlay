control 'SV-270563' do
  title 'Oracle Database must enforce password maximum lifetime restrictions.'
  desc "Password maximum lifetime is the maximum period of time, (typically in days) a user's password may be in effect before the user is forced to change it.

Passwords need to be changed at specific policy-based intervals as per policy. Any password, no matter how complex, can eventually be cracked.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

The PASSWORD_LIFE_TIME parameter defines the number of days a password remains valid. This can must not be set to UNLIMITED. Further, the PASSWORD_GRACE_TIME parameter, if set to UNLIMITED, can nullify the PASSWORD_LIFE_TIME. PASSWORD_GRACE_TIME must be set to 0 days (or another small integer).

Note: User authentication and account management must be done via an enterprise-wide mechanism whenever possible. Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. With respect to Oracle, this requirement applies to cases where it is necessary to have accounts directly managed by Oracle."
  desc 'check', %q(If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

Review database management system (DBMS) settings to determine if passwords must be changed periodically. Run the following script:

SELECT p1.profile,
CASE DECODE(p1.limit, 'DEFAULT', p3.limit, p1.limit) WHEN 'UNLIMITED' THEN 'UNLIMITED' ELSE
CASE DECODE(p2.limit, 'DEFAULT', p4.limit, p2.limit) WHEN 'UNLIMITED' THEN 'UNLIMITED' ELSE
TO_CHAR(DECODE(p1.limit, 'DEFAULT', p3.limit, p1.limit) + DECODE(p2.limit, 'DEFAULT', p4.limit, p2.limit))
END
END effective_life_time
FROM dba_profiles p1, dba_profiles p2, dba_profiles p3, dba_profiles p4
WHERE p1.profile=p2.profile
AND p3.profile='DEFAULT'
AND p4.profile='DEFAULT'
AND p1.resource_name='PASSWORD_LIFE_TIME'
AND p2.resource_name='PASSWORD_GRACE_TIME'
AND p3.resource_name='PASSWORD_LIFE_TIME' -- from DEFAULT profile
AND p4.resource_name='PASSWORD_GRACE_TIME' -- from DEFAULT profile
order by 1;

If the EFFECTIVE_LIFE_TIME is greater than 60 for any profile applied to user accounts, and the need for this has not been documented and approved, this is a finding.

If PASSWORD_LIFE_TIME or PASSWORD_GRACE_TIME is set to "UNLIMITED", this is a finding.)
  desc 'fix', 'For user accounts managed by Oracle, modify DBMS settings to force users to periodically change their passwords. For example, using "PPPPPP" to stand for a profile name:

ALTER PROFILE PPPPPP LIMIT PASSWORD_LIFE_TIME 35 PASSWORD_GRACE_TIME 0;

Do this for each profile applied to user accounts.

Note: Although the DOD requirement is for a password change every 60 days, using a value of 35 facilitates the use of PASSWORD_LIFE_TIME as a means of locking accounts inactive for 35 days. But if 35 is not a practical or acceptable limit for password lifetime, set it to the standard DOD value of 60.

Where a password lifetime longer than 60 is needed, document the reasons and obtain information system security officer (ISSO) approval.'
  impact 0.5
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag gid: 'V-270563'
  tag rid: 'SV-270563r1064967_rule'
  tag stig_id: 'O19C-00-014700'
  tag fix_id: 'F-74497r1064966_fix'
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

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  get_effective_life_time = sql.query("SELECT p1.profile,
  CASE p1.limit WHEN 'UNLIMITED' THEN 'UNLIMITED' ELSE
  CASE p2.limit WHEN 'UNLIMITED' THEN 'UNLIMITED' ELSE
  CASE p3.limit WHEN 'UNLIMITED' THEN 'UNLIMITED' ELSE
  CASE p4.limit WHEN 'UNLIMITED' THEN 'UNLIMITED' ELSE
  TO_CHAR(DECODE(p1.limit, 'DEFAULT', p3.limit, p1.limit) + DECODE(p2.limit,
  'DEFAULT', p4.limit, p2.limit))
  END
  END
  END
  END effective_life_time
  FROM dba_profiles p1, dba_profiles p2, dba_profiles p3, dba_profiles p4
  WHERE p1.profile=p2.profile
  AND p3.profile='DEFAULT'
  AND p4.profile='DEFAULT'
  AND p1.resource_name='PASSWORD_LIFE_TIME'
  AND p2.resource_name='PASSWORD_GRACE_TIME'
  AND p3.resource_name='PASSWORD_LIFE_TIME' -- from DEFAULT profile
  AND p4.resource_name='PASSWORD_GRACE_TIME' -- from DEFAULT profile
  order by 1;").column('effective_life_time')

  get_effective_life_time.each do |effective_life_time|

    describe 'The oracle database account effective life time limit' do
      subject { effective_life_time }
      it { should cmp >= 60 }
    end
  end
  describe get_effective_life_time do
    it { should_not be_empty }
  end
end
