# MVP overlay: pull in exactly one control from the depended-on baseline
# (the cloud-gov fork's `cloudgov` branch) to validate the full
# depends -> overlay -> SQL-verify path end to end.
#
# SV-270495 (concurrent sessions per user / SESSIONS_PER_USER) is the simplest
# oracledb_session check in the baseline: a single SELECT against
# SYS.DBA_PROFILES with a flat should_not-include assertion. As more controls
# are dispositioned per control-layers.yml, add them to this block (#3).
#
# NOTE (temporary local override): the vendored baseline control instantiates
# oracledb_session WITHOUT a `port:`, so the resource silently defaults to 1521.
# That breaks the live Cloud.gov TCPS run, which must target port 2484 — oraquery
# fails closed ("verify-ca cannot connect to the plaintext Oracle port 1521").
# Until the fix lands upstream in the baseline fork, we DEFINE SV-270495 directly
# here (instead of `require_controls`) purely to forward `port: input('port')`
# into the connect string. Everything else mirrors the baseline control verbatim.
# TODO(#3): drop this override and restore `require_controls` once the upstream
# fork forwards `port:`; also declare/forward `port` in the upstream profile.
control 'SV-270495' do
  title 'Oracle Database must limit the number of concurrent sessions for each system account to an organization-defined number of sessions.'
  desc 'Database management includes the ability to control the number of users and user sessions using a database management system (DBMS). Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks. 

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS by modifying user database profiles.

Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization must to define the maximum number of concurrent sessions by user type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, two might be an acceptable limit for general users accessing the database via an application; but three might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session: An account associated with a connection pool might require hundreds or thousands.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)'
  desc 'check', %q(Retrieve the settings for concurrent sessions for each profile with the query:

SELECT con_id, inherited, limit FROM sys.cdb_profiles WHERE resource_name = 'SESSIONS_PER_USER';

If the DBMS settings for concurrent sessions for each profile are greater than the site-specific maximum number of sessions (or the database maximum number of sessions) for the user type, this is a finding.

The reason for "site-specific" is because two different databases at different "sites" could have very different requirements.
Also, two different databases at the same "site" (data center) could have very different requirements.)
  desc 'fix', 'Limit concurrent connections for each system account to a number less than or equal to the organization-defined number of sessions using the following SQL. Create profiles that conform to the requirements. Assign users to the appropriate profile.

The user profile, ORA_STIG_PROFILE, has been provided with Oracle 19c to satisfy the STIG requirements pertaining to profile parameters. Oracle recommends that this profile be customized with requirements and assigned to all users through the creation of user type specific profiles such as (Single-Session, Administrators, Application Connection Pool) where applicable. 

Note: The ORA_STIG_PROFILE limit for SESSIONS_PER_USER is DEFAULT which is, on installation, not compliant and must be configured for each database and in a container database for CDB$ROOT and, potentially, for each PDB.

Set concurrent sessions for each profile with the following SQL statement, as required.

ALTER PROFILE <profile_name> LIMIT SESSIONS_PER_USER <integer>;'
  impact 0.5
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-270495'
  tag rid: 'SV-270495r1167748_rule'
  tag stig_id: 'O19C-00-000100'
  tag fix_id: 'F-74429r1167747_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10', 'Rev_4']
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

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), port: input('port'), sqlplus_bin: input('sqlplus_bin'))

  concurrent_sessions = sql.query("SELECT limit FROM SYS.DBA_PROFILES WHERE RESOURCE_NAME = 'SESSIONS_PER_USER';").column('limit')

  describe 'The oracle database number of concurrent sessions allowed' do
    subject { concurrent_sessions }
    it { should_not include 'UNLIMITED' }
    it { should_not include 'DEFAULT' }
  end
end
