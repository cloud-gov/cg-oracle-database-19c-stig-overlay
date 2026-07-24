control 'SV-270585' do
  title 'Oracle Database software must be evaluated and patched against newly found vulnerabilities.'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'When the Quarterly CPU is released, check the CPU Notice and note the specific patch number for the system. Then, issue the following command:

SELECT patch_id, source_version, action, status, description from dba_registry_sqlpatch;

This will generate the patch levels for the home and any specific patches that have been applied to it.

If the currently installed patch levels are lower than the latest, this is a finding.'
  desc 'fix', 'Institute and adhere to policies and procedures to ensure that patches are consistently applied to the Oracle Database within the time allowed.

Follow the instructions provided by Oracle to download and apply the appropriate security patches.

Log on to My Oracle Support.

Select patches and download the specific patch number and corresponding sha256 checksum. Once the patch is downloaded to the server, check the sha256 checksum to make sure the patch is valid.

To check the sha256 Checksum in Linux/Unix, the command is:
$ sha256sum /home/myuser/test_file4

09b4b51a60d6913b82e3353eef179969ad0968ff8acfb37ca891f04df67b93f0 /home/myuser/test_file5

Once the checksum is validated, apply the patch:
$ cd $ORACLE_HOME
$ opatch apply'
  impact 0.7
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag gid: 'V-270585'
  tag rid: 'SV-270585r1137667_rule'
  tag stig_id: 'O19C-00-018600'
  tag fix_id: 'F-74519r1065297_fix'
  tag cci: ['CCI-001499', 'CCI-002605']
  tag nist: ['CM-5 (6)', 'Rev_4', 'SI-2 c']
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

  patches = sql.query('SELECT patch_id from dba_registry_sqlpatch;').column('patch_id')

  describe 'The oracle database installed patches' do
    subject { patches }
    it { should_not cmp nil }
  end
end
