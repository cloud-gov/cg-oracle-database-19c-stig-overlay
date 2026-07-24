control 'SV-270569' do
  title 'Oracle Database must use NIST-validated FIPS 140-2/140-3 compliant cryptography for authentication mechanisms.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of using encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the database management system (DBMS).

Applications (including DBMSs) using cryptography are required to use approved NIST FIPS 140-2/140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While federal agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules.

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/.'
  desc 'check', 'Check the following settings to verify FIPS 140-2 or FIPS 140-3 authentication/encryption is configured. If encryption is required but not configured, check with the database administrator (DBA) and system administrator to verify if other mechanisms or third-party cryptography products are deployed for authentication.

To verify if Oracle is configured for FIPS 140 Secure Sockets Layer (SSL)/Transport Layer Security (TLS) authentication and/or encryption:

Open the fips.ora file in a browser or editor. (The default location for fips.ora is $ORACLE_HOME/ldap/admin/ but alternate locations are possible. An alternate location, if it is in use, is specified in the FIPS_HOME environment variable.)

If the line "SSLFIPS_140=TRUE" is not found in fips.ora, or the file does not exist, this is a finding.'
  desc 'fix', %q(Utilize NIST-validated FIPS 140-2/140-3 compliant cryptography for all authentication mechanisms.

Open the fips.ora file in an editor. (The default location for fips.ora is $ORACLE_HOME/ldap/admin/ but alternate locations are possible. An alternate location, if it is in use, is specified in the FIPS_HOME environment variable.)
Create or modify fips.ora to include the line "SSLFIPS_140=TRUE".

The strength requirements are dependent upon data classification.

For unclassified data, where cryptography is required:
AES 128 for encryption
SHA 256 for hashing

NSA has established the suite B encryption requirements for protecting National Security Systems (NSS) as follows:
AES 128 for Secret
AES 256 for Top Secret
SHA 256 for Secret
SHA 384 for Top Secret

NSS is defined as: (OMB Circular A-130) Any telecommunications or information system operated by the United States Government, the function, operation, or use of which (1) involves intelligence activities; (2) involves cryptologic activities related to national security; (3) involves command and control of military forces; (4) involves equipment that is an integral part of a weapon or weapons system; or (5) is critical to the direct fulfillment of military or intelligence missions, but excluding any system that is to be used for routine administrative and business applications (including payroll, finance, logistics, and personnel management applications).

There is more information on this topic in the Oracle Database 19c Advanced Security Administrator's Guide, located at https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/oracle-database-fips-140-settings.html.

Note: Because of changes in Oracle's licensing policy, it is no longer necessary to purchase Oracle Advanced Security to use network encryption and advanced authentication.

FIPS documentation can be downloaded from https://csrc.nist.gov/publications/fips.)
  impact 0.7
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag gid: 'V-270569'
  tag rid: 'SV-270569r1065205_rule'
  tag stig_id: 'O19C-00-015500'
  tag fix_id: 'F-74503r1065204_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7', 'Rev_4']
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

  version = sql.query('select version from v$instance;').column('version')

  describe 'The oracle database version' do
    subject { version }
    it { should cmp >= '12.1.0.2' }
  end

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/ldap/admin/fips.ora" do
    its('content') { should include 'SSLFIPS_140=TRUE' }
    it { should exist }
  end
end
