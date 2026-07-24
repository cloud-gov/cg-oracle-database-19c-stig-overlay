control 'SV-270571' do
  title "Oracle Database must implement NIST FIPS 140-2/140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owner's requirements."
  desc "Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', %q(If encryption is not required for the database, this is not a finding.

If the database management system (DBMS) has not implemented federally required cryptographic protections for the level of classification of the data it contains, this is a finding.

Check the following settings to verify FIPS 140-2/140-3 encryption is configured. If encryption is not configured, check with the database administrator (DBA) and system administrator (SA) to verify if other mechanisms or third-party products are deployed to encrypt data during the transmission or storage of data.

For Transparent Data Encryption and DBMS_CRYPTO:

To verify if Oracle is configured for FIPS 140 Transparent Data Encryption and/or DBMS_CRYPTO, enter the following SQL*Plus command:
SHOW PARAMETER DBFIPS_140
or the following SQL query:
SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'DBFIPS_140';

If Oracle returns the value "FALSE", or returns no rows, this is a finding.

To verify if Oracle is configured for FIPS 140 Secure Sockets Layer (SSL)/Transport Layer Security (TLS) authentication and/or encryption:

Open the fips.ora file in a browser or editor. (The default location for fips.ora is $ORACLE_HOME/ldap/admin/ but alternate locations are possible. An alternate location, if it is in use, is specified in the FIPS_HOME environment variable.)

If the line "SSLFIPS_140=TRUE" is not found in fips.ora, or the file does not exist, this is a finding.

For (Native) Network Data Encryption:
If the line, SQLNET.FIPS_140=TRUE is not found in $ORACLE_HOME/network/admin/sqlnet.ora, this is a finding. (Note: This assumes that a single sqlnet.ora file, in the default location, is in use).)
  desc 'fix', 'Implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

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

More information on implementing FIPS settings can be found at https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/oracle-database-fips-140-settings.html.'
  impact 0.7
  tag check_id: 'C-74604r1065206_chk'
  tag severity: 'high'
  tag gid: 'V-270571'
  tag rid: 'SV-270571r1137664_rule'
  tag stig_id: 'O19C-00-016000'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag fix_id: 'F-74505r1064990_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  # OVERLAY-ADDED (NOT-APPLICABLE-RDS, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'N/A on AWS RDS: FIPS mode requires fips.ora/sqlnet.ora host files; the DBFIPS_140 param is visible but the file portions are host-level, N/A on managed RDS' do
    skip 'N/A on AWS RDS: FIPS mode requires fips.ora/sqlnet.ora host files; the DBFIPS_140 param is visible but the file portions are host-level, N/A on managed RDS'
  end
end
