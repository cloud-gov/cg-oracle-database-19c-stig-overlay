control 'SV-270589' do
  title 'Oracle Database must include only approved trust anchors in trust stores or certificate stores managed by the organization.'
  desc 'Public key infrastructure (PKI) certificates are certificates with visibility external to organizational systems and certificates related to the internal operations of systems, such as application-specific time services. In cryptographic systems with a hierarchical structure, a trust anchor is an authoritative source (i.e., a certificate authority) for which trust is assumed and not derived. A root certificate for a PKI system is an example of a trust anchor. A trust store or certificate store maintains a list of trusted root certificates.'
  desc 'check', 'If all accounts are authenticated by the OS or an enterprise-level authentication/access mechanism and not by Oracle, this is not a finding.

Verify the database management system (DBMS) is configured to include only approved trust anchors in trust stores or certificate stores managed by the organization.

If trust stores or certification paths are not being validated back to a trust anchor, this is a finding.

The database supports PKI-based authentication by using digital certificates over Transport Layer Security (TLS) in addition to the native encryption and data integrity capabilities of these protocols.

Oracle provides a complete PKI that is based on RSA Security, Inc., Public-Key Cryptography Standards, and interoperates with Oracle servers and clients. The database uses a wallet that is a container to store authentication and signing credentials, including private keys, certificates, and trusted certificates needed by TLS. In an Oracle environment, every entity that communicates over TLS must have a wallet containing an X.509 version 3 certificate, private key, and list of trusted certificates.

If the $ORACLE_HOME/network/admin/sqlnet.ora contains the following entries, TLS is installed.

WALLET_LOCATION = (SOURCE=
(METHOD = FILE) 
(METHOD_DATA = 
DIRECTORY=/wallet) 

SSL_CIPHER_SUITES=(SSL_cipher_suiteExample) 
SSL_VERSION = 1.1 or 1.2
SSL_CLIENT_AUTHENTICATION=TRUE'
  desc 'fix', 'Configure the DBMS to include only approved trust anchors in trust stores or certificate stores managed by the organization.

Configure the database to support TLS protocols and the Oracle Wallet to store authentication and signing credentials, including private keys.'
  impact 0.5
  tag check_id: 'C-74622r1136926_chk'
  tag severity: 'medium'
  tag gid: 'V-270589'
  tag rid: 'SV-270589r1136927_rule'
  tag stig_id: 'O19C-00-020400'
  tag gtitle: 'SRG-APP-000910-DB-000300'
  tag fix_id: 'F-74523r1065044_fix'
  tag 'documentable'
  tag cci: ['CCI-004909']
  tag nist: ['SC-17 b']

  # OVERLAY-ADDED (NOT-APPLICABLE-RDS, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'N/A on AWS RDS: trust-anchor/wallet cert store is a host filesystem check; N/A on managed RDS' do
    skip 'N/A on AWS RDS: trust-anchor/wallet cert store is a host filesystem check; N/A on managed RDS'
  end
end
