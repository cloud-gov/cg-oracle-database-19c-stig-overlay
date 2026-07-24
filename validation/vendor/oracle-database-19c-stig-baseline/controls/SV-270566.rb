control 'SV-270566' do
  title 'Oracle Database, when using public key infrastructure (PKI)-based authentication, must enforce authorized access to the corresponding private key.'
  desc "The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and nonrepudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.

All access to the private key of Oracle Database must be restricted to authorized and authenticated users. If unauthorized users have access to the database management system's (DBMS's) private key, an attacker could gain access to the primary key and use it to impersonate the database on the network.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names including 'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS."
  desc 'check', "Review DBMS configuration to determine whether appropriate access controls exist to protect the DBMS's private key. If strong access controls do not exist to enforce authorized access to the private key, this is a finding.

The database supports authentication by using digital certificates over TLS in addition to the native encryption and data integrity capabilities of these protocols.

An Oracle Wallet is a container that is used to store authentication and signing credentials, including private keys, certificates, and trusted certificates needed by TLS. In an Oracle environment, every entity that communicates over TLS must have a wallet containing an X.509 version 3 certificate, private key, and list of trusted certificates, with the exception of Diffie-Hellman.

Verify the $ORACLE_HOME/network/admin/sqlnet.ora contains entries similar to the following to confirm TLS is installed: 

WALLET_LOCATION = (SOURCE=
(METHOD = FILE) 
(METHOD_DATA = 
DIRECTORY=/wallet)

SSL_CIPHER_SUITES=(SSL_cipher_suiteExample) 
SSL_VERSION = 1.1 or 1.2
SSL_CLIENT_AUTHENTICATION=TRUE

If the sqlnet.ora file does not contain such entries, this is a finding."
  desc 'fix', "Implement strong access and authentication controls to protect the database's private key.

Configure the database to support TLS protocols and the Oracle Wallet to store authentication and signing credentials, including private keys. 

More information can be found at https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-secure-sockets-layer-authentication.html#GUID-EF8DEC69-C8BE-462B-ABDD-E621914E617E."
  impact 0.7
  tag check_id: 'C-74599r1136922_chk'
  tag severity: 'high'
  tag gid: 'V-270566'
  tag rid: 'SV-270566r1136923_rule'
  tag stig_id: 'O19C-00-015200'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-74500r1064975_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']

  # OVERLAY-ADDED (NOT-APPLICABLE-RDS, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'N/A on AWS RDS: PKI private-key protection is a host filesystem/wallet check; not accessible on managed RDS' do
    skip 'N/A on AWS RDS: PKI private-key protection is a host filesystem/wallet check; not accessible on managed RDS'
  end
end
