control 'SV-270565' do
  title 'If passwords are used for authentication, the Oracle Database must transmit only encrypted representations of passwords.'
  desc 'The DOD standard for authentication is DOD-approved public key infrastructure (PKI) certificates.

Authentication based on user ID and password may be used only when it is not possible to employ a PKI certificate, and requires authorizing official (AO) approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

Database management system (DBMS) passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names including "SSL", such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.'
  desc 'check', 'If all accounts are authenticated by the OS or an enterprise-level authentication/access mechanism and not by Oracle, this is not a finding.

Review configuration settings for encrypting passwords in transit across the network. If passwords are not encrypted, this is a finding. 

The database supports PKI-based authentication by using digital certificates over TLS in addition to the native encryption and data integrity capabilities of these protocols.

Oracle provides a complete PKI that is based on RSA Security, Inc., Public-Key Cryptography Standards, and interoperates with Oracle servers and clients. The database uses a wallet that is a container used to store authentication and signing credentials, including private keys, certificates, and trusted certificates needed by TLS. In an Oracle environment, every entity that communicates over TLS must have a wallet containing an X.509 version 3 certificate, private key, and list of trusted certificates.

Verify the $ORACLE_HOME/network/admin/sqlnet.ora contains entries similar to the following to confirm TLS is installed: 

WALLET_LOCATION = (SOURCE=
(METHOD = FILE) 
(METHOD_DATA = 
DIRECTORY=/wallet)

SSL_CIPHER_SUITES=(SSL_cipher_suiteExample) 
SSL_VERSION = 1.1 or 1.2
SSL_CLIENT_AUTHENTICATION=TRUE

If the sqlnet.ora file does not contain such entries, this is a finding.'
  desc 'fix', 'Configure encryption for transmission of passwords across the network.

Configure the database to support TLS protocols and the Oracle Wallet to store authentication and signing credentials, including private keys. 

More information can be found at https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-secure-sockets-layer-authentication.html#GUID-EF8DEC69-C8BE-462B-ABDD-E621914E617E.'
  impact 0.5
  tag check_id: 'C-74598r1136920_chk'
  tag severity: 'medium'
  tag gid: 'V-270565'
  tag rid: 'SV-270565r1136921_rule'
  tag stig_id: 'O19C-00-014900'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-74499r1064972_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']

  # OVERLAY-ADDED (NOT-APPLICABLE-RDS, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'N/A on AWS RDS: encrypted password transit is verified via sqlnet.ora on the DB host; not accessible on managed RDS (AWS-managed OS/listener)' do
    skip 'N/A on AWS RDS: encrypted password transit is verified via sqlnet.ora on the DB host; not accessible on managed RDS (AWS-managed OS/listener)'
  end
end
