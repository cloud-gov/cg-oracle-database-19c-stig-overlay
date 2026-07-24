control 'SV-270564' do
  title 'Oracle Database must, for password-based authentication, store passwords using an approved salted key derivation function, preferably using a keyed hash.'
  desc 'The DOD standard for authentication is DOD-approved public key infrastructure (PKI) certificates.

Authentication based on user ID and password may be used only when it is not possible to employ a PKI certificate and requires authorizing official (AO) approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the database management system (DBMS).

Database passwords stored in clear text are vulnerable to unauthorized disclosure. Database passwords must always be encoded or encrypted when stored internally or externally to the DBMS.

Transport Layer Security (TLS) is the successor protocol to Secure Sockets Layer (SSL). Although the Oracle configuration parameters have names that include "SSL", such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.'
  desc 'check', 'Oracle Database stores and displays its passwords in encrypted form. Nevertheless, this should be verified by reviewing the relevant system views, along with the other items to be checked here.

Review the list of DBMS database objects, database configuration files, associated scripts, and applications defined within and external to the DBMS that access the database. The list should also include files, tables, or settings used to configure the operational environment for the DBMS and for interactive DBMS user accounts.

Determine whether any DBMS database objects, database configuration files, associated scripts, applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings contain database passwords. If any do, confirm that DBMS passwords stored internally or externally to the DBMS are hashed using FIPS-approved cryptographic algorithms and include a salt. 

If any passwords are stored in clear text, this is a finding. 

If any passwords are stored with reversible encryption, this is a finding. 

Determine if an external password store for applications, batch jobs, and scripts is in use. Verify that all passwords stored there are encrypted.

If a password store is used and any password is not encrypted, this is a finding.'
  desc 'fix', 'Develop, document, and maintain a list of DBMS database objects, database configuration files, associated scripts, applications defined within or external to the DBMS that access the database, and DBMS/user environment files/settings in the system documentation.

Record whether they do or do not contain DBMS passwords. If passwords are present, ensure they are correctly hashed using one-way, salted hashing functions, and that the hashes are protected by host system security.

The following are notes on implementing a Secure External Password Store using Oracle Wallet.

Oracle provides the capability to provide for a secure external password facility. Use the Oracle mkstore to create a secure storage area for passwords for applications, batch jobs, and scripts to use, or deploy a site-authorized facility to perform this function.

Check to verify what has been stored in the Oracle External Password Store.

To view all contents of a client wallet external password store, check specific credentials by viewing them. Listing the external password store contents provides information that can be used to decide whether to add or delete credentials from the store. To list the contents of the external password store, enter the following command at the command line:

$ mkstore -wrl wallet_location -listCredential

For example: $ mkstore -wrl c:\\oracle\\product\\19.0.0\\db_1\\wallets -listCredential

The wallet_location specifies the path to the directory where the wallet, whose external password store contents is to be viewed, is located. This command lists all of the credential database service names (aliases) and the corresponding username (schema) for that database. Passwords are not listed.

Configuring Clients to Use the External Password Store:

If the client is already configured to use external authentication, such as Windows built-in authentication or Transport Layer Security (TLS), then Oracle Database uses that authentication method. The same credentials used for this type of authentication are typically also used to log on to the database.

For clients not using such authentication methods or wanting to override them for database authentication, can set the SQLNET.WALLET_OVERRIDE parameter in sqlnet.ora to TRUE. The default value for SQLNET.WALLET_OVERRIDE is FALSE, allowing standard use of authentication credentials as before.

If wanting a client to use the secure external password store feature, then perform the following configuration task:

1. Create a wallet on the client by using the following syntax at the command line:

mkstore -wrl wallet_location -create

For example: mkstore -wrl c:\\oracle\\product\\19.0.0\\db_1\\wallets -create
Enter password: password

The wallet_location is the path to the directory where the wallet is to be created and stored. This command creates an Oracle wallet with the autologon feature enabled at the location specified. The autologon feature enables the client to access the wallet contents without supplying a password.

The mkstore utility -create option uses password complexity verification.

2. Create database connection credentials in the wallet by using the following syntax at the command line:

mkstore -wrl wallet_location -createCredential db_connect_string username
Enter password: password

For example: mkstore -wrl c:\\oracle\\product\\19.0.0\\db_1\\wallets -createCredential oracle system
Enter password: password

In this specification, the wallet_location is the path to the directory where the wallet was created. The db_connect_string used in the CONNECT /@db_connect_string statement must be identical to the db_connect_string specified in the -createCredential command. The db_connect_string is the TNS alias used to specify the database in the tnsnames.ora file or any service name used to identify the database on an Oracle network. By default, tnsnames.ora is located in the $ORACLE_HOME/network/admin directory on Unix systems and in ORACLE_HOME\\network\\admin on Windows. The username is the database logon credential. When prompted, enter the password for this user.

3. In the client sqlnet.ora file, enter the WALLET_LOCATION parameter and set it to the directory location of the wallet created in Step 1. For example, if the wallet was created in $ORACLE_HOME/network/admin and Oracle home is set to /private/ora19, then enter the following into client sqlnet.ora file:

WALLET_LOCATION =
(SOURCE =
(METHOD = FILE)
(METHOD_DATA =
(DIRECTORY = /private/ora19/network/admin)
)
)

4. In the client sqlnet.ora file, enter the SQLNET.WALLET_OVERRIDE parameter and set it to TRUE as follows:

SQLNET.WALLET_OVERRIDE = TRUE

This setting causes all CONNECT /@db_connect_string statements to use the information in the wallet at the specified location to authenticate to databases.

When external authentication is in use, an authenticated user with such a wallet can use the CONNECT /@db_connect_string syntax to access the previously specified databases without providing a username and password. However, if a user fails that external authentication, then these connect statements also fail.

Below is a sample sqlnet.ora file with the WALLET_LOCATION and the SQLNET.WALLET_OVERRIDE parameters set as described in Steps 3 and 4.

WALLET_LOCATION =
(SOURCE =
(METHOD = FILE)
(METHOD_DATA =
(DIRECTORY = /private/ora19/network/admin)
)
)
SQLNET.WALLET_OVERRIDE = TRUE
SSL_CLIENT_AUTHENTICATION = FALSE
SSL_VERSION = 1.1 or 1.2

Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Refer to the following link if using a nondefault configuration:
https://docs.oracle.com/en/database/oracle/oracle-database/19/netrf/parameters-for-the-sqlnet.ora.html'
  impact 0.7
  tag check_id: 'C-74597r1064968_chk'
  tag severity: 'high'
  tag gid: 'V-270564'
  tag rid: 'SV-270564r1136919_rule'
  tag stig_id: 'O19C-00-014800'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-74498r1136918_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'passwords not stored reversibly is a wallet/config review' do
    skip 'passwords not stored reversibly is a wallet/config review'
  end
end
