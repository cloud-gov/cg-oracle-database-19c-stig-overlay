control 'SV-270579' do
  title 'Oracle Database must employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission unless the transmitted data is otherwise protected by alternative physical measures.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism to protect the information during transmission. This is usually achieved using Transport Layer Security (TLS), secure sockets layer (SSL) virtual private network (VPN), or IPsec tunnel.

Alternative physical protection measures include Protected Distribution Systems (PDS). PDS are used to transmit unencrypted classified NSI through an area of lesser classification or control. Inasmuch as the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation. Refer to NSTSSI No. 7003 for additional details on a PDS.

Information in transmission is particularly vulnerable to attack. If the database management system (DBMS) does not employ cryptographic mechanisms preventing unauthorized disclosure of information during transit, the information may be compromised.

SHA-1 is in the process of being removed from service within the DOD and its use is to be limited during the transition to SHA-2. Use of SHA-1 for digital signature generation is prohibited. Allowable uses during the transition include CHECKSUM usage and verification of legacy certificate signatures. SHA-1 is considered a temporary solution during legacy application transitionary periods and should not be engineered into new applications. SHA-2 is the path forward for DOD.'
  desc 'check', 'Check database management system (DBMS) settings to determine whether cryptographic mechanisms are used to prevent the unauthorized disclosure of information during transmission. Determine whether physical measures are being used instead of cryptographic mechanisms. If neither cryptographic nor physical measures are being used, this is a finding.

To check that network encryption is enabled and using site-specified encryption procedures, look in SQLNET.ORA located at $ORACLE_HOME/network/admin/sqlnet.ora. If encryption is set, entries like the following will be present:

SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT= (SHA384)
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER= (SHA384)
SQLNET.ENCRYPTION_TYPES_CLIENT= (AES256)

SQLNET.ENCRYPTION_TYPES_SERVER= (AES256)
SQLNET.CRYPTO_CHECKSUM_CLIENT = requested
SQLNET.CRYPTO_CHECKSUM_SERVER = required

The values assigned to the parameters may be different, the combination of parameters may be different, and not all of the example parameters will necessarily exist in the file.'
  desc 'fix', 'Configure DBMS and/or operating system to use cryptographic mechanisms to prevent unauthorized disclosure of information during transmission where physical measures are not being used.'
  impact 0.7
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag gid: 'V-270579'
  tag rid: 'SV-270579r1065015_rule'
  tag stig_id: 'O19C-00-017700'
  tag fix_id: 'F-74513r1065014_fix'
  tag cci: ['CCI-002421', 'CCI-002420']
  tag nist: ['SC-8 (1)', 'Rev_4', 'SC-8 (2)']
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

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT= (SHA384)' }
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER= (SHA384)' }
    its('content') { should include 'SQLNET.ENCRYPTION_TYPES_CLIENT= (AES256)' }
    its('content') { should include 'SQLNET.ENCRYPTION_TYPES_SERVER= (AES256)' }
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_CLIENT = requested' }
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_SERVER = required' }
  end
end
