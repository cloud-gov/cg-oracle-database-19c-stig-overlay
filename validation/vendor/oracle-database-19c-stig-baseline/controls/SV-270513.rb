control 'SV-270513' do
  title 'Oracle Database products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the system documentation and interview the database administrator.

Identify all database software components.

Review the version and release information.

From SQL*Plus:
Select version from v$instance;

Access the vendor website or use other means to verify the version is still supported.
Oracle Release schedule:
https://support.oracle.com/knowledge/Oracle%20Database%20Products/742060_1.html

If the Oracle version or any of the software components are not supported by the vendor, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products.

Upgrade unsupported DBMS or unsupported components to a supported version of the product.'
  impact 0.7
  tag check_id: 'C-74546r1064815_chk'
  tag severity: 'high'
  tag gid: 'V-270513'
  tag rid: 'SV-270513r1138543_rule'
  tag stig_id: 'O19C-00-007400'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-74447r1064816_fix'
  tag 'documentable'
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']

  # PORTED FROM 12c V-61539 (overlay #6). DBMS must be a vendor-supported
  # version. Reports the running version for review against supported releases.
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  version = sql.query("SELECT version FROM v$instance;").column('version')
  describe 'Oracle Database version (must be a vendor-supported release)' do
    subject { version.first }
    it { should_not be_nil }
  end
end
