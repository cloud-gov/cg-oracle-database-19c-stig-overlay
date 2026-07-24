control 'SV-270511' do
  title 'The system must protect audit tools from unauthorized access, modification, or deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data.

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records.

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.

'
  desc 'check', 'Review access permissions to tools used to view or modify audit log data. These tools may include the database management system (DBMS) itself or tools external to the database.

If appropriate permissions and access controls are not applied to prevent unauthorized access, modification, or deletion of these tools, this is a finding.'
  desc 'fix', 'Add or modify access controls and permissions to tools used to view or modify audit log data. Tools must be accessible by authorized personnel only.'
  impact 0.5
  tag check_id: 'C-74544r1064809_chk'
  tag severity: 'medium'
  tag gid: 'V-270511'
  tag rid: 'SV-270511r1065262_rule'
  tag stig_id: 'O19C-00-006900'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-74445r1064810_fix'
  tag satisfies: ['SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']

  # PORTED FROM 12c V-61659 (overlay #6). Protect audit TOOLS: AUDSYS object
  # privileges limited to authorized audit users.
  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'), sqlcl_bin: input('sqlcl_bin'))
  grantees = sql.query("SELECT GRANTEE FROM DBA_TAB_PRIVS WHERE owner='AUDSYS';").column('grantee').uniq
  if grantees.empty?
    describe 'No AUDSYS object-privilege grantees' do
      subject { grantees }
      it { should be_empty }
    end
  else
    grantees.each do |g|
      describe "AUDSYS object-privilege grantee #{g}" do
        subject { g }
        it { should be_in input('allowed_audit_users') }
      end
    end
  end
end
