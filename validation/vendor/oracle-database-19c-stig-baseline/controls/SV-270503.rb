control 'SV-270503' do
  title 'Oracle Database must allow designated organizational personnel to select which auditable events are to be audited by the database.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Check database management system (DBMS) settings and documentation to determine whether designated personnel are able to select which auditable events are being audited. 

If designated personnel are not able to configure auditable events, this is a finding.'
  desc 'fix', %q(Configure the DBMS's settings to allow designated personnel to select which auditable events are audited.

Note: In Oracle, any user can configure auditing for the objects in their own schema by using the AUDIT statement. To undo the audit configuration for an object, the user can use the NOAUDIT statement. No additional privileges are needed to perform this task.

To audit objects in another schema, the user must have the AUDIT ANY system privilege.

To audit system privileges, the user must have the AUDIT SYSTEM privilege.

For more information on the configuration of auditing, refer to the following documents:

"Monitoring Database Activity with Auditing" in the Oracle Database Security Guide:
https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/part_6.html)
  impact 0.5
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag gid: 'V-270503'
  tag rid: 'SV-270503r1064787_rule'
  tag stig_id: 'O19C-00-001900'
  tag fix_id: 'F-74437r1064786_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b', 'Rev_4']
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

  describe 'A manual review is required to ensure the DBMS allows designated organizational personnel to select
    which auditable events are to be audited by the database' do
    skip 'A manual review is required to ensure the DBMS allows designated organizational personnel to select
    which auditable events are to be audited by the database'
  end
end
