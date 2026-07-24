control 'SV-270498' do
  title 'Oracle Database must associate organization-defined types of security labels having organization-defined security label values with information in storage.'
  desc 'Without the association of security labels to information, there is no basis for the database management system (DBMS) to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling, or distribution instructions, or support other aspects of the information security policy. 

One example includes marking data as classified or CUI. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

Some DBMS systems provide the feature to assign security labels to data elements. If labeling is required, implementation options include the Oracle Label Security package, or a third-party product, or custom-developed functionality. The confidentiality and integrity of the data depends upon the security label assignment where this feature is in use.

'
  desc 'check', 'If no data has been identified as being sensitive or classified in the system documentation, this is not a finding.

If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but the security labeling is not implemented or does not reliably maintain labels on information in storage, this is a finding.'
  desc 'fix', 'Define the policy for security labels defined for the data. 

Document the security label requirements and configure database security labels in accordance with the policy.

To provide reliable security labeling of information in storage, enable DBMS features; deploy third-party software; or add custom data structures, data elements, and application code.

Oracle recommends Oracle Label Security.

For additional information on Oracle Label Security:
https://docs.oracle.com/en/database/oracle/oracle-database/19/olsag/label-security-administrators-guide.pdf.'
  impact 0.5
  tag check_id: 'C-74531r1064770_chk'
  tag severity: 'medium'
  tag gid: 'V-270498'
  tag rid: 'SV-270498r1167732_rule'
  tag stig_id: 'O19C-00-000500'
  tag gtitle: 'SRG-APP-000311-DB-000308'
  tag fix_id: 'F-74432r1167731_fix'
  tag satisfies: ['SRG-APP-000311-DB-000308', 'SRG-APP-000313-DB-000309', 'SRG-APP-000314-DB-000310']
  tag 'documentable'
  tag cci: ['CCI-002262', 'CCI-002263', 'CCI-002264']
  tag nist: ['AC-16 a', 'AC-16 a', 'AC-16 a']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'security labeling (Oracle Label Security) is policy/config-defined' do
    skip 'security labeling (Oracle Label Security) is policy/config-defined'
  end
end
