control 'SV-270499' do
  title 'Oracle Database must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to act on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in noncentralized account stores, such as multiple servers. Account management functions can also include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

Oracle Database must be configured to automatically use organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, and not by Oracle, this is not a finding.

If an Oracle feature/product, an OS feature, a third-party product, or custom code is used to automate account management, this is not a finding.

If there are any accounts managed by the Oracle Database, review the system documentation for justification and approval of these accounts.

If any Oracle-managed accounts exist that are not documented and approved, this is a finding.'
  desc 'fix', 'Integrate database management system (DBMS) security with an organization-level authentication/access mechanism providing account management for all users, groups, roles, and any other principals.

For each Oracle-managed account that is not documented and approved, either transfer it to management by the external mechanism, or document the need for it and obtain approval, as appropriate.

Utilize an Oracle feature/product, an OS feature, a third-party product, or custom code to automate as much account maintenance functionality as possible.'
  impact 0.7
  tag check_id: 'C-74532r1064773_chk'
  tag severity: 'high'
  tag gid: 'V-270499'
  tag rid: 'SV-270499r1064775_rule'
  tag stig_id: 'O19C-00-000800'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-74433r1064774_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']

  # OVERLAY-ADDED (MANUAL-REVIEW, overlay #6): upstream shipped this as an empty stub
  # (silent pass). Marked as an explicit review so it can never silently pass.
  describe 'enterprise/OS-authenticated account management (external mechanism)' do
    skip 'enterprise/OS-authenticated account management (external mechanism)'
  end
end
