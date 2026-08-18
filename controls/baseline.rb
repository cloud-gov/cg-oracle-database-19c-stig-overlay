# Include ALL Oracle 19c STIG controls from the depended-on baseline and, on a
# platform-only run, skip the CUSTOMER-responsibility controls in-place (they are
# not FAILED by remediation the tenant owns). Rationale, criteria, postures, and
# how to add a control: docs/RESPONSIBILITY.md.

skip_customer = input('skip_customer_responsibility_controls') == true

include_controls 'oracle-database-19c-stig-baseline' do
  if skip_customer
    skip_control 'SV-270495'  # SESSIONS_PER_USER — org-defined value; see docs/RESPONSIBILITY.md
  end
end
