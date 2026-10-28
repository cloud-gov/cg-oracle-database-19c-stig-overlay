-- customer-hardening.sql -- ordered customer hardening runbook.
--
-- This driver must be preceded by a reviewed input file that defines:
--   assign_users, verify_function, and session_headroom.
-- See customer-hardening-input.sql.example. The input contains organization-
-- defined, non-secret values; it is deliberately separate from this runbook.
--
-- Assessment-only scripts (00, 01, 40, and 50) and rollback scripts are not
-- included. This applies every database-altering customer hardening script.
WHENEVER OSERROR EXIT FAILURE
WHENEVER SQLERROR EXIT SQL.SQLCODE

@@10_profiles.sql
SET DEFINE ON
@@11_ora_stig_profile.sql &&assign_users
@@12_password_verify_function.sql &&verify_function
@@15_concurrent_sessions.sql &&session_headroom
@@20_users_roles_privileges.sql
@@30_audit_policies.sql
@@60_temporary_users.sql

PROMPT customer-hardening: all customer hardening scripts completed.
