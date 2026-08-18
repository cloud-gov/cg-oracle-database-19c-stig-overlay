-- 15_concurrent_sessions.sql — hardening (idempotent) for SV-270495
-- (O19C-00-000100 / SRG-APP-000001-DB-000031 / CCI-000054 / AC-10):
-- "Oracle Database must limit the number of concurrent sessions for each system
-- account to an organization-defined number of sessions."
--
-- STIG fix:  ALTER PROFILE <profile_name> LIMIT SESSIONS_PER_USER <integer>;
--
-- CUSTOMER RESPONSIBILITY (see docs/RESPONSIBILITY.md): the <integer> is an
-- ORGANIZATION-DEFINED value the platform cannot choose for the tenant, so this
-- script is *sample* remediation only. It sets a conservative, non-UNLIMITED,
-- non-DEFAULT value on the DEFAULT profile so the baseline check (SV-270495 reads
-- SESSIONS_PER_USER and fails on 'UNLIMITED'/'DEFAULT') passes. The tenant MUST
-- review the value against their own work-requirements (an app connection pool may
-- need hundreds; a single-session user may need 1) and adjust before treating this
-- as compliant. Uses ALTER PROFILE (permitted for the RDS master user; non-SYS).
--
-- To use a site-specific value, edit the &&sessions_per_user default below (this
-- file is run through sqlplus/sqlcl, which honor substitution variables — see
-- runner/README.md; db-query.sh/oraquery does NOT interpret them).
SET DEFINE ON
SET FEEDBACK OFF
SET VERIFY OFF
WHENEVER SQLERROR CONTINUE

-- Organization-defined session limit. DEFAULT here is a sample starting value,
-- NOT a Cloud.gov recommendation. Override at run time:  DEFINE sessions_per_user=<n>
DEFINE sessions_per_user = 10

-- ALTER PROFILE is idempotent: re-running with the same limit is a no-op. Setting
-- an explicit integer clears the non-compliant 'UNLIMITED'/'DEFAULT' state that
-- SV-270495 flags. STIG: SRG-APP-000001-DB-000031 (AC-10).
ALTER PROFILE DEFAULT LIMIT SESSIONS_PER_USER &&sessions_per_user;

PROMPT 15_concurrent_sessions: DEFAULT profile SESSIONS_PER_USER set (SV-270495).
PROMPT   NOTE: value is a SAMPLE (org-defined). Review per docs/RESPONSIBILITY.md.
