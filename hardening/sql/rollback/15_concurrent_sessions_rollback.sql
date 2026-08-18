-- rollback/15_concurrent_sessions_rollback.sql — reverses
-- 15_concurrent_sessions.sql by resetting the DEFAULT profile SESSIONS_PER_USER to
-- the Oracle 19c VENDOR default (UNLIMITED). NOTE: this does NOT restore this
-- database's pre-hardening value (capture that from 01_inventory first for a true
-- restore); it resets to the documented Oracle 19c out-of-the-box default. Use
-- only in local/dev — resetting to UNLIMITED REDUCES the STIG posture (it re-opens
-- the SV-270495 finding) and must be a deliberate, reviewed action.
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

ALTER PROFILE DEFAULT LIMIT SESSIONS_PER_USER UNLIMITED;

PROMPT rollback/15_concurrent_sessions: DEFAULT SESSIONS_PER_USER reset to Oracle 19c vendor default (UNLIMITED).
PROMPT (does NOT restore pre-hardening value; use 01_inventory capture for a true restore. Re-opens SV-270495.)
