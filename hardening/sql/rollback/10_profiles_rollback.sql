-- rollback/10_profiles_rollback.sql — resets the DEFAULT profile limits to Oracle
-- 19c VENDOR defaults. NOTE: this does NOT restore this database's pre-hardening
-- values (capture those from 01_inventory output first if you need a true
-- restore); it resets to the documented Oracle 19c out-of-the-box defaults. Use
-- only in local/dev; changing DEFAULT profile limits affects all users on that
-- profile.
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS 10;
ALTER PROFILE DEFAULT LIMIT PASSWORD_LIFE_TIME 180;
ALTER PROFILE DEFAULT LIMIT PASSWORD_LOCK_TIME 1;
ALTER PROFILE DEFAULT LIMIT PASSWORD_REUSE_MAX UNLIMITED;
ALTER PROFILE DEFAULT LIMIT INACTIVE_ACCOUNT_TIME UNLIMITED;

PROMPT rollback/10_profiles: DEFAULT profile limits reset to Oracle 19c vendor defaults.
PROMPT (does NOT restore pre-hardening values; use 01_inventory capture for a true restore)
