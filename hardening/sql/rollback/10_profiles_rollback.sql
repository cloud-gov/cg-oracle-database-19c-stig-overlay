-- rollback/10_profiles_rollback.sql — reverts 10_profiles.sql to DEFAULT profile
-- Oracle defaults. Use only in local/dev; on a real system, changing profile
-- limits affects all users on the DEFAULT profile.
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS 10;
ALTER PROFILE DEFAULT LIMIT PASSWORD_LIFE_TIME 180;
ALTER PROFILE DEFAULT LIMIT PASSWORD_LOCK_TIME 1;
ALTER PROFILE DEFAULT LIMIT PASSWORD_REUSE_MAX UNLIMITED;
ALTER PROFILE DEFAULT LIMIT INACTIVE_ACCOUNT_TIME UNLIMITED;

PROMPT rollback/10_profiles: DEFAULT profile limits reverted to Oracle defaults.
