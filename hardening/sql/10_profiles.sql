-- 10_profiles.sql — hardening (idempotent). Enforce STIG password/lockout limits
-- on the DEFAULT profile. Uses ALTER PROFILE (permitted for the RDS master user).
-- Values align with the overlay inputs (failed_logon_attempts=3,
-- password_life_time=35, account_inactivity_age=35).
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- ALTER PROFILE is idempotent: setting a limit to its target value is a no-op if
-- already set. STIG: SRG-APP-000065 (lockout), SRG-APP-000174 (password lifetime).
ALTER PROFILE DEFAULT LIMIT FAILED_LOGIN_ATTEMPTS 3;         -- SV-270550 (<=3)
-- SV-270563: EFFECTIVE_LIFE_TIME (PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME) must
-- be <=60 and neither component UNLIMITED. The Oracle vendor DEFAULT of
-- LIFE_TIME 35 + GRACE_TIME 7 = 42 already satisfies this (42 <= 60), so no
-- change to those limits is needed here. Keep LIFE_TIME 35 to preserve the
-- ORA-28002 grace/warning window on DEFAULT (the RDS master and broker app user
-- live there); setting GRACE_TIME 0 would remove the soft-fail runway.
ALTER PROFILE DEFAULT LIMIT PASSWORD_LIFE_TIME 35;
-- SV-270549 requires lockout persist until an administrator resets it:
-- PASSWORD_LOCK_TIME must be UNLIMITED (not a finite auto-unlock window).
ALTER PROFILE DEFAULT LIMIT PASSWORD_LOCK_TIME UNLIMITED;    -- SV-270549 (UNLIMITED)
ALTER PROFILE DEFAULT LIMIT PASSWORD_REUSE_MAX 10;
ALTER PROFILE DEFAULT LIMIT INACTIVE_ACCOUNT_TIME 35;        -- SV-270551 (<=35)

PROMPT 10_profiles: DEFAULT profile limits enforced (idempotent).
