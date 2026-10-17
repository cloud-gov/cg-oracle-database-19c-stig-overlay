-- 10_profiles.sql — hardening (idempotent). Enforce STIG password/lockout limits
-- on the DEFAULT profile. Uses ALTER PROFILE (permitted for the RDS master user).
-- Values align with the overlay inputs (failed_logon_attempts=3,
-- password_life_time=35, account_inactivity_age=35).
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
-- EXIT (not CONTINUE) so the summarizing RAISE_APPLICATION_ERROR at the end of the
-- block below terminates the SQLcl session NON-ZERO. Per-statement ALTER PROFILE
-- failures do NOT abort the run: they are caught by the block's inner EXCEPTION
-- handler (which increments v_failures and continues the loop), so they never reach
-- this WHENEVER. Only the final RAISE — emitted once if v_failures > 0 — propagates
-- to SQLcl and, under EXIT, yields a non-zero exit. Using CONTINUE here would print
-- the ORA-20013 but still exit 0 (a false PASS).
WHENEVER SQLERROR EXIT SQL.SQLCODE

-- ALTER PROFILE is idempotent: setting a limit to its target value is a no-op if
-- already set. STIG: SRG-APP-000065 (lockout), SRG-APP-000174 (password lifetime).
--
-- Each limit is applied with per-statement exception handling and a failure
-- counter, matching 20_/30_. Without this, a rejected ALTER PROFILE (RDS can
-- reject ALTER PROFILE via a DDL trigger — see ORA-20900 on ALTER PROFILE
-- RDSADMIN, baseline #16) would be caught by the inner EXCEPTION handler and
-- counted; the run would otherwise record a false success with password/lockout
-- controls only partially applied. A non-zero failure count RAISEs the final
-- ORA-20013 which, under WHENEVER SQLERROR EXIT SQL.SQLCODE, exits non-zero.
--
-- SV-270563: EFFECTIVE_LIFE_TIME (PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME) must
-- be <=60 and neither component UNLIMITED. The Oracle vendor DEFAULT of
-- LIFE_TIME 35 + GRACE_TIME 7 = 42 already satisfies this (42 <= 60), so no
-- change to those limits is needed here. Keep LIFE_TIME 35 to preserve the
-- ORA-28002 grace/warning window on DEFAULT (the RDS master and broker app user
-- live there); setting GRACE_TIME 0 would remove the soft-fail runway.
-- SV-270549 requires lockout persist until an administrator resets it:
-- PASSWORD_LOCK_TIME must be UNLIMITED (not a finite auto-unlock window).
DECLARE
  TYPE limit_list IS TABLE OF VARCHAR2(100);
  -- Each entry is the trailing "<LIMIT_NAME> <value>" of an ALTER PROFILE DEFAULT
  -- LIMIT statement. Documented STIG mappings are inline above / in comments.
  limits limit_list := limit_list(
    'FAILED_LOGIN_ATTEMPTS 3',      -- SV-270550 (<=3)
    'PASSWORD_LIFE_TIME 35',        -- SV-270563 (component of EFFECTIVE_LIFE_TIME)
    'PASSWORD_LOCK_TIME UNLIMITED', -- SV-270549 (UNLIMITED)
    'PASSWORD_REUSE_MAX 10',
    'INACTIVE_ACCOUNT_TIME 35'      -- SV-270551 (<=35)
  );
  v_failures PLS_INTEGER := 0;
  v_acted    PLS_INTEGER := 0;
BEGIN
  FOR i IN 1 .. limits.COUNT LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER PROFILE DEFAULT LIMIT '||limits(i);
      v_acted := v_acted + 1;
      DBMS_OUTPUT.PUT_LINE('applied DEFAULT limit: '||limits(i));
    EXCEPTION
      WHEN OTHERS THEN
        v_failures := v_failures + 1;
        DBMS_OUTPUT.PUT_LINE('ERROR DEFAULT limit '||limits(i)||': '||SQLERRM);
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('10_profiles: acted='||v_acted||' failures='||v_failures);
  -- Fail loudly if any limit was rejected, so an automated run cannot record a
  -- false PASS (the run exits non-zero via the WHENEVER below). Error number is
  -- kept unique across the hardening set (11_=-20010/-20011, 15_=-20016,
  -- 20_/12_=-20020, 30_=-20030, 60_=-20060); 10_ uses -20013.
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20013, '10_profiles: '||v_failures||' profile limit(s) failed');
  END IF;
END;
/

PROMPT 10_profiles: DEFAULT profile limits enforced (idempotent).
