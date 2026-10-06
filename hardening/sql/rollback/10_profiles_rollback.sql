-- rollback/10_profiles_rollback.sql — resets the DEFAULT profile limits to Oracle
-- 19c VENDOR defaults. NOTE: this does NOT restore this database's pre-hardening
-- values (capture those from 01_inventory output first if you need a true
-- restore); it resets to the documented Oracle 19c out-of-the-box defaults. Use
-- only in local/dev; changing DEFAULT profile limits affects all users on that
-- profile.
--
-- A silently-partial rollback leaves the DEFAULT profile in an unknown mixed
-- state (some limits reset, some still hardened). Mirror the forward script
-- (10_profiles.sql): apply each reset with per-statement exception handling and
-- a failure counter, and RAISE on any failure so the run exits non-zero rather
-- than reporting a false success.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
-- EXIT (not CONTINUE): per-statement reset failures are caught by the block's inner
-- EXCEPTION handler and counted; only the final summarizing RAISE escapes, and under
-- WHENEVER SQLERROR EXIT it terminates the session non-zero. CONTINUE would print the
-- ORA-20013 but still exit 0 (a false PASS on a partial rollback). Mirrors 10_profiles.
WHENEVER SQLERROR EXIT SQL.SQLCODE

DECLARE
  TYPE limit_list IS TABLE OF VARCHAR2(100);
  -- Oracle 19c out-of-the-box DEFAULT profile limits (NOT this DB's pre-hardening
  -- values — see header note).
  limits limit_list := limit_list(
    'FAILED_LOGIN_ATTEMPTS 10',
    'PASSWORD_LIFE_TIME 180',
    'PASSWORD_LOCK_TIME 1',
    'PASSWORD_REUSE_MAX UNLIMITED',
    'INACTIVE_ACCOUNT_TIME UNLIMITED'
  );
  v_failures PLS_INTEGER := 0;
  v_acted    PLS_INTEGER := 0;
BEGIN
  FOR i IN 1 .. limits.COUNT LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER PROFILE DEFAULT LIMIT '||limits(i);
      v_acted := v_acted + 1;
      DBMS_OUTPUT.PUT_LINE('reset DEFAULT limit: '||limits(i));
    EXCEPTION
      WHEN OTHERS THEN
        v_failures := v_failures + 1;
        DBMS_OUTPUT.PUT_LINE('ERROR DEFAULT limit '||limits(i)||': '||SQLERRM);
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('rollback/10_profiles: acted='||v_acted||' failures='||v_failures);
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20013, 'rollback/10_profiles: '||v_failures||' profile limit(s) failed');
  END IF;
END;
/

PROMPT rollback/10_profiles: DEFAULT profile limits reset to Oracle 19c vendor defaults.
PROMPT (does NOT restore pre-hardening values; use 01_inventory capture for a true restore)
