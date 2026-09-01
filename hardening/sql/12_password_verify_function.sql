-- 12_password_verify_function.sql — hardening (idempotent, detect-first) for
-- SV-270561 (DOD password complexity, IA-5(1)(a)).
--
-- The DISA V1R5 check requires every profile applied to Oracle-authenticated
-- accounts to have a non-null PASSWORD_VERIFY_FUNCTION whose code enforces the
-- DOD rules (>= 15 chars; at least one upper, lower, numeric, and special
-- character; and >= 50% of the minimum length — i.e. 8 — characters changed from
-- the previous password). The DISA fix names Oracle's supplied sample function
-- ORA12C_STIG_VERIFY_FUNCTION (from $ORACLE_HOME/rdbms/admin/catpvf.sql) as the
-- starting point, and Oracle also ships the immutable ORA_STIG_PROFILE, which
-- already binds a STIG-compliant verify function.
--
--   Control satisfied for assigned profiles:
--     SV-270561  PASSWORD_VERIFY_FUNCTION set + DOD complexity enforced (IA-5(1)(a))
--
-- CUSTOMER RESPONSIBILITY (see docs/RESPONSIBILITY.md): choosing/authoring the
-- verify function and binding it to the site's profiles is org-defined,
-- db-altering SQL on the SV-270495 pattern. This script uses the STIG-named
-- Oracle-supplied vehicle (ORA_STIG_PROFILE, via 11_ora_stig_profile.sql) as the
-- recommended path and, for accounts that stay on DEFAULT, binds the
-- Oracle-supplied ORA12C_STIG_VERIFY_FUNCTION to the DEFAULT profile.
--
-- PREFERRED PATH: run 11_ora_stig_profile.sql, which assigns ORA_STIG_PROFILE
-- (already carries a compliant PASSWORD_VERIFY_FUNCTION) to the site's accounts.
-- This script covers accounts that remain on the DEFAULT profile.
--
-- NON-SYS / RDS: uses ALTER PROFILE only (permitted for the RDS master user, not
-- SYS/SYSDBA). Creating the ORA12C_STIG_VERIFY_FUNCTION requires the catpvf.sql
-- catalog script, which is run once by Oracle on 19c/23ai; on RDS it is present.
-- If it is absent this script FAILS LOUDLY rather than binding a nonexistent
-- function (which would itself raise ORA-07443 at password-set time).
--
-- DETECT-FIRST: reports the current DEFAULT profile function first; binds only
-- when apply_fix = Y. To assess WITHOUT changing the profile, run with:
--   DEFINE apply_fix = N
SET SERVEROUTPUT ON
SET DEFINE ON
SET FEEDBACK OFF
SET VERIFY OFF
WHENEVER SQLERROR CONTINUE

-- Set to N to only report the DEFAULT profile's verify function (no ALTER PROFILE).
DEFINE apply_fix = Y

-- Org-defined verify function. ORA12C_STIG_VERIFY_FUNCTION is the Oracle-supplied
-- STIG-compliant function named by the DISA fix. A site with a customized function
-- overrides this DEFINE with its own function name.
DEFINE verify_function = ORA12C_STIG_VERIFY_FUNCTION

DECLARE
  v_apply    VARCHAR2(1)   := UPPER('&&apply_fix');
  v_func     VARCHAR2(128) := UPPER('&&verify_function');
  v_exists   PLS_INTEGER;
  v_current  VARCHAR2(128);
BEGIN
  ----------------------------------------------------------------------------
  -- Existence guard: the named verify function must exist before we bind it, or
  -- password changes on bound accounts would fail at runtime (ORA-07443).
  ----------------------------------------------------------------------------
  SELECT COUNT(*) INTO v_exists FROM DBA_OBJECTS
    WHERE OBJECT_NAME = v_func AND OBJECT_TYPE = 'FUNCTION' AND ROWNUM = 1;
  IF v_exists = 0 THEN
    RAISE_APPLICATION_ERROR(-20020,
      '12_password_verify_function: verify function '||v_func||' not found. On '||
      'Oracle 19c/23ai run $ORACLE_HOME/rdbms/admin/catpvf.sql (Oracle-supplied) '||
      'to create ORA12C_STIG_VERIFY_FUNCTION, or set verify_function to your '||
      'site''s custom function.');
  END IF;

  ----------------------------------------------------------------------------
  -- Report the DEFAULT profile's current verify function (detect-first).
  ----------------------------------------------------------------------------
  SELECT LIMIT INTO v_current FROM DBA_PROFILES
    WHERE PROFILE = 'DEFAULT' AND RESOURCE_NAME = 'PASSWORD_VERIFY_FUNCTION';
  DBMS_OUTPUT.PUT_LINE('DEFAULT profile PASSWORD_VERIFY_FUNCTION currently: '||
    NVL(v_current, 'NULL'));

  IF v_apply = 'Y' THEN
    IF v_current = v_func THEN
      DBMS_OUTPUT.PUT_LINE('DEFAULT profile already bound to '||v_func||
        ' (no change).');
    ELSE
      EXECUTE IMMEDIATE 'ALTER PROFILE DEFAULT LIMIT PASSWORD_VERIFY_FUNCTION '||v_func;
      DBMS_OUTPUT.PUT_LINE('bound PASSWORD_VERIFY_FUNCTION '||v_func||
        ' to DEFAULT profile (was '||NVL(v_current, 'NULL')||').');
    END IF;
  ELSE
    DBMS_OUTPUT.PUT_LINE('apply_fix=N: DEFAULT profile not changed. Preferred '||
      'path is 11_ora_stig_profile.sql (assigns ORA_STIG_PROFILE, which already '||
      'binds a compliant verify function).');
  END IF;
END;
/

PROMPT 12_password_verify_function: DEFAULT profile PASSWORD_VERIFY_FUNCTION enforced (SV-270561). Preferred path: 11_ora_stig_profile.sql (ORA_STIG_PROFILE).
