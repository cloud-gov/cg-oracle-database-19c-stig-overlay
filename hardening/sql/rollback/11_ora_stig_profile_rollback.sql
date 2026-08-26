-- rollback/11_ora_stig_profile_rollback.sql — reverses 11_ora_stig_profile.sql.
--
-- 11_ only ASSIGNS the Oracle-supplied ORA_STIG_PROFILE to accounts; it never
-- creates or modifies the (immutable, Oracle-maintained) profile. This rollback
-- therefore only moves the accounts 11_ reassigned back to the DEFAULT profile.
-- It never drops ORA_STIG_PROFILE (it is Oracle-supplied and cannot be dropped —
-- ORA-02384 — and its presence is not a finding).
--
-- NOTE: this resets accounts to DEFAULT (the Oracle out-of-the-box assignment),
-- NOT to each account's PRE-hardening profile — capture that from 01_inventory
-- output first for a true restore. Reassigning to DEFAULT re-opens the
-- SV-270549/550/551 findings for those accounts unless DEFAULT was hardened by
-- 10_profiles.sql. Use only in local/dev or a deliberate operator action.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

DECLARE
  v_failures   PLS_INTEGER := 0;
  v_moved      PLS_INTEGER := 0;

  -- Same exclusion list as 11_: never touch operator/platform accounts even if
  -- they somehow ended up on the profile. Comma-bounded string so it can be used
  -- in a plain SQL cursor predicate (a PL/SQL-local collection cannot appear in a
  -- SQL TABLE(...) operator — ORA-22905/PLS-00642).
  c_exclusions CONSTANT VARCHAR2(400) :=
    ',RDSADMIN,RDS_MASTER,ADMIN,SYSRAC,SYS,SYSTEM,';
BEGIN
  -- Move non-Oracle, non-excluded accounts off ORA_STIG_PROFILE back to DEFAULT.
  FOR u IN (
    SELECT du.USERNAME
      FROM DBA_USERS du
     WHERE du.PROFILE = 'ORA_STIG_PROFILE'
       AND du.ORACLE_MAINTAINED = 'N'
       AND INSTR(c_exclusions, ','||du.USERNAME||',') = 0
     ORDER BY du.USERNAME
  ) LOOP
    BEGIN
      EXECUTE IMMEDIATE 'ALTER USER "'||u.USERNAME||'" PROFILE DEFAULT';
      v_moved := v_moved + 1;
      DBMS_OUTPUT.PUT_LINE('reset '||u.USERNAME||' to DEFAULT profile');
    EXCEPTION WHEN OTHERS THEN
      v_failures := v_failures + 1;
      DBMS_OUTPUT.PUT_LINE('ERROR resetting '||u.USERNAME||': '||SQLERRM);
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('rollback/11_ora_stig_profile: moved='||v_moved||
    ' failures='||v_failures||' (ORA_STIG_PROFILE left in place - Oracle-supplied)');
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20111,
      'rollback/11_ora_stig_profile: '||v_failures||' operation(s) failed');
  END IF;
END;
/

PROMPT rollback/11_ora_stig_profile: accounts reset to DEFAULT; Oracle-supplied ORA_STIG_PROFILE left in place.
PROMPT (does NOT restore pre-hardening profile assignments; use 01_inventory capture for a true restore)
