-- 90_validate.sql — ASSESSMENT ONLY. Post-hardening validation summary: prints a
-- PASS/REVIEW line per SQL-layer control so the before/after diff is legible.
-- This is development/operator signal; authoritative pass/fail is the InSpec run.
SET SERVEROUTPUT ON
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

DECLARE
  v_val VARCHAR2(100);
  PROCEDURE check_profile(p_res VARCHAR2, p_want VARCHAR2) IS
    v_limit VARCHAR2(100);
  BEGIN
    SELECT LIMIT INTO v_limit FROM DBA_PROFILES
     WHERE PROFILE='DEFAULT' AND RESOURCE_NAME=p_res;
    DBMS_OUTPUT.PUT_LINE(
      RPAD(p_res,28)||' = '||RPAD(v_limit,12)||
      CASE WHEN v_limit=p_want THEN ' [PASS]' ELSE ' [REVIEW want '||p_want||']' END);
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE(RPAD(p_res,28)||' = <error: '||SQLERRM||'>');
  END;
BEGIN
  DBMS_OUTPUT.PUT_LINE('=== SQL-layer validation (development/operator signal) ===');
  check_profile('FAILED_LOGIN_ATTEMPTS','3');
  check_profile('PASSWORD_LIFE_TIME','35');
  check_profile('INACTIVE_ACCOUNT_TIME','35');

  BEGIN
    SELECT COUNT(*) INTO v_val FROM AUDIT_UNIFIED_ENABLED_POLICIES
     WHERE POLICY_NAME IN ('ORA_SECURECONFIG','ORA_LOGON_FAILURES');
    DBMS_OUTPUT.PUT_LINE(RPAD('unified_audit_policies',28)||' = '||v_val||
      CASE WHEN TO_NUMBER(v_val) >= 2 THEN ' [PASS]' ELSE ' [REVIEW]' END);
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('unified_audit_policies check error: '||SQLERRM);
  END;
END;
/
