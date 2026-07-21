-- rollback/30_audit_policies_rollback.sql — reverses 30_audit_policies.sql by
-- NOISY (idempotent) disabling of the unified audit policies it enables. Use in
-- local/dev only; disabling audit policies on a real system REDUCES the STIG
-- posture and should be a deliberate, reviewed action.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

DECLARE
  PROCEDURE disable_policy(p_name VARCHAR2) IS
    v_cnt PLS_INTEGER;
  BEGIN
    SELECT COUNT(DISTINCT POLICY_NAME) INTO v_cnt FROM AUDIT_UNIFIED_ENABLED_POLICIES
     WHERE POLICY_NAME = p_name;
    IF v_cnt > 0 THEN
      EXECUTE IMMEDIATE 'NOAUDIT POLICY '||p_name;
      DBMS_OUTPUT.PUT_LINE('disabled unified audit policy: '||p_name);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already disabled: '||p_name);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('skip '||p_name||': '||SQLERRM);
  END;
BEGIN
  disable_policy('ORA_SECURECONFIG');
  disable_policy('ORA_LOGON_FAILURES');
END;
/
