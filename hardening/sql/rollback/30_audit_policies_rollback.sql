-- rollback/30_audit_policies_rollback.sql — reverses 30_audit_policies.sql by
-- disabling (NOAUDIT) and dropping the tenant CG_AUDIT_POLICY it creates. Use in
-- local/dev only; removing this policy on a real system REDUCES the STIG posture
-- (drops auditing of REVOKE, CHANGE PASSWORD, SET USER PASSWORD, LOGOFF,
-- CREATE SPFILE) and should be a deliberate, reviewed action.
--
-- Does NOT touch the RDS-default policies (ORA_SECURECONFIG, ORA_LOGON_FAILURES):
-- those are platform-set and were never enabled by 30_audit_policies.sql.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

DECLARE
  v_en_cnt  PLS_INTEGER;
  v_pol_cnt PLS_INTEGER;
  c_policy  CONSTANT VARCHAR2(30) := 'CG_AUDIT_POLICY';
BEGIN
  -- 1) Disable (NOAUDIT) if currently enabled.
  BEGIN
    SELECT COUNT(DISTINCT POLICY_NAME) INTO v_en_cnt
      FROM AUDIT_UNIFIED_ENABLED_POLICIES
     WHERE POLICY_NAME = c_policy;
    IF v_en_cnt > 0 THEN
      EXECUTE IMMEDIATE 'NOAUDIT POLICY '||c_policy;
      DBMS_OUTPUT.PUT_LINE('disabled unified audit policy: '||c_policy);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already disabled: '||c_policy);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('skip disable '||c_policy||': '||SQLERRM);
  END;

  -- 2) Drop the policy if it exists.
  BEGIN
    SELECT COUNT(DISTINCT POLICY_NAME) INTO v_pol_cnt
      FROM AUDIT_UNIFIED_POLICIES
     WHERE POLICY_NAME = c_policy;
    IF v_pol_cnt > 0 THEN
      EXECUTE IMMEDIATE 'DROP AUDIT POLICY '||c_policy;
      DBMS_OUTPUT.PUT_LINE('dropped unified audit policy: '||c_policy);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already absent: '||c_policy);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('skip drop '||c_policy||': '||SQLERRM);
  END;
END;
/
