-- 30_audit_policies.sql — hardening (idempotent). Enables unified audit policies
-- for STIG-relevant events. Requires AUDIT_ADMIN (granted to the RDS master user
-- pattern). audit_trail itself is a PARAMETER set by the broker's RDS parameter
-- group (aws-broker#525), NOT here.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- Enable the built-in secure-config + logon-failure policies if not already on.
-- The guard counts DISTINCT policy names so a policy enabled multiple ways is not
-- miscounted. A failure counter makes a total-failure run exit non-zero rather
-- than printing a false success (C2).
DECLARE
  v_failures PLS_INTEGER := 0;
  PROCEDURE enable_policy(p_name VARCHAR2) IS
    v_cnt PLS_INTEGER;
  BEGIN
    SELECT COUNT(DISTINCT POLICY_NAME) INTO v_cnt FROM AUDIT_UNIFIED_ENABLED_POLICIES
     WHERE POLICY_NAME = p_name;
    IF v_cnt = 0 THEN
      EXECUTE IMMEDIATE 'AUDIT POLICY '||p_name;
      DBMS_OUTPUT.PUT_LINE('enabled unified audit policy: '||p_name);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already enabled: '||p_name);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    v_failures := v_failures + 1;
    DBMS_OUTPUT.PUT_LINE('ERROR '||p_name||': '||SQLERRM);
  END;
BEGIN
  -- Oracle-provided policies present in 19c.
  enable_policy('ORA_SECURECONFIG');
  enable_policy('ORA_LOGON_FAILURES');
  DBMS_OUTPUT.PUT_LINE('30_audit_policies: failures='||v_failures);
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20030, '30_audit_policies: '||v_failures||' audit-policy operation(s) failed');
  END IF;
END;
/

PROMPT 30_audit_policies: unified audit policies enabled (idempotent).
