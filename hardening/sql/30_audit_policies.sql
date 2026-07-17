-- 30_audit_policies.sql — hardening (idempotent). Enables unified audit policies
-- for STIG-relevant events. Requires AUDIT_ADMIN (granted to the RDS master user
-- pattern). audit_trail itself is a PARAMETER set by the broker's RDS parameter
-- group (aws-broker#525), NOT here.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- Enable the built-in secure-config + logon-failure policies if not already on.
-- CREATE AUDIT POLICY / AUDIT are idempotent via the guard below.
DECLARE
  PROCEDURE enable_policy(p_name VARCHAR2) IS
    v_cnt PLS_INTEGER;
  BEGIN
    SELECT COUNT(*) INTO v_cnt FROM AUDIT_UNIFIED_ENABLED_POLICIES
     WHERE POLICY_NAME = p_name;
    IF v_cnt = 0 THEN
      EXECUTE IMMEDIATE 'AUDIT POLICY '||p_name;
      DBMS_OUTPUT.PUT_LINE('enabled unified audit policy: '||p_name);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already enabled: '||p_name);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('skip '||p_name||' (reason: '||SQLERRM||')');
  END;
BEGIN
  -- Oracle-provided policies present in 19c.
  enable_policy('ORA_SECURECONFIG');
  enable_policy('ORA_LOGON_FAILURES');
END;
/

PROMPT 30_audit_policies: unified audit policies enabled (idempotent).
