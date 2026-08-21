-- 30_audit_policies.sql — hardening (idempotent). Creates and enables a tenant
-- unified audit policy (CG_AUDIT_POLICY) covering STIG-relevant auditable events
-- that are NOT already captured by the Oracle-provided default policies on RDS.
--
-- Requires AUDIT_ADMIN (granted to the RDS master user pattern). audit_trail
-- itself is a PARAMETER set by the broker's RDS parameter group (aws-broker#525),
-- NOT here.
--
-- RDS DEFAULTS (do NOT re-enable here): RDS for Oracle enables ORA_SECURECONFIG
-- and ORA_LOGON_FAILURES BY DEFAULT once audit_trail is routed to a DB
-- destination. Those cover privilege GRANT, security-config/DDL, most account
-- administration (CREATE/ALTER/DROP USER, incl. admin password changes via
-- ALTER USER), ALTER SYSTEM/DATABASE, and LOGON. This script therefore only adds
-- the events the defaults MISS (SV-270504 / AU-12 c):
--   REVOKE, CHANGE PASSWORD, LOGOFF, CREATE SPFILE
-- These are Oracle unified-audit standard *action* names (AUDITABLE_SYSTEM_ACTIONS),
-- confirmed valid + not covered by the RDS defaults on live RDS 19c SE2. Oracle
-- auto-expands the XS-namespace variants (e.g. REVOKE -> REVOKE ROLE / REVOKE
-- SYSTEM PRIVILEGE, CHANGE PASSWORD -> SET USER PASSWORD) when the policy is
-- created; those appear as AUDIT_OPTION_TYPE='XS ACTION' rows and need not be
-- specified (specifying SET USER PASSWORD directly fails ORA-46356).
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- Create CG_AUDIT_POLICY if absent, then enable it for ALL USERS (success and
-- failure). Idempotent: an existing policy is left in place (Oracle has no
-- portable ALTER-to-add-actions that is safe to re-run, so we do not recreate),
-- and an already-enabled policy is not re-enabled. A failure counter makes a
-- total-failure run exit non-zero rather than printing a false success (C2).
DECLARE
  v_failures  PLS_INTEGER := 0;
  v_pol_cnt   PLS_INTEGER;
  v_en_cnt    PLS_INTEGER;
  c_policy    CONSTANT VARCHAR2(30) := 'CG_AUDIT_POLICY';
  -- Actions missing from the RDS default policies. Kept as one CREATE so the
  -- policy is defined atomically; each name is a documented auditable action.
  c_actions   CONSTANT VARCHAR2(200) :=
    'REVOKE, CHANGE PASSWORD, LOGOFF, CREATE SPFILE';
BEGIN
  -- 1) Create the policy if it does not already exist.
  BEGIN
    SELECT COUNT(DISTINCT POLICY_NAME) INTO v_pol_cnt
      FROM AUDIT_UNIFIED_POLICIES
     WHERE POLICY_NAME = c_policy;
    IF v_pol_cnt = 0 THEN
      EXECUTE IMMEDIATE 'CREATE AUDIT POLICY '||c_policy||' ACTIONS '||c_actions;
      DBMS_OUTPUT.PUT_LINE('created unified audit policy: '||c_policy);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already exists: '||c_policy);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    v_failures := v_failures + 1;
    DBMS_OUTPUT.PUT_LINE('ERROR create '||c_policy||': '||SQLERRM);
  END;

  -- 2) Enable the policy for ALL USERS (audits both success and failure) if it is
  --    not already enabled. Guard counts DISTINCT names so a policy enabled more
  --    than one way is not miscounted.
  BEGIN
    SELECT COUNT(DISTINCT POLICY_NAME) INTO v_en_cnt
      FROM AUDIT_UNIFIED_ENABLED_POLICIES
     WHERE POLICY_NAME = c_policy;
    IF v_en_cnt = 0 THEN
      EXECUTE IMMEDIATE 'AUDIT POLICY '||c_policy;
      DBMS_OUTPUT.PUT_LINE('enabled unified audit policy: '||c_policy);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already enabled: '||c_policy);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    v_failures := v_failures + 1;
    DBMS_OUTPUT.PUT_LINE('ERROR enable '||c_policy||': '||SQLERRM);
  END;

  DBMS_OUTPUT.PUT_LINE('30_audit_policies: failures='||v_failures);
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20030, '30_audit_policies: '||v_failures||' audit-policy operation(s) failed');
  END IF;
END;
/

PROMPT 30_audit_policies: CG_AUDIT_POLICY created and enabled (idempotent).
