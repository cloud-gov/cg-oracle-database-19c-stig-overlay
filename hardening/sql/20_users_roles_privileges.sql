-- 20_users_roles_privileges.sql — hardening (idempotent, detect-first).
-- Locks/expires well-known Oracle SAMPLE/demo accounts if present and open. Does
-- NOT drop users or revoke PUBLIC grants (that is detect-first, see 40_*).
--
-- SCOPE: this script touches ONLY Oracle-provided *sample/demo* schemas (the
-- HR/OE/... example schemas). It deliberately does NOT touch option-managed or
-- security schemas (e.g. DVSYS/Database Vault, LBACSYS/OLS, AUDSYS): locking those
-- can break a live RDS option and RDS may reject it. Reversal caveat: PASSWORD
-- EXPIRE is NOT cleanly reversible (see rollback/20_users_rollback.sql).
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- Lock a curated set of Oracle SAMPLE/demo accounts when they exist and are OPEN.
-- Idempotent: an already-locked (non-OPEN) account is skipped. A failure counter
-- is tracked so the run does not silently report success on total failure.
DECLARE
  TYPE name_list IS TABLE OF VARCHAR2(30);
  -- Oracle-provided EXAMPLE schemas only. NOT security/option schemas.
  samples name_list := name_list(
    'HR','OE','PM','IX','SH','BI','SCOTT'
  );
  v_status  DBA_USERS.ACCOUNT_STATUS%TYPE;
  v_failures PLS_INTEGER := 0;
  v_acted    PLS_INTEGER := 0;
BEGIN
  FOR i IN 1 .. samples.COUNT LOOP
    BEGIN
      SELECT ACCOUNT_STATUS INTO v_status FROM DBA_USERS WHERE USERNAME = samples(i);
      -- Act only on accounts that are currently usable (OPEN or EXPIRED-but-unlocked).
      IF v_status = 'OPEN' OR v_status LIKE 'EXPIRED%' AND v_status NOT LIKE '%LOCKED%' THEN
        EXECUTE IMMEDIATE 'ALTER USER "'||samples(i)||'" ACCOUNT LOCK PASSWORD EXPIRE';
        v_acted := v_acted + 1;
        DBMS_OUTPUT.PUT_LINE('locked+expired sample account: '||samples(i));
      ELSE
        DBMS_OUTPUT.PUT_LINE('skip '||samples(i)||' (status '||v_status||')');
      END IF;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN NULL; -- account not present: nothing to do
      WHEN OTHERS THEN
        v_failures := v_failures + 1;
        DBMS_OUTPUT.PUT_LINE('ERROR '||samples(i)||': '||SQLERRM);
    END;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('20_users_roles_privileges: acted='||v_acted||' failures='||v_failures);
  -- Fail loudly if any lock attempt errored, so an automated run cannot record a
  -- false PASS (the run exits non-zero via the WHENEVER below).
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20020, '20_users_roles_privileges: '||v_failures||' account operation(s) failed');
  END IF;
END;
/

PROMPT 20_users_roles_privileges: default accounts locked/expired where present.
