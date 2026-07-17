-- 20_users_roles_privileges.sql — hardening (idempotent, detect-first).
-- Locks/expires well-known sample/default accounts if present and open. Does NOT
-- drop users or revoke PUBLIC grants (that is detect-first, see 40_*).
SET SERVEROUTPUT ON
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- Lock a curated set of default/sample accounts when they exist and are OPEN.
-- Idempotent: locking an already-locked account is skipped.
DECLARE
  TYPE name_list IS TABLE OF VARCHAR2(30);
  defaults name_list := name_list(
    'HR','OE','PM','IX','SH','BI','SCOTT','DVSYS','SPATIAL_CSW_ADMIN_USR'
  );
  v_status DBA_USERS.ACCOUNT_STATUS%TYPE;
BEGIN
  FOR i IN 1 .. defaults.COUNT LOOP
    BEGIN
      SELECT ACCOUNT_STATUS INTO v_status FROM DBA_USERS WHERE USERNAME = defaults(i);
      IF v_status = 'OPEN' THEN
        EXECUTE IMMEDIATE 'ALTER USER "'||defaults(i)||'" ACCOUNT LOCK PASSWORD EXPIRE';
        DBMS_OUTPUT.PUT_LINE('locked+expired default account: '||defaults(i));
      END IF;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN NULL; -- account not present: nothing to do
      WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('skip '||defaults(i)||' (reason: '||SQLERRM||')');
    END;
  END LOOP;
END;
/

PROMPT 20_users_roles_privileges: default accounts locked/expired where present.
