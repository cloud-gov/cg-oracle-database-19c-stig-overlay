-- rollback/20_users_rollback.sql — partial reversal of 20_users_roles_privileges.
--
-- IMPORTANT: PASSWORD EXPIRE is NOT cleanly reversible — Oracle has no
-- "un-expire" that restores the prior password; the account owner must set a new
-- password. This script only UNLOCKS the sample accounts it may have locked; it
-- CANNOT restore an expired password. Use in local/dev only. On a real system,
-- unlocking Oracle sample schemas is itself usually undesirable (they should stay
-- locked), so this exists for completeness/testing, not as a recommended action.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

DECLARE
  TYPE name_list IS TABLE OF VARCHAR2(30);
  samples name_list := name_list('HR','OE','PM','IX','SH','BI','SCOTT');
  v_status DBA_USERS.ACCOUNT_STATUS%TYPE;
BEGIN
  FOR i IN 1 .. samples.COUNT LOOP
    BEGIN
      SELECT ACCOUNT_STATUS INTO v_status FROM DBA_USERS WHERE USERNAME = samples(i);
      IF v_status LIKE '%LOCKED%' THEN
        EXECUTE IMMEDIATE 'ALTER USER "'||samples(i)||'" ACCOUNT UNLOCK';
        DBMS_OUTPUT.PUT_LINE('unlocked sample account: '||samples(i)||
          ' (NOTE: password remains expired; owner must reset it)');
      END IF;
    EXCEPTION
      WHEN NO_DATA_FOUND THEN NULL;
      WHEN OTHERS THEN DBMS_OUTPUT.PUT_LINE('skip '||samples(i)||': '||SQLERRM);
    END;
  END LOOP;
END;
/
