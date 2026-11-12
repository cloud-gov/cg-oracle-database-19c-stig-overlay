-- 16_profile_completion.sql -- complete the known customer profile limits after
-- scripts 15 and 60. Run only with the same reviewed session-cap decision as 15.
-- Live RDS validation (2026-11-12) permits these ORA_STIG_PROFILE changes; do not
-- confuse it with the AWS-managed RDSADMIN profile. Unknown profiles stay findings.
-- The 55-day lifetime preserves ORA_STIG_PROFILE's observed five-day grace.
SET DEFINE OFF
SET SERVEROUTPUT ON
SET FEEDBACK OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE

DECLARE
  v_sessions VARCHAR2(128);
  v_grace    VARCHAR2(128);
BEGIN
  SELECT limit INTO v_sessions FROM dba_profiles
    WHERE profile = 'DEFAULT' AND resource_name = 'SESSIONS_PER_USER';
  IF v_sessions IS NULL OR NOT REGEXP_LIKE(v_sessions, '^[1-9][0-9]*$') THEN
    RAISE_APPLICATION_ERROR(-20017, 'Run 15_concurrent_sessions.sql with reviewed headroom first');
  END IF;
  SELECT limit INTO v_grace FROM dba_profiles
    WHERE profile = 'ORA_STIG_PROFILE' AND resource_name = 'PASSWORD_GRACE_TIME';
  IF v_grace IS NULL OR v_grace <> '5' THEN
    RAISE_APPLICATION_ERROR(-20018, 'Unexpected ORA_STIG_PROFILE grace; review lifetime before changing it');
  END IF;
  EXECUTE IMMEDIATE 'ALTER PROFILE ORA_STIG_PROFILE LIMIT SESSIONS_PER_USER ' ||
    v_sessions || ' PASSWORD_LIFE_TIME 55';
  EXECUTE IMMEDIATE 'ALTER PROFILE TEMPORARY_USERS LIMIT SESSIONS_PER_USER ' || v_sessions;
  DBMS_OUTPUT.PUT_LINE('16_profile_completion: explicit customer session caps applied; ORA_STIG_PROFILE lifetime 55+5=60');
END;
/
