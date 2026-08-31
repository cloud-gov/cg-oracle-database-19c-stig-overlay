-- rollback/60_temporary_users_rollback.sql — reverses 60_temporary_users.sql by
-- dropping the scheduled lock job and the TEMPORARY_USERS profile it creates. Use
-- in local/dev only; removing this mechanism on a real system REDUCES the STIG
-- posture (SV-270547: no longer auto-locks temporary accounts after 72h) and
-- should be a deliberate, reviewed action.
--
-- Does NOT unlock or drop any account. Dropping the profile fails if accounts are
-- still assigned to it; reassign those accounts (e.g. to DEFAULT) first. This is
-- intentional — the rollback must not silently move real accounts.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

DECLARE
  v_job_cnt   PLS_INTEGER;
  v_prof_cnt  PLS_INTEGER;
  c_profile   CONSTANT VARCHAR2(30) := 'TEMPORARY_USERS';
  c_job       CONSTANT VARCHAR2(30) := 'CG_LOCK_TEMP_USERS_72H';
BEGIN
  -- 1) Drop the scheduled lock job if present.
  BEGIN
    SELECT COUNT(*) INTO v_job_cnt
      FROM USER_SCHEDULER_JOBS WHERE JOB_NAME = c_job;
    IF v_job_cnt > 0 THEN
      DBMS_SCHEDULER.DROP_JOB(job_name => c_job, force => TRUE);
      DBMS_OUTPUT.PUT_LINE('dropped job: '||c_job);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already absent: '||c_job);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('skip drop job '||c_job||': '||SQLERRM);
  END;

  -- 2) Drop the profile if it exists AND no account is assigned to it. Do NOT
  --    CASCADE (that would silently move accounts to DEFAULT).
  BEGIN
    SELECT COUNT(DISTINCT PROFILE) INTO v_prof_cnt
      FROM DBA_PROFILES WHERE PROFILE = c_profile;
    IF v_prof_cnt > 0 THEN
      EXECUTE IMMEDIATE 'DROP PROFILE '||c_profile;
      DBMS_OUTPUT.PUT_LINE('dropped profile: '||c_profile);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already absent: '||c_profile);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    -- ORA-02382: profile still has assigned users. Report; do not force.
    DBMS_OUTPUT.PUT_LINE('skip drop profile '||c_profile||' (reassign its users first): '||SQLERRM);
  END;
END;
/
