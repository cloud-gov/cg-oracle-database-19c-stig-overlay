-- 60_temporary_users.sql — hardening (idempotent) SAMPLE for SV-270547
-- (O19C-00-012100 / SRG-APP-000516-DB-000363 / CCI-000366 / CM-6 b):
-- "Oracle Database must provide a mechanism to automatically remove or disable
-- temporary user accounts after 72 hours."
--
-- STIG fix:  use a distinctively named profile (e.g. TEMPORARY_USERS) so temporary
-- accounts are easily identified, assign temporary accounts to it, and create a
-- job to LOCK accounts under that profile that are more than 72 hours old.
--
-- CUSTOMER RESPONSIBILITY (see docs/RESPONSIBILITY.md): this is the companion to
-- SV-270546 (identify temporary accounts via a distinctive profile). The STIG
-- check is Not a Finding if the organization has a consistently enforced policy
-- forbidding temporary/emergency accounts, or if all accounts authenticate via the
-- OS / an enterprise mechanism rather than Oracle. Cloud.gov satisfies the baseline
-- at provisioning (the broker issues a single, non-temporary customer account); if
-- the customer chooses to create Oracle-managed temporary accounts, managing their
-- 72-hour lifecycle per the STIG is the customer's responsibility. This script is a
-- SAMPLE of the DATABASE mechanism, NOT a Cloud.gov recommendation — review before
-- use.
--
-- SCOPE / SAFETY:
--   * detect-first, additive: creates the profile and the lock job only; it does
--     NOT create, move, or lock any real account on its own beyond the scheduled
--     job's own action against accounts already assigned to TEMPORARY_USERS.
--   * The job locks (does not drop) accounts on TEMPORARY_USERS whose CREATED
--     timestamp is older than 72 hours — reversible by an administrator.
--   * Uses ALTER SYSTEM SET RESOURCE_LIMIT and CREATE PROFILE / DBMS_SCHEDULER,
--     which the RDS master user pattern is permitted to run (non-SYS).
--   * Assigning a temporary account to the profile is a per-account customer step
--     (CREATE USER ... PROFILE TEMPORARY_USERS) and is intentionally NOT automated
--     here.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- Profiles only limit resources when RESOURCE_LIMIT is enabled. Idempotent.
ALTER SYSTEM SET RESOURCE_LIMIT = TRUE;

DECLARE
  v_failures  PLS_INTEGER := 0;
  v_prof_cnt  PLS_INTEGER;
  v_job_cnt   PLS_INTEGER;
  c_profile   CONSTANT VARCHAR2(30) := 'TEMPORARY_USERS';
  c_job       CONSTANT VARCHAR2(30) := 'CG_LOCK_TEMP_USERS_72H';
BEGIN
  -- 1) Create the distinctively named temporary-users profile if absent. Values
  --    here are SAMPLE limits aligned with the STIG example + this overlay's
  --    lockout inputs (FAILED_LOGIN_ATTEMPTS 3, PASSWORD_LOCK_TIME UNLIMITED);
  --    the org MUST review resource limits for its situation.
  BEGIN
    SELECT COUNT(*) INTO v_prof_cnt
      FROM DBA_PROFILES WHERE PROFILE = c_profile AND ROWNUM = 1;
    IF v_prof_cnt = 0 THEN
      EXECUTE IMMEDIATE
        'CREATE PROFILE '||c_profile||' LIMIT '||
        'FAILED_LOGIN_ATTEMPTS 3 '||
        'PASSWORD_LIFE_TIME 7 '||
        'PASSWORD_REUSE_TIME 60 '||
        'PASSWORD_REUSE_MAX 5 '||
        'PASSWORD_LOCK_TIME UNLIMITED '||
        'PASSWORD_GRACE_TIME 3';
      DBMS_OUTPUT.PUT_LINE('created profile: '||c_profile);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already exists: '||c_profile);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    v_failures := v_failures + 1;
    DBMS_OUTPUT.PUT_LINE('ERROR create profile '||c_profile||': '||SQLERRM);
  END;

  -- 2) Create the scheduled lock job if absent. It runs hourly and LOCKs any
  --    account on TEMPORARY_USERS created more than 72 hours ago. Locking (not
  --    dropping) satisfies "remove OR disable" reversibly. Idempotent: an existing
  --    job is left in place.
  BEGIN
    SELECT COUNT(*) INTO v_job_cnt
      FROM USER_SCHEDULER_JOBS WHERE JOB_NAME = c_job;
    IF v_job_cnt = 0 THEN
      DBMS_SCHEDULER.CREATE_JOB(
        job_name        => c_job,
        job_type        => 'PLSQL_BLOCK',
        job_action      => q'[
          BEGIN
            FOR r IN (
              SELECT username FROM dba_users
               WHERE profile = 'TEMPORARY_USERS'
                 AND account_status NOT LIKE '%LOCKED%'
                 AND created < SYSTIMESTAMP - INTERVAL '72' HOUR
            ) LOOP
              EXECUTE IMMEDIATE 'ALTER USER "'||r.username||'" ACCOUNT LOCK';
            END LOOP;
          END;
        ]',
        start_date      => SYSTIMESTAMP,
        repeat_interval => 'FREQ=HOURLY;INTERVAL=1',
        enabled         => TRUE,
        comments        => 'SV-270547: lock TEMPORARY_USERS accounts older than 72h');
      DBMS_OUTPUT.PUT_LINE('created job: '||c_job);
    ELSE
      DBMS_OUTPUT.PUT_LINE('already exists: '||c_job);
    END IF;
  EXCEPTION WHEN OTHERS THEN
    v_failures := v_failures + 1;
    DBMS_OUTPUT.PUT_LINE('ERROR create job '||c_job||': '||SQLERRM);
  END;

  DBMS_OUTPUT.PUT_LINE('60_temporary_users: failures='||v_failures);
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20060, '60_temporary_users: '||v_failures||' operation(s) failed');
  END IF;
END;
/

PROMPT 60_temporary_users: TEMPORARY_USERS profile + 72h lock job created (idempotent).
PROMPT 60_temporary_users: assign temp accounts with CREATE USER ... PROFILE TEMPORARY_USERS (customer step).
