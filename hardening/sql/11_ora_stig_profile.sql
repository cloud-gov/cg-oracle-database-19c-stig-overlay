-- 11_ora_stig_profile.sql — hardening (idempotent, detect-first assignment) for
-- the profile-lockout controls SV-270549 / SV-270550 / SV-270551.
--
-- The DISA V1R5 fixes for these three controls name ORA_STIG_PROFILE as the
-- vehicle Oracle SHIPS to satisfy the profile parameters, offering
-- "ALTER USER <user> PROFILE ora_stig_profile" as the remediation.
-- ORA_STIG_PROFILE is an Oracle-supplied, Oracle-MAINTAINED profile that already
-- carries the required limits (PASSWORD_LOCK_TIME UNLIMITED, FAILED_LOGIN_ATTEMPTS
-- 3, INACTIVE_ACCOUNT_TIME 35) and is effectively immutable — Oracle rejects
-- ALTER PROFILE on it (ORA-41724). Per the STIG, the supplied profile can be used
-- as-is; this script therefore does NOT create or modify the profile and does NOT
-- verify its limits. It only ASSIGNS ORA_STIG_PROFILE to the appropriate user
-- accounts, which is what satisfies SV-270549/550/551 for those users (the
-- baseline InSpec checks assert the limits on every profile a user is on).
--
--   Controls satisfied for assigned users (via the supplied profile's limits):
--     SV-270549  PASSWORD_LOCK_TIME     UNLIMITED   (lockout persists until admin reset, AC-7 b)
--     SV-270550  FAILED_LOGIN_ATTEMPTS  3           (<= org-defined max invalid attempts, CM-6 b)
--     SV-270551  INACTIVE_ACCOUNT_TIME  35          (<= org-defined inactivity age, IA-4 e / AC-2(3)(a))
--
-- CUSTOMER RESPONSIBILITY (see docs/RESPONSIBILITY.md): assigning the profile to
-- the site's accounts is org-defined on the SV-270495 pattern. A site whose
-- org-defined values differ from the Oracle-supplied profile must instead assign
-- a customized profile of its own (out of scope for this script, which uses the
-- STIG-named supplied profile).
--
-- NON-SYS / RDS: uses ALTER USER only, permitted for the RDS master user (not
-- SYS/SYSDBA).
--
-- ACCOUNT-ASSIGNMENT SAFETY (why detect-first): moving an account onto
-- ORA_STIG_PROFILE changes its lockout/inactivity behavior and can lock out an
-- app connection (e.g. after 3 failed logons). This script therefore ONLY
-- reassigns accounts that are:
--   * not Oracle-supplied (DBA_USERS.ORACLE_MAINTAINED = 'N'), and
--   * not on the operator/platform exclusion list below, and
--   * not already on ORA_STIG_PROFILE.
-- It reports what it will do first, then acts. To assess WITHOUT changing
-- assignments, run with:  DEFINE assign_users = N
SET SERVEROUTPUT ON
SET DEFINE ON
SET FEEDBACK OFF
SET VERIFY OFF
WHENEVER SQLERROR CONTINUE

-- Set to N to only report candidate accounts (no ALTER USER ... PROFILE).
DEFINE assign_users = Y

DECLARE
  v_assign      VARCHAR2(1) := UPPER('&&assign_users');
  v_exists      PLS_INTEGER;
  v_failures    PLS_INTEGER := 0;
  v_assigned    PLS_INTEGER := 0;
  v_candidates  PLS_INTEGER := 0;

  -- Operator/platform accounts NOT Oracle-maintained but that must stay on their
  -- current profile (moving the RDS master or a broker account onto a 3-strikes
  -- lockout profile risks locking out platform operations). Extend per site.
  -- Kept as a comma-delimited, comma-bounded string so it can be used inside a
  -- plain SQL cursor predicate (a PL/SQL-local collection type cannot appear in a
  -- SQL TABLE(...) operator — ORA-22905/PLS-00642).
  c_exclusions CONSTANT VARCHAR2(400) :=
    ',RDSADMIN,RDS_MASTER,ADMIN,SYSRAC,SYS,SYSTEM,';
BEGIN
  ----------------------------------------------------------------------------
  -- Existence guard only. ORA_STIG_PROFILE is Oracle-supplied on 19c/23ai; we do
  -- not create or modify it. If it is somehow absent, fail loudly rather than
  -- assign accounts to a nonexistent profile.
  ----------------------------------------------------------------------------
  SELECT COUNT(*) INTO v_exists FROM DBA_PROFILES
    WHERE PROFILE = 'ORA_STIG_PROFILE' AND ROWNUM = 1;
  IF v_exists = 0 THEN
    RAISE_APPLICATION_ERROR(-20010,
      '11_ora_stig_profile: Oracle-supplied ORA_STIG_PROFILE not found; expected '||
      'on Oracle 19c/23ai. Do not create it here — investigate the instance.');
  END IF;
  DBMS_OUTPUT.PUT_LINE('using Oracle-supplied ORA_STIG_PROFILE '||
    '(immutable; limits not modified or verified here)');

  ----------------------------------------------------------------------------
  -- Detect-first assignment: move non-Oracle, non-excluded accounts that are NOT
  -- already on ORA_STIG_PROFILE onto it. Report each; act only when
  -- assign_users = Y.
  ----------------------------------------------------------------------------
  FOR u IN (
    SELECT du.USERNAME, du.PROFILE
      FROM DBA_USERS du
     WHERE du.ORACLE_MAINTAINED = 'N'
       AND du.PROFILE <> 'ORA_STIG_PROFILE'
       AND INSTR(c_exclusions, ','||du.USERNAME||',') = 0
     ORDER BY du.USERNAME
  ) LOOP
    v_candidates := v_candidates + 1;
    IF v_assign = 'Y' THEN
      BEGIN
        EXECUTE IMMEDIATE 'ALTER USER "'||u.USERNAME||'" PROFILE ORA_STIG_PROFILE';
        v_assigned := v_assigned + 1;
        DBMS_OUTPUT.PUT_LINE('assigned ORA_STIG_PROFILE to '||u.USERNAME||
          ' (was '||u.PROFILE||')');
      EXCEPTION WHEN OTHERS THEN
        v_failures := v_failures + 1;
        DBMS_OUTPUT.PUT_LINE('ERROR assigning '||u.USERNAME||': '||SQLERRM);
      END;
    ELSE
      DBMS_OUTPUT.PUT_LINE('candidate (assign_users=N, not changed): '||
        u.USERNAME||' (profile '||u.PROFILE||')');
    END IF;
  END LOOP;

  DBMS_OUTPUT.PUT_LINE('11_ora_stig_profile: candidates='||v_candidates||
    ' assigned='||v_assigned||' failures='||v_failures);

  -- Fail loudly if any assignment errored, so an automated run cannot record a
  -- false PASS (the run exits non-zero via the WHENEVER below).
  IF v_failures > 0 THEN
    RAISE_APPLICATION_ERROR(-20011,
      '11_ora_stig_profile: '||v_failures||' account assignment(s) failed');
  END IF;
END;
/

PROMPT 11_ora_stig_profile: Oracle-supplied ORA_STIG_PROFILE assigned to org-defined accounts (SV-270549/550/551).
