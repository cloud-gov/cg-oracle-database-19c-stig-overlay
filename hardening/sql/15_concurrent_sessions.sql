-- 15_concurrent_sessions.sql — hardening (idempotent) for SV-270495
-- (O19C-00-000100 / SRG-APP-000001-DB-000031 / CCI-000054 / AC-10):
-- "Oracle Database must limit the number of concurrent sessions for each system
-- account to an organization-defined number of sessions."
--
-- STIG fix:  ALTER PROFILE <profile_name> LIMIT SESSIONS_PER_USER <integer>;
--
-- APPROACH (mirrors cloud-gov/cg-mysql-8-stig-overlay SV-235096, which derives the
-- per-user cap from the server ceiling minus a headroom): here the server ceiling
-- is the instance SESSIONS parameter (analogous to MySQL max_connections), read
-- live from V$PARAMETER, and the per-user limit is set to SESSIONS - headroom.
-- Leaving headroom below the ceiling ensures a single account cannot exhaust the
-- instance's session pool (DoS protection, the intent of AC-10) while keeping the
-- limit bounded (non-UNLIMITED/DEFAULT), which is what SV-270495 checks.
--
-- CUSTOMER RESPONSIBILITY (see docs/RESPONSIBILITY.md): the exact number is
-- ORGANIZATION-DEFINED. This SESSIONS-minus-headroom value is a conservative,
-- SAFE-FOR-ALL upper bound sample, NOT a Cloud.gov recommendation. A tenant whose
-- workload wants a *tighter* per-user cap (e.g. 2 for interactive users) or a
-- looser one for a connection-pool account MUST review and adjust before treating
-- this as compliant. Uses ALTER PROFILE (permitted for the RDS master user; non-SYS).
--
-- Override the headroom at run time:  DEFINE session_headroom=<n>
-- (this file is run through sqlplus/sqlcl, which honor substitution variables and
-- bind variables — see runner/README.md; db-query.sh/oraquery does NOT interpret
-- them, so run this with sqlplus/sqlcl).
SET DEFINE ON
SET SERVEROUTPUT ON
SET FEEDBACK OFF
SET VERIFY OFF
WHENEVER SQLERROR CONTINUE

-- Connections held back from the instance SESSIONS ceiling so no single account
-- can consume the entire pool — leaving free sessions for an operator to log in
-- and remediate. Org-defined; 64 is a conservative default (e.g. on an se2.medium
-- with SESSIONS=614 this caps a user at 550).
DEFINE session_headroom = 64

DECLARE
  v_headroom  PLS_INTEGER := &&session_headroom;
  v_sessions  PLS_INTEGER;
  v_limit     PLS_INTEGER;
BEGIN
  -- Read the instance session ceiling. On RDS this is set by the parameter group
  -- but remains SQL-readable (set_by <> verified_by; see control-layers.yml).
  BEGIN
    SELECT TO_NUMBER(value) INTO v_sessions
      FROM V$PARAMETER WHERE name = 'sessions';
  EXCEPTION WHEN OTHERS THEN
    -- Fail loud rather than silently guessing a limit (no false PASS).
    RAISE_APPLICATION_ERROR(-20015,
      '15_concurrent_sessions: cannot read V$PARAMETER sessions ('||SQLERRM||
      '); set SESSIONS_PER_USER manually per SV-270495');
  END;

  v_limit := v_sessions - v_headroom;

  -- Guard against a misconfigured/tiny ceiling producing a non-positive limit.
  IF v_limit < 1 THEN
    RAISE_APPLICATION_ERROR(-20016,
      '15_concurrent_sessions: SESSIONS ('||v_sessions||') - headroom ('||
      v_headroom||') = '||v_limit||' is not a usable per-user limit; lower the headroom');
  END IF;

  -- ALTER PROFILE is idempotent: re-running with the same limit is a no-op. Setting
  -- an explicit integer clears the non-compliant 'UNLIMITED'/'DEFAULT' state that
  -- SV-270495 flags. STIG: SRG-APP-000001-DB-000031 (AC-10).
  EXECUTE IMMEDIATE 'ALTER PROFILE DEFAULT LIMIT SESSIONS_PER_USER '||v_limit;

  DBMS_OUTPUT.PUT_LINE('15_concurrent_sessions: DEFAULT SESSIONS_PER_USER = '||
    v_limit||' (SESSIONS '||v_sessions||' - headroom '||v_headroom||') [SV-270495]');
END;
/

PROMPT 15_concurrent_sessions: DEFAULT profile SESSIONS_PER_USER set to SESSIONS - headroom (SV-270495).
PROMPT   NOTE: an org-defined SAFE upper bound (not a recommendation). Review per docs/RESPONSIBILITY.md.
