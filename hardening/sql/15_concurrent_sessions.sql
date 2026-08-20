-- 15_concurrent_sessions.sql — hardening (idempotent) for SV-270495
-- (O19C-00-000100 / SRG-APP-000001-DB-000031 / CCI-000054 / AC-10):
-- "Oracle Database must limit the number of concurrent sessions for each system
-- account to an organization-defined number of sessions."
--
-- STIG fix:  ALTER PROFILE <profile_name> LIMIT SESSIONS_PER_USER <integer>;
--
-- WORKLOAD CONTEXT (why headroom, not a tiny cap): these are single-tenant
-- backend databases for one web application. The "user" is effectively the single
-- account behind the binding credential (a connection pool), not a room full of
-- interactive analysts. That account legitimately needs the bulk of the instance's
-- sessions. So the sample sets a HIGH per-user cap: the instance SESSIONS ceiling
-- minus a headroom, leaving enough free sessions for an RDS/operator account to log
-- in and diagnose if the app account ever pins its cap. This mirrors
-- cloud-gov/cg-mysql-8-stig-overlay SV-235096 (max_connections − headroom); the
-- Oracle instance-wide ceiling here is the SESSIONS parameter, read from
-- V$PARAMETER (SQL-readable on RDS even though it is set by the parameter group).
--
-- CUSTOMER RESPONSIBILITY (see docs/RESPONSIBILITY.md): the exact number is
-- ORGANIZATION-DEFINED. SESSIONS − headroom is a conservative sample sized for the
-- one-app-user case, NOT a Cloud.gov recommendation. A tenant that runs multiple
-- application accounts, or wants a tight interactive-user cap, MUST review and
-- adjust before treating this as compliant. Uses ALTER PROFILE (permitted for the
-- RDS master user; non-SYS).
--
-- CAVEAT — DEFAULT profile also governs the RDS master. This sets the limit on the
-- DEFAULT profile, which on RDS is shared by the app account AND the master/backup
-- account. The headroom is therefore only a *reservation by convention*: it holds
-- as long as no OTHER DEFAULT-profile account also climbs to the high cap. It is
-- not an enforced guarantee. Do NOT lower the headroom to a tiny value, or the
-- operator account inherits the same tight cap and loses its diagnostic reserve.
-- A tenant wanting a hard guarantee should put the app account on its own profile
-- (high cap) and keep DEFAULT — hence the master — on a smaller reserved cap.
--
-- Override the headroom at run time:  DEFINE session_headroom=<n>
-- (this file is run through sqlplus/sqlcl, which honor substitution variables and
-- PL/SQL — see runner/README.md; db-query.sh/oraquery does NOT interpret them, so
-- run this with sqlplus/sqlcl).
SET DEFINE ON
SET SERVEROUTPUT ON
SET FEEDBACK OFF
SET VERIFY OFF
WHENEVER SQLERROR EXIT FAILURE

-- Sessions held back from the instance SESSIONS ceiling so the app account cannot
-- consume the entire pool — leaving free sessions for an RDS/operator account to
-- log in and remediate. Org-defined; 64 is a conservative default (e.g. on an
-- se2.medium with SESSIONS=614 this caps a user at 550, ~90% of the pool).
DEFINE session_headroom = 64

DECLARE
  v_headroom  PLS_INTEGER := &&session_headroom;
  v_sessions  PLS_INTEGER;
  v_limit     PLS_INTEGER;
BEGIN
  -- Read the instance session ceiling. On RDS this is set by the parameter group
  -- but remains SQL-readable (set_by <> verified_by; see control-layers.yml).
  -- No inner handler: any failure here propagates and, with WHENEVER SQLERROR EXIT
  -- FAILURE above, aborts the script (fail loud — never a false PASS).
  SELECT TO_NUMBER(value) INTO v_sessions
    FROM V$PARAMETER WHERE name = 'sessions';

  v_limit := v_sessions - v_headroom;

  -- Guard against a misconfigured/tiny ceiling producing a non-positive limit.
  IF v_limit < 1 THEN
    RAISE_APPLICATION_ERROR(-20016,
      '15_concurrent_sessions: SESSIONS ('||v_sessions||') - headroom ('||
      v_headroom||') = '||v_limit||' is not a usable per-user limit; lower the headroom');
  END IF;

  -- ALTER PROFILE is idempotent: re-running with the same limit is a no-op. Setting
  -- an explicit integer clears the non-compliant 'UNLIMITED'/'DEFAULT' state that
  -- SV-270495 flags. STIG: SRG-APP-000001-DB-000031 (AC-10). On failure, WHENEVER
  -- SQLERROR EXIT FAILURE aborts — the operator does not see a success message.
  EXECUTE IMMEDIATE 'ALTER PROFILE DEFAULT LIMIT SESSIONS_PER_USER '||v_limit;

  -- Only reached on success (a raised error above exits before this line).
  DBMS_OUTPUT.PUT_LINE('15_concurrent_sessions: DEFAULT SESSIONS_PER_USER = '||
    v_limit||' (SESSIONS '||v_sessions||' - headroom '||v_headroom||') [SV-270495]'||
    ' — SAMPLE org-defined value; review per docs/RESPONSIBILITY.md');
END;
/
