-- 00_connectivity_check.sql — assessment-only (assess).
-- Verifies the connection and reports the effective user + whether we have the
-- expected RDS-master-like privileges (NOT SYS). Never mutates state.
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

PROMPT === connectivity & effective user ===
SELECT USER AS effective_user FROM DUAL;
SELECT SYS_CONTEXT('USERENV','CON_NAME') AS container FROM DUAL;
SELECT BANNER FROM V$VERSION WHERE ROWNUM = 1;

PROMPT === sanity: this must NOT be SYS on RDS ===
SELECT CASE WHEN USER = 'SYS' THEN 'WARNING: connected as SYS (not the RDS model)'
            ELSE 'ok: non-SYS user' END AS sys_check
FROM DUAL;
