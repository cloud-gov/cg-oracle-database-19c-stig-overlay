-- 40_public_grants_assess.sql — ASSESSMENT ONLY (detect-first, never revokes).
-- Excessive privileges granted to PUBLIC are a classic STIG finding, but revoking
-- them can break applications/vendor packages. This script REPORTS them so an
-- operator can build an explicit allowlist before any revoke (see rollback/ and
-- the README's detect-first principle). It performs NO changes.
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

PROMPT === EXECUTE privileges granted to PUBLIC on powerful packages (review) ===
SELECT TABLE_NAME AS object_name, PRIVILEGE
FROM   DBA_TAB_PRIVS
WHERE  GRANTEE = 'PUBLIC'
AND    PRIVILEGE = 'EXECUTE'
AND    TABLE_NAME IN ('UTL_FILE','UTL_TCP','UTL_HTTP','UTL_SMTP','UTL_INADDR',
                      'DBMS_LOB','DBMS_SQL','DBMS_JAVA','DBMS_SCHEDULER')
ORDER  BY TABLE_NAME;

PROMPT === count of ALL privileges granted to PUBLIC (situational awareness) ===
SELECT PRIVILEGE, COUNT(*) AS grant_count
FROM   DBA_TAB_PRIVS
WHERE  GRANTEE = 'PUBLIC'
GROUP  BY PRIVILEGE
ORDER  BY grant_count DESC;

PROMPT NOTE: this script does not revoke anything. Build an allowlist first.
