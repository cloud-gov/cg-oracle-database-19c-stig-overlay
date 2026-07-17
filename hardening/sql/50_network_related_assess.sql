-- 50_network_related_assess.sql — ASSESSMENT ONLY. Reports network/encryption
-- settings visible from SQL. On RDS many network controls (listener config, native
-- network encryption, TLS termination) are AWS-inherited/managed and configured via
-- option groups or the platform, NOT via SQL — those are validated as inherited by
-- the InSpec profile (control-layers.yml), not remediated here.
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

PROMPT === parameters relevant to network security (read-only view) ===
SELECT NAME, VALUE
FROM   V$PARAMETER
WHERE  NAME IN ('sec_case_sensitive_logon','remote_login_passwordfile',
                'sec_protocol_error_further_action','sec_max_failed_login_attempts')
ORDER  BY NAME;

PROMPT NOTE: sqlnet.ora settings (e.g. sqlnet.allowed_logon_version_server), the
PROMPT       listener, TDE, and native network encryption are NOT in V$PARAMETER
PROMPT       and are platform/option-group managed on RDS — validated as
PROMPT       AWS-inherited (control-layers.yml), not SQL-checkable here.
