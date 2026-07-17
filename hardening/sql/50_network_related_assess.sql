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
                'sec_protocol_error_further_action','sec_max_failed_login_attempts',
                'sqlnet.allowed_logon_version_server')
ORDER  BY NAME;

PROMPT NOTE: listener/TDE/native-network-encryption on RDS are platform/option-group
PROMPT       managed and validated as AWS-inherited, not set by SQL here.
