-- 11_session_idle.sql — hardening (idempotent). SV-270497 (O19C-00-000300):
-- automatically terminate idle user sessions. Sets the MAX_IDLE_TIME instance
-- parameter (minutes). The value is ORGANIZATION-DEFINED; the STIG says assume
-- 15 minutes when no site value is documented. Customer responsibility: the
-- tenant chooses the value and applies it (Cloud.gov ships this sample only).
--
-- NOTE (RDS): whether max_idle_time is settable via ALTER SYSTEM vs. must be set
-- through the RDS DB parameter group is UNVERIFIED against authoritative AWS docs
-- for the GovCloud oracle-ee-19 family (research failed closed). Confirm with:
--   aws rds describe-engine-default-parameters \
--     --db-parameter-group-family oracle-ee-19 --region us-gov-west-1 \
--     --query "EngineDefaults.Parameters[?ParameterName=='max_idle_time']"
-- If IsModifiable=false, apply the value via the broker parameter group instead
-- of the ALTER SYSTEM below.
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- ALTER SYSTEM is idempotent: setting max_idle_time to its target value is a
-- no-op if already set. Adjust 15 to the organization-defined number of minutes.
-- SID = '*' applies to all RAC instances; SCOPE = BOTH persists across restarts.
ALTER SYSTEM SET max_idle_time = 15
  COMMENT = 'Altered for STIG SV-270497 compliance'
  SID = '*'
  SCOPE = BOTH;

PROMPT 11_session_idle: max_idle_time enforced (idempotent). Confirm RDS modifiability.
