-- rollback/12_password_verify_function_rollback.sql — reverses
-- 12_password_verify_function.sql.
--
-- 12_ binds PASSWORD_VERIFY_FUNCTION on the DEFAULT profile to the Oracle-supplied
-- ORA12C_STIG_VERIFY_FUNCTION. This rollback sets the DEFAULT profile's
-- PASSWORD_VERIFY_FUNCTION back to NULL (the Oracle out-of-the-box value), which
-- re-opens the SV-270561 finding for accounts on the DEFAULT profile. It does NOT
-- drop the Oracle-supplied ORA12C_STIG_VERIFY_FUNCTION (its presence is not a
-- finding, and catpvf.sql owns its lifecycle).
--
-- NOTE: this resets to NULL (Oracle default), NOT to the profile's PRE-hardening
-- value — capture that from 01_inventory output first for a true restore. Use only
-- in local/dev or a deliberate operator action.
--
-- NON-SYS / RDS: uses ALTER PROFILE only (permitted for the RDS master user).
SET SERVEROUTPUT ON
SET DEFINE OFF
SET FEEDBACK OFF
WHENEVER SQLERROR CONTINUE

-- ALTER PROFILE is idempotent; setting the function to NULL is a no-op if already
-- NULL. STIG: SRG-APP-000164 (password complexity).
ALTER PROFILE DEFAULT LIMIT PASSWORD_VERIFY_FUNCTION NULL;   -- reverses SV-270561 binding

PROMPT rollback/12_password_verify_function: DEFAULT profile PASSWORD_VERIFY_FUNCTION reset to NULL (reopens SV-270561).
PROMPT (does NOT restore a pre-hardening custom function; use 01_inventory capture for a true restore. Oracle-supplied ORA12C_STIG_VERIFY_FUNCTION left in place.)
