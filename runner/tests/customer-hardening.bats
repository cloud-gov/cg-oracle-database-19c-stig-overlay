#!/usr/bin/env bats
# Static regression contracts for SQL that needs a live Oracle interpreter. These
# assertions protect the reviewed predicates and guard ordering without pretending
# to replace a live Oracle/Cloud Foundry run.

setup() {
  repo_root="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
}

@test "profile assignment preserves TEMPORARY_USERS lifecycle accounts" {
  grep -Fqx "       AND du.PROFILE <> 'TEMPORARY_USERS'" \
    "$repo_root/hardening/sql/11_ora_stig_profile.sql"
  grep -Fqx "               WHERE profile = 'TEMPORARY_USERS'" \
    "$repo_root/hardening/sql/60_temporary_users.sql"
}

@test "session headroom rejects invalid reserves before altering DEFAULT" {
  script="$repo_root/hardening/sql/15_concurrent_sessions.sql"
  grep -Fq "REGEXP_LIKE(TRIM(v_headroom_text), '^[0-9]+$')" "$script"
  grep -Fq 'IF v_headroom < 1 OR v_headroom >= v_sessions THEN' "$script"
  guard_line="$(grep -n 'IF v_headroom < 1 OR v_headroom >= v_sessions THEN' "$script" | cut -d: -f1)"
  alter_line="$(grep -n "EXECUTE IMMEDIATE 'ALTER PROFILE DEFAULT LIMIT SESSIONS_PER_USER" "$script" | cut -d: -f1)"
  [ "$guard_line" -lt "$alter_line" ]
}

@test "customer hardening driver forwards every reviewed input" {
  driver="$repo_root/hardening/sql/customer-hardening.sql"
  grep -Fqx '@@11_ora_stig_profile.sql &&assign_users' "$driver"
  grep -Fqx '@@12_password_verify_function.sql &&verify_function' "$driver"
  grep -Fqx '@@15_concurrent_sessions.sql &&session_headroom' "$driver"
  completion_line="$(grep -n '^@@70_profile_completion.sql$' "$driver" | cut -d: -f1)"
  temporary_line="$(grep -n '^@@60_temporary_users.sql$' "$driver" | cut -d: -f1)"
  [ "$completion_line" -gt "$temporary_line" ]
}

@test "profile completion validates cap and grace before any DDL" {
  script="$repo_root/hardening/sql/70_profile_completion.sql"
  grep -Fq "IF v_sessions IS NULL OR NOT REGEXP_LIKE(v_sessions, '^[1-9][0-9]*$') THEN" "$script"
  grep -Fq "IF v_grace IS NULL OR v_grace <> '5' THEN" "$script"
  guard_line="$(grep -n 'RAISE_APPLICATION_ERROR(-20018' "$script" | cut -d: -f1)"
  alter_line="$(grep -n "EXECUTE IMMEDIATE 'ALTER PROFILE ORA_STIG_PROFILE" "$script" | cut -d: -f1)"
  [ "$guard_line" -lt "$alter_line" ]
}
