#!/usr/bin/env bats
# Static regression contracts for SQL that needs a live Oracle interpreter. These
# assertions protect the reviewed predicates and guard ordering without pretending
# to replace a live Oracle/Cloud Foundry run.

@test "overlay responsibility tags use explicit string keys" {
  overlay="${BATS_TEST_DIRNAME}/../../controls/overlay.rb"
  ! grep -Eq '^[[:space:]]+tag responsibility:' "$overlay"
  [ "$(grep -Ec "^[[:space:]]+tag 'responsibility' => '(platform|customer)'" "$overlay")" -ge 57 ]
}

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
}
