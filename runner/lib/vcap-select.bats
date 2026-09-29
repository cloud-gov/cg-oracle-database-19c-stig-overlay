#!/usr/bin/env bats
# Regression tests for the VCAP_SERVICES binding contract in db-connect.sh
# (issue #21): the runner supports exactly ONE aws-rds binding, and it must be the
# Oracle (ORCL) database. Zero bindings, more than one binding, or a single
# non-ORCL binding each fail closed. More than one is REFUSED rather than guessed
# at — a future multi-binding use case adds selection then.
#
# Unlike db-connect.bats (pure bash+sed, runs in the stock bats image), these
# exercise _dbc_parse_vcap end-to-end, which needs a real interpreter (Ruby or
# jq). The suite SKIPS when neither is present — so it passes in the CINC
# AUDITOR_IMAGE (embedded Ruby) via `make test-vcap` and in any jq-only
# environment, without a hard Ruby/jq host dependency.
#
# Both interpreters implement the SAME contract, so every case here asserts the
# behavior of _dbc_parse_vcap (the shared decision point) rather than either
# parser directly — proving the two paths cannot drift on policy.

setup() {
  bats_require_minimum_version 1.5.0  # `run --separate-stderr` needs 1.5.0+
  # shellcheck disable=SC1091
  source "${BATS_TEST_DIRNAME}/db-connect.sh"
  if [ -z "$(_dbc_ruby_bin 2>/dev/null)" ] && ! command -v jq >/dev/null 2>&1; then
    skip "no Ruby or jq interpreter available to parse VCAP_SERVICES"
  fi
}

# Fixture builder: one binding object per "instance:dbname" pair. dbname defaults
# to ORCL. instance_name is the top-level CF service-instance field.
_binding() {
  local instance="$1" dbname="${2:-ORCL}"
  printf '{"instance_name":"%s","credentials":{"username":"u_%s","password":"p_%s","host":"h_%s.example.com","db_name":"%s","port":2484}}' \
    "$instance" "$instance" "$instance" "$instance" "$dbname"
}

# Assemble a VCAP_SERVICES doc with an aws-rds array from the given binding JSONs.
_vcap() {
  local joined="" b
  for b in "$@"; do
    joined="${joined:+$joined,}$b"
  done
  printf '{"aws-rds":[%s]}' "$joined"
}

# --- exactly one ORCL binding (the supported case) --------------------------

@test "vcap: a single ORCL binding fills DB_*" {
  VCAP_SERVICES="$(_vcap "$(_binding only-orcl)")"
  export VCAP_SERVICES
  # --separate-stderr keeps the resolver's _dbc_log lines (stderr) out of $output
  # so we assert only the coordinate row the inner shell prints on stdout.
  run --separate-stderr bash -c '
    source "'"${BATS_TEST_DIRNAME}"'/db-connect.sh"
    _dbc_parse_vcap || exit $?
    printf "%s|%s|%s|%s\n" "$DB_USER" "$DB_HOST" "$DB_SERVICE" "$DB_INSTANCE_NAME"
  '
  [ "$status" -eq 0 ]
  [ "$output" = "u_only-orcl|h_only-orcl.example.com|ORCL|only-orcl" ]
}

# --- zero bindings (fail closed) --------------------------------------------

@test "vcap: a single non-Oracle binding fails closed" {
  VCAP_SERVICES="$(_vcap "$(_binding only-pg pg)")"
  export VCAP_SERVICES
  run _dbc_parse_vcap
  [ "$status" -ne 0 ]
  [[ "$output" == *'no single aws-rds binding with db_name "ORCL"'* ]]
}

@test "vcap: an absent aws-rds key fails closed (no stack trace)" {
  VCAP_SERVICES='{"other-svc":[]}'
  export VCAP_SERVICES
  run _dbc_parse_vcap
  [ "$status" -ne 0 ]
  [[ "$output" == *'no single aws-rds binding with db_name "ORCL"'* ]]
}

@test "vcap: an empty aws-rds array fails closed" {
  VCAP_SERVICES='{"aws-rds":[]}'
  export VCAP_SERVICES
  run _dbc_parse_vcap
  [ "$status" -ne 0 ]
  [[ "$output" == *'no single aws-rds binding with db_name "ORCL"'* ]]
}

# --- more than one binding (issue #21 core: refuse to guess) ----------------

@test "vcap: two aws-rds bindings fail closed, whatever their db_name" {
  VCAP_SERVICES="$(_vcap "$(_binding orcl-one)" "$(_binding orcl-two)")"
  export VCAP_SERVICES
  run _dbc_parse_vcap
  [ "$status" -ne 0 ]
  [[ "$output" == *'more than one aws-rds binding'* ]]
  [[ "$output" == *'refusing to guess'* ]]
}

@test "vcap: one ORCL + one non-Oracle binding still fails (count is over ALL)" {
  VCAP_SERVICES="$(_vcap "$(_binding the-orcl ORCL)" "$(_binding a-postgres pg)")"
  export VCAP_SERVICES
  run _dbc_parse_vcap
  [ "$status" -ne 0 ]
  [[ "$output" == *'more than one aws-rds binding'* ]]
}
