#!/usr/bin/env bats
# Regression tests for SQLcl batch-driver generation. Uses a fake SQLcl binary;
# no Oracle, Docker daemon, or network access is needed.

setup() {
  repo_root="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  work="$(mktemp -d)"
  mkdir -p "$work/bin" "$work/lib"
  cp "$repo_root/runner/lib/db-connect.sh" "$work/lib/db-connect.sh"
  cp "$repo_root/runner/sqlcl/sqlcl-connect.sh" "$work/sqlcl-connect.sh"
  : > "$work/script.sql"
  cat > "$work/bin/sql" <<'EOF'
#!/usr/bin/env bash
set -eu
cat "${2#@}" > "$SQLCL_DRIVER_CAPTURE"
EOF
  chmod +x "$work/bin/sql"
}

teardown() {
  rm -rf "$work"
}

@test "sqlcl batch wrapper forwards positional arguments to the script" {
  run env SQLCL_BIN="$work/bin/sql" SQLCL_DRIVER_CAPTURE="$work/driver" \
    DB_USER=user DB_PASSWORD=password DB_HOST=127.0.0.1 DB_PORT=1521 \
    DB_SERVICE=FREEPDB1 ORAQUERY_TLS=disable \
    "$work/sqlcl-connect.sh" -f "$work/script.sql" 64
  [ "$status" -eq 0 ]
  grep -Fx "@$work/script.sql 64" "$work/driver"
}

@test "sqlcl batch wrapper rejects an unreadable script before invoking SQLcl" {
  run env SQLCL_BIN="$work/bin/sql" SQLCL_DRIVER_CAPTURE="$work/driver" \
    DB_USER=user DB_PASSWORD=password DB_HOST=127.0.0.1 DB_PORT=1521 \
    DB_SERVICE=FREEPDB1 ORAQUERY_TLS=disable \
    "$work/sqlcl-connect.sh" -f "$work/missing.sql"
  [ "$status" -eq 2 ]
  [[ "$output" == *"script not readable"* ]]
  [ ! -e "$work/driver" ]
}
