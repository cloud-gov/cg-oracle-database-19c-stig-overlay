#!/usr/bin/env bash
# run-validation.sh (#7) — execute the vendored MITRE Oracle 19c STIG profile
# against a target Oracle DB via CINC Auditor + oracledb_session (sqlcl backend),
# emit per-control pass/fail/skip/error + a summary that is the AUTHORITATIVE
# stub/coverage count for #6.
#
# Required env (injected at runtime, never baked into the image):
#   DB_USER, DB_PASSWORD, DB_HOST, DB_SERVICE
# Optional:
#   DB_PORT (default 1521; use 2484 for TCPS), OUT_DIR (default /out)
#
# Fidelity: local runs target Oracle 23ai Free (gvenzl) — NOT 19c/SE2/RDS. This
# proves the check LOGIC runs; RDS/version-specific behavior is deferred to the
# live proof (aws-broker#558). Do not treat this output as compliance evidence.

set -euo pipefail

: "${DB_USER:?DB_USER required}"
: "${DB_PASSWORD:?DB_PASSWORD required}"
: "${DB_HOST:?DB_HOST required}"
: "${DB_SERVICE:?DB_SERVICE required}"
DB_PORT="${DB_PORT:-1521}"
OUT_DIR="${OUT_DIR:-/out}"
mkdir -p "$OUT_DIR"

echo "run-validation: CINC Auditor $(cinc-auditor version 2>/dev/null || inspec version 2>/dev/null || echo '?')"
echo "run-validation: sqlcl $(sql -V 2>/dev/null | head -1 || echo '?')"
echo "run-validation: target ${DB_HOST}:${DB_PORT}/${DB_SERVICE} as ${DB_USER}"

# Inputs the MITRE profile expects. oracledb_session uses sqlcl (sqlcl_bin).
cat >/tmp/inputs.yml <<EOF
user: '${DB_USER}'
password: '${DB_PASSWORD}'
host: '${DB_HOST}'
service: '${DB_SERVICE}'
port: ${DB_PORT}
sqlplus_bin: 'oraquery'
sqlcl_bin: ''
failed_logon_attempts: 3
standard_auditing_used: true
unified_auditing_used: false
EOF

# CINC Auditor is invoked as `cinc-auditor` (falls back to `inspec` if aliased).
AUDITOR=cinc-auditor
command -v "$AUDITOR" >/dev/null 2>&1 || AUDITOR=inspec

set +e
"$AUDITOR" exec /profile \
    --input-file /tmp/inputs.yml \
    --reporter cli "json:${OUT_DIR}/results.json" \
    --no-distinct-exit
rc=$?
set -e

# Summarize per-status from the JSON (the authoritative coverage count).
if [ -f "${OUT_DIR}/results.json" ]; then
    echo "=== per-control status summary ==="
    # crude jq-free summary via ruby (present in the auditor image)
    ruby -rjson -e '
      d=JSON.parse(File.read(ENV["OUT_DIR"]+"/results.json"))
      ctrl=d["profiles"].flat_map{|p| p["controls"]}
      require "set"
      counts=Hash.new(0)
      ctrl.each do |c|
        res=(c["results"]||[])
        if res.empty?
          counts["EMPTY_no_results(STUB?)"]+=1
        elsif res.any?{|r| r["status"]=="failed"}
          counts["failed"]+=1
        elsif res.all?{|r| r["status"]=="skipped"}
          counts["skipped"]+=1
        elsif res.all?{|r| r["status"]=="passed"}
          counts["passed"]+=1
        else
          counts["mixed/error"]+=1
        end
      end
      puts "total controls: #{ctrl.size}"
      counts.sort.each{|k,v| puts "  #{k}: #{v}"}
    ' OUT_DIR="$OUT_DIR"
else
    echo "run-validation: no results.json produced" >&2
fi

echo "run-validation: done (auditor exit ${rc}). Results in ${OUT_DIR}/results.json"
# Exit 0: this is a VALIDATION run (we want the report), not a pass/fail gate.
exit 0
