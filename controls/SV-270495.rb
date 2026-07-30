# MVP overlay: pull in exactly one control from the depended-on baseline
# (the cloud-gov fork's `cloudgov` branch) to validate the full
# depends -> overlay -> SQL-verify path end to end.
#
# SV-270495 (concurrent sessions per user / SESSIONS_PER_USER) is the simplest
# oracledb_session check in the baseline: a single SELECT against
# SYS.DBA_PROFILES with a flat should_not-include assertion. As more controls
# are dispositioned per control-layers.yml, add them to this block (#3).
require_controls 'oracle-database-19c-stig-baseline' do
  control 'SV-270495'
end
