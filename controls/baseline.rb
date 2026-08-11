# Pull in the runnable Oracle 19c STIG controls from the depended-on baseline
# (the cloud-gov fork's `cloudgov` branch). We `require_controls` rather than
# redefine them so the overlay stays a thin consumer of the authoritative
# DISA/MITRE checks; Cloud.gov/RDS-specific logic lives elsewhere in this repo
# (control-layers.yml, hardening/sql/).
#
# Scope: the 32 baseline controls that define actual InSpec tests (each connects
# via oracledb_session). The remaining baseline controls are empty stubs or
# doc-only manual-review controls with no tests to run, so they are intentionally
# not required here.
#
# The baseline `cloudgov` branch now forwards `port: input('port')` into every
# oracledb_session connect string (PR #1), and declares the `port` input, so the
# previous inline SV-270495 override is no longer needed — this overlay's `port`
# input flows straight through to the required controls.
require_controls 'oracle-database-19c-stig-baseline' do
  control 'SV-270495'
  control 'SV-270501'
  control 'SV-270502'
  control 'SV-270505'
  control 'SV-270515'
  control 'SV-270518'
  control 'SV-270521'
  control 'SV-270522'
  control 'SV-270524'
  control 'SV-270525'
  control 'SV-270527'
  control 'SV-270528'
  control 'SV-270529'
  control 'SV-270530'
  control 'SV-270532'
  control 'SV-270533'
  control 'SV-270534'
  control 'SV-270535'
  control 'SV-270540'
  control 'SV-270541'
  control 'SV-270545'
  control 'SV-270549'
  control 'SV-270551'
  control 'SV-270552'
  control 'SV-270554'
  control 'SV-270556'
  control 'SV-270563'
  control 'SV-270569'
  control 'SV-270573'
  control 'SV-270574'
  control 'SV-270585'
  control 'SV-276000'
end
