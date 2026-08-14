# Pull in ALL Oracle 19c STIG controls from the depended-on baseline (the
# cloud-gov fork's `cloudgov` branch) exactly as they are defined there. Using
# `include_controls` with no per-control filter keeps this overlay a thin
# consumer of the authoritative DISA/MITRE checks — every baseline control (its
# assertions, skips, impact, and tags) is inherited as-is. Cloud.gov/RDS-specific
# logic lives elsewhere in this repo (control-layers.yml, hardening/sql/).
#
# The baseline `cloudgov` branch forwards `port: input('port')` into every
# oracledb_session connect string and declares the `port` input, so this
# overlay's `port` input flows straight through to the inherited controls.
include_controls 'oracle-database-19c-stig-baseline'
