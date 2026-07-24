# oracle-database-19c-stig-baseline

InSpec profile to validate secure configuration of Oracle Database 19c against the DISA Oracle Database 19c Security Technical Implementation Guide (STIG).

This profile contains 96 controls in `controls/`. Controls use Oracle SQL checks through `oracledb_session(...)` and environment-specific values from `inspec.yml` or an input override file.

## Getting Started

Install current Chef InSpec and supporting Ruby components on the runner. Installation options are available from the [Chef InSpec documentation](https://docs.chef.io/inspec/).

```sh
bundle install
bundle exec rake inspec:check
```

## Tailoring to Your Environment

Create an input file such as `inputs.yml` before running the profile. Do not commit real credentials or target-specific secrets.

More information about inputs is available in the [InSpec inputs documentation](https://docs.chef.io/inspec/profiles/inputs/).

```yaml
# Username Oracle DB, for example: system
user: ''

# Password Oracle DB
password: ''

# Hostname or IP for Oracle DB, for example: localhost
host: ''

# Oracle service name, for example: ORCLCDB
service: ''

# Location of sqlplus, for example: /opt/oracle/product/19c/dbhome_1/bin/sqlplus
sqlplus_bin: ''

# Set based on the Oracle 19c audit configuration
standard_auditing_used: true
unified_auditing_used: false

# Organization-specific allow lists
allowed_db_links: []
allowed_dbadmin_users: []
users_allowed_access_to_public: []
allowed_users_dba_role: []
allowed_users_system_tablespace: []
allowed_application_owners: []
allowed_unlocked_oracledb_accounts: []
users_allowed_access_to_dictionary_table: []
allowed_users_with_admin_privs: []
allowed_audit_users: []
allowed_dbaobject_owners: []
allowed_oracledb_components: []
allowed_oracledb_components_integrated_into_dbms: []
oracle_dbas: []
emergency_profile_list: []

# Organization-specific profile parameter thresholds
failed_logon_attempts: 3
password_life_time: 35
account_inactivity_age: 35
```

## Running This Profile

### Using SSH

Run all controls from a local checkout:

```sh
bundle exec inspec exec . -t ssh://<user>@<host>:<port> --sudo --input-file=inputs.yml --reporter=cli json:oracle-database-19c-stig-baseline-results.json
```

Run one control from a local checkout:

```sh
bundle exec inspec exec . -t ssh://<user>@<host>:<port> --sudo --input-file=inputs.yml --controls=SV-270495
```

Run from the GitHub archive:

```sh
inspec exec https://github.com/mitre/oracle-database-19c-stig-baseline/archive/master.tar.gz -t ssh://<user>@<host>:<port> --sudo --input-file=inputs.yml --reporter=cli json:oracle-database-19c-stig-baseline-results.json
```

### Using WinRM

```sh
inspec exec https://github.com/mitre/oracle-database-19c-stig-baseline/archive/master.tar.gz -t winrm://<host> --user '<admin-account>' --password='<password>' --input-file=inputs.yml --reporter=cli json:oracle-database-19c-stig-baseline-results.json
```

### Using Docker

```sh
bundle exec inspec exec . -t docker://<containerid> --input-file=inputs.yml --reporter=cli json:oracle-database-19c-stig-baseline-results.json
```

Docker runs require a target container with access to the Oracle Database 19c instance and the configured `sqlplus_bin`.

Full command options are available in the [InSpec CLI documentation](https://docs.chef.io/inspec/cli/).

## Running from a Local Archive

Create a reusable archive when the runner cannot always reach GitHub.

```sh
mkdir profiles
cd profiles
git clone https://github.com/mitre/oracle-database-19c-stig-baseline
cd oracle-database-19c-stig-baseline
bundle install
bundle exec inspec archive . --overwrite
bundle exec inspec exec <generated-archive>.tar.gz -t ssh://<user>@<host>:<port> --sudo --input-file=inputs.yml --reporter=cli json:oracle-database-19c-stig-baseline-results.json
```

Refresh the archive after profile updates:

```sh
cd oracle-database-19c-stig-baseline
git pull
bundle install
bundle exec inspec archive . --overwrite
```

## Local Checks

```sh
bundle exec rake inspec:check
bundle exec rake lint
bundle exec rake pre_commit_checks
```

## Viewing the JSON Results

Load the JSON results file into [Heimdall Lite](https://heimdall-lite.mitre.org/) for an interactive view of the InSpec results.

The JSON results file can also be loaded into a [full Heimdall server](https://github.com/mitre/heimdall) to store and compare multiple profile runs.

## Contributing and Getting Help

To report a bug or feature request, open an [issue](https://github.com/mitre/oracle-database-19c-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE

DISA STIGs are published by DISA, see: <https://public.cyber.mil/stigs/>
