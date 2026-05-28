# Cloud.gov Oracle 19c STIG Compliance Baseline

Cloud.gov baseline Inspec profile for Oracle 19c, based on
[MITRE's Oracle 12c Baseline](https://github.com/mitre/oracle-database-12c-stig-baseline)

The baseline InSpec profile is used to validate the secure configuration of
Oracle 19c exactly against DISA's Oracle 19c (STIG) Version 1 Release 5.

For this work we use the open-source `cinc-auditor` from the
[Cinc Project](https://cinc.sh), derived from
[Chef InSpec](https://docs.chef.io/inspec/).

## Testing this overlay against an existing AWS RDS DB in Cloud.gov

### ToDo: Update for Oracle and brokered databases

Auditing is currently done on-demand from a Cloud.gov platform operator's
workstation. Running as part of CI/CD is a future implementation step (as of
2025-08-06). Assuming you're on a Cloud.gov dev workstation:

- Install `mysql-client` and `cinc-auditor`
  - e.g. `brew install cinc-workstation; brew install mysql-client`
  - note: We have requested that corporate policies allow access to
    downloads.cinc.sh, but that may not yet have happened.
- The next steps are fully described in
  <https://github.com/cloud.gov/internal-docs>:
  - Obtain the MySQL database hostname, username, and password
  - Establish an SSH tunnel from localhost:3306 to remote_server:3306
  - Test `mysql` connection with `mysql -p -h 127.0.0.1 -u <USERNAME>` (and
    password)
  - Note: **DO NOT** use `mysql -p$PASSWORD -h 127.0.0.1 -u <USERNAME>` as the
    passwords will be visible in the system process list.
- Copy `input_sample.yml` to `input.yml`
- Update `input.yml` with the `user` and `password`. Be sure to
  - set strict file permissions
  - delete the file when your work is done
- Run `cinc-auditor` for the profile:

```sh
cinc-auditor exec .  --show-progress --input-file input.yml  \
 --reporter=cli json:reports/$(date +'%Y-%m-%dH%H%M').json
```

- Or run `cinc-auditor` for a single control, e.g.:

```sh
cinc-auditor exec .  --show-progress --input-file input.yml  \
  --reporter=cli json:reports/$(date +'%Y-%m-%dH%H%M').json \
  --controls 'SV-235096'
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into
**[heimdall-lite](https://github.com/mitre/heimdall2/)** for a user-interactive,
graphical view of the InSpec results. For local usage:

```shell
npx @mitre/heimdall-lite &
```

The Heimdall-Lite interface will be available at <http://localhost:8080>. From
the Finder, you can then drag the `.json` results into the viewer to see if
there are any variations from our standards.
