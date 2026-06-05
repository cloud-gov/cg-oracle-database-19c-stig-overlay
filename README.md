# Cloud.gov Oracle 19c STIG Compliance Baseline

Cloud.gov baseline Inspec profile for Oracle 19c, based on
[MITRE's Oracle 12c Baseline](https://github.com/mitre/oracle-database-12c-stig-baseline)

The baseline InSpec profile is used to validate the secure configuration of
Oracle 19c exactly against DISA's Oracle 19c (STIG) Version 1 Release 5.

For this work we use the open-source `cinc-auditor` from the
[Cinc Project](https://cinc.sh), derived from
[Chef InSpec](https://docs.chef.io/inspec/).

## Architecture and overview

The essential components are:

- The Oracle DB under test, instantiated with the Cloud.gov AWS Broker
- A Cloud.gov Cloud Foundry app, "bridge", with a binding to the Oracle DB
- A CINC Auditor + Oracle SQLPlus client Docker container running locally on the
  testing workstation.

To run the audit, we:

- Build the Docker image (or pull it from a repository)
- Start the bridge app
- Bind the Oracle DB to the bridge app
- Establish an SSH connection with `cf ssh` to the bridge app and tunneling to
  port 1521 on the Oracle DB
- Update the `input.yml` with the credentails to connect to the Oracle DB
- Run the audit

> [!ADR NOTES]
>
> - This uses cinc-auditor instead of Chef Inspec to avoid licensing issues
> - This uses cinc-auditor in Docker to avoid supply-chain risks
> - Installing `sqlplus` on the bridge app, and using
>   `cinc-auditor -t ssh://...` fails because CINC's ssh algorithms are
>   incompatible with Cloud Foundry's algorithm So this seems like the most
>   practable steps at this point.

## Steps

- make docker-image
- make app
- make binding
- make input
- make ssh
- make audit

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

## Testing / Debugging Snippes

SQLPLUS direct for testing

    sqlplus $username/$password@host.docker.internal:62549/ORCL

# smoke test

docker run -v $(pwd):/share cinc-auditor-oracle version

# run profile

docker run -v $(pwd):/share cinc-auditor-oracle exec . --input-file input.yml

# shell

docker run -v $(pwd):/share -it cinc-auditor-oracle shell --input-file input.yml
