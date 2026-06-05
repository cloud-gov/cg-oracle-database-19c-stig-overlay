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

## Running over Cloud.gov SSH

APP="cinc-auditor" APP_GUID=$(cf app $APP --guid)
PROC_GUID=$(cf curl
/v3/apps/${APP_GUID}/processes | jq -r '.resources[] | select(.type=="web") | .guid')
SSH_USER=cf:$PROC_GUID/0
SSH_ENDPOINT=ssh.dev.us-gov-west-1.aws-us-gov.cloud.gov PORT=2222

ssh -p $PORT $SSH_USER@$SSH_ENDPOINT

---

cf:$(cf curl /v3/apps/$(cf app APP-NAME --guid)/processes | jq -r '.resources[]
| select(.type=="web") | .guid')/0@SSH-ENDPOINT

ssh

    inspec exec . -t ssh://<hostip> --user '<admin-account>' --password=<password> --input-file input.yml

ssh -p PORT-NUMBER cf:$(cf curl /v3/apps/$(cf app APP-NAME --guid)/processes |
jq -r '.resources[] | select(.type=="web") | .guid')/0@SSH-ENDPOINT

    #--reporter cli json:<filename>.json

Runs this profile over ssh to the host at IP address <hostip> as a privileged
user account (i.e., an account with administrative privileges), reporting
results to both the command line interface (cli) and to a machine-readable JSON
file. inspec exec
https://github.com/mitre/oracle-database-12c-stig-baseline/archive/master.tar.gz
-t
ssh://$hostip --user '<admin-account>' --password=<password> --input-file oracle-database-input-file.yml --reporter cli json:oracle-database-12c-stig-baseline-results.json
inspec exec <name of generated archive> -t ssh://$hostip
--user '<admin-account>' --password=<password>
--input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml>
--reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
inspec exec <name of generated archive> -t ssh://$hostip --user
'<admin-account>' --password=<password>
--input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml>
--reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>

SQLPLUS direct for testing

sqlplus $username/$password@127.0.0.1:62549/ORCL

<logon> is: {<username>[/<password>][@<connect_identifier>] | / }
