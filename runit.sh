#!/bin/bash

set -euo pipefail

## Running over Cloud.gov SSH

APP="cinc-auditor" APP_GUID=$(cf app $APP --guid)
PROC_GUID=$(cf curl /v3/apps/${APP_GUID}/processes | jq -r '.resources[] | select(.type=="web") | .guid')
SSH_USER=cf:$PROC_GUID/0
SSH_ENDPOINT=ssh.dev.us-gov-west-1.aws-us-gov.cloud.gov PORT=2222

INSPEC="docker run -v $(pwd):/share cincproject/auditor"

#docker run -v $(pwd):/share cincproject/auditor exec . -t ssh://$SSH_ENDPOINT:2222 --user $SSH_USER --password=$(cf ssh-code) --input-file input.yml
inspec exec . -t ssh://$SSH_ENDPOINT:2222 --user $SSH_USER --password=$(cf ssh-code) --input-file input.yml
#inspec exec . -t ssh://$SSH_ENDPOINT:2222 --user $SSH_USER --password=$(cf ssh-code) --input-file input.yml
#    inspec exec . -t ssh://<hostip> --user '<admin-account>' --password=<password> --input-file input.yml
