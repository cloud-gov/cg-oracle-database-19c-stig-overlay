# Cloud.gov Agent Workflow

This repository may deploy and test applications only in the Cloud.gov development environment. Agents must not use these instructions for staging or production.

## Host Prerequisites

Before starting the sandbox, a human administrator must:

1. Create a dedicated Cloud.gov `space-deployer` service account in the org and space used for this work. The plan initially assigns its service account the `SpaceDeveloper` role in that one space. Authenticate and target the dedicated development org and space, then create the service instance and a service key:

   ```sh
   cf create-service cloud-gov-service-account space-deployer cg-overlay-service-account
   cf create-service-key cg-overlay-service-account cg-overlay-service-key
   cf service-key cg-overlay-service-account cg-overlay-service-key
   ```

   Append the returned credentials to the ignored `.env` file without printing them:

   ```sh
   cf service-key cg-overlay-service-account cg-overlay-service-key --json \
     | jq -r '"CF_DEPLOYER_USERNAME=\(.username)\nCF_DEPLOYER_PASSWORD=\(.password)"' >> .env
   ```

   Do not print, commit, or otherwise share the credentials. Do not add or modify service-account roles without explicit approval.

2. Save the service-account credentials locally in an ignored file such as `.env`. Never commit credentials, tokens, CF configuration, or command output that includes them.
3. Configure the host's agentic-coding-quickstart network allowlist at `~/.config/acq/cloudgov-balanced-hosts.txt` with these endpoints:

   ```text
   api.dev.us-gov-west-1.aws-us-gov.cloud.gov:443
   login.dev.us-gov-west-1.aws-us-gov.cloud.gov:443
   uaa.dev.us-gov-west-1.aws-us-gov.cloud.gov:443
   ssh.dev.us-gov-west-1.aws-us-gov.cloud.gov:2222
   doppler.dev.us-gov-west-1.aws-us-gov.cloud.gov:443
   ```

4. Export the allowlist path before launching `acq`:

   ```sh
   export ACQ_MSB_BALANCED_HOSTS_FILE="$HOME/.config/acq/cloudgov-balanced-hosts.txt"
   ```

The host configuration is outside the sandbox. Do not try to modify `~/.config/acq/` from the sandbox.

## Sandbox Setup

Install the Cloud Foundry CLI from the official `cloudfoundry/cli` GitHub releases into the ignored `.tools/bin` directory. Select the release asset matching the sandbox architecture, such as `cf8-cli_<version>_linux_arm64.tgz` on Linux ARM64.

```sh
mkdir -p .tools/bin
curl --fail --location --proto '=https' --tlsv1.2 \
  --output /tmp/cf8-cli.tgz \
  https://github.com/cloudfoundry/cli/releases/download/v<version>/cf8-cli_<version>_linux_arm64.tgz
tar -xzf /tmp/cf8-cli.tgz -C .tools/bin
.tools/bin/cf8 version
```

Only download release artifacts from `https://github.com/cloudfoundry/cli/releases`. Verify the CLI version before using it.

## Development Deployment And Testing

Load credentials only into the current shell, authenticate to the configured development API, and target the dedicated org and space. Do not print credential values.

```sh
set -a
source .env
set +a
.tools/bin/cf8 api "$CF_API"
.tools/bin/cf8 auth "$CF_DEPLOYER_USERNAME" "$CF_DEPLOYER_PASSWORD"
.tools/bin/cf8 target -o <dedicated-org> -s <dedicated-space>
.tools/bin/cf8 apps
```

Use the repository's deployment and validation targets:

```sh
make push-cloudgov
make report-cloudgov
```

Before deploying, confirm the active API, org, and space with `cf8 target`. Use only the dedicated development space. After a deployment, verify the target app is running with `cf8 app <app-name>` and use a non-mutating SSH command such as `cf8 ssh <app-name> -i 0 -c true` before running a validation command over SSH.

Do not delete apps, services, routes, spaces, or orgs without explicit human approval. Do not deploy to any environment other than the dedicated development org and space.
