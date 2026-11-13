---
title: "Repository instructions for AI agents"
description: "Project-specific safety, development, and Cloud.gov workflow guidance for AI coding agents."
status: canonical
tier: 1
last_updated: "2026-11-09"
---

# Repository instructions for AI agents

These instructions supplement the universal agent behavioral contract. They do
not grant authority to access external systems, deploy applications, modify a
database, or handle data beyond the user's authorization.

## Project context

This repository contains the Cloud.gov Oracle Database 19c STIG overlay,
validation runner, and SQLcl-based hardening tooling. Keep local functional
checks distinct from evidence produced against the authorized AWS RDS target.
An accepted platform exception is not technical STIG compliance or assessor
approval.

## Safety and data handling

- Treat database and Cloud.gov data as sensitive. Do not print, commit, or copy
  `.env`, credentials, `VCAP_SERVICES`, connection strings, hostnames, or
  database usernames into logs, documentation, or reports shared outside the
  authorized review boundary.
- Use the app's bound `aws-rds` service and the shared connection resolver;
  do not add direct credentials to application configuration.
- Live database checks must be read-only unless the user separately authorizes
  a specific change. Never run customer hardening scripts, DDL, DML, or other
  database-altering commands as part of validation without explicit approval.
- Before a live Cloud.gov action, identify the target org/space, app, and
  service. Do not bind, unbind, push, restart, or delete Cloud.gov resources
  unless explicitly authorized for that operation.
- Never deploy a local or feature-branch auditor image directly to Cloud.gov.
  The Cloud.gov auditor image is built and published through the approved AWS
  pipeline; verify its provenance and branch/revision before using it for a
  feature-branch assessment.
- Do not broaden RDSADMIN-only exceptions based on unidentified profiles.
  Preserve unknown, missing, or unexpected values as findings and distinguish
  an accepted deviation from technical compliance.

## Development and verification

- Start with the relevant files and `git status`; preserve unrelated user work.
- Use the Makefile as the source of truth for supported commands.
- `make verify` runs local/static checks and builds the local runner; it does
  not establish live AWS RDS compliance.
- `make test-rdsadmin` exercises the exception logic with fake SQL. It is not a
  substitute for testing against Oracle.
- `make report-cloudgov` runs the auditor app's default full (`--all`) posture
  and saves JSON report artifacts under `out/` by default. Review connection
  metadata before sharing artifacts; never treat platform-only skipped controls
  as customer-compliance evidence.
- Run `git diff --check` and the applicable tests after changes. Report checks
  blocked by unavailable Docker, Cloud.gov access, or database connectivity;
  do not claim an unrun check passed.

## Cloud Foundry CLI and credentials

- The CLI is a prerequisite for Cloud.gov operations. Use the official
  Cloud Foundry CLI GitHub releases and verify the published SHA-256 digest.
  Prefer a user-local or session-temporary install; do not install system-wide
  without explicit approval.
- Keep `.env` ignored and untracked. Load it only in the command's environment
  as needed; do not display its contents. The Makefile supports `CF_ENV_FILE`
  for Cloud Foundry deployment credentials/configuration.
- Never put secrets in command-line arguments, shell transcripts, source files,
  or committed configuration. Use existing authenticated CF sessions or the
  Makefile's environment-variable authentication flow.

## Change scope and contribution

- Keep changes focused on the approved request. Ask before changing CI/CD,
  deployment architecture, dependency versions, or database state.
- Architecture changes and new external dependencies require an ADR review.
- AI-generated code requires human review before production use. Follow
  `CONTRIBUTING.md` and the repository's contribution eligibility policy.
