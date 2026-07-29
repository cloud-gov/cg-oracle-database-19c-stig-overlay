---
title: "Minimum-Viable Oracle 19c STIG Overlay Profile — Feature Plan"
description: "Scope, organization, and MVP plan for a minimally-viable InSpec profile for Oracle 19c STIG validation on brokered Cloud.gov RDS"
status: draft
tier: 2
last_updated: "2026-07-29"
---

# FEATURE — Minimum-Viable Oracle 19c STIG Overlay Profile

> **Status: draft / work in progress.** This document is the forward plan for the
> `feat/minimum-viable-profile` branch. It is not a compliance attestation. See the
> [README](README.md) for the current committed state of the repo.

## High-level goals

The goal of this feature is to have a minimally-viable profile for Oracle 19c STIG
validation to serve as the basis for:

- Testing our validation process/architecture end to end.
- A baseline for iterating on our custom overlay controls.

This is part of the overall Cloud.gov brokered STIG-compliant Oracle 19c database
epic ([cloud-gov/aws-broker#519](https://github.com/cloud-gov/aws-broker/issues/519),
[PR #537](https://github.com/cloud-gov/aws-broker/pull/537)); see especially the
`docs/oracle19c/` files on that branch.

## Relationship to other InSpec-based profiles

The intent is to leverage the upstream MITRE baseline and contribute back to it.

The upstream at <https://github.com/mitre/oracle-database-19c-stig-baseline> is not
usable as-is. The blocking problem is that a control with mismatched quotes/parens is
a syntax error that prevents the profile from even **loading** — so a `depends`
statement against upstream fails outright, before any control runs (reported upstream
as [mitre/oracle-database-19c-stig-baseline#1](https://github.com/mitre/oracle-database-19c-stig-baseline/issues/1)).
Beyond that load-blocker, the profile is also substantially incomplete — roughly 35+
of 96 controls are empty stubs, and some content is 12c-mislabeled (tracked in
[#6](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/6)).
Because of this, the `inspec.yml` in this repo will `depends` on our Cloud.gov fork
and the `cloudgov` branch
(<https://github.com/cloud-gov/oracle-database-19c-stig-baseline/tree/cloudgov>),
which carries the syntax fix.

Our intention is for the MITRE repo to eventually be authoritative for anyone else
needing to consume Oracle 19c validation checks. We will make updates to generic
checks in our fork of the MITRE repo, then submit those upstream as PRs. If there is
no motion on our PRs, we can reach out to MITRE directly.

### Generic vs. Cloud.gov-specific: what lives where

This is the core organizing rule for the whole effort:

- **Generic checks belong upstream** (MITRE, and our `cloud-gov` fork until the PRs
  are accepted). Any "fixed" generic checks currently sitting in this PR should be
  **dropped from here** and moved to the fork. This lets third parties consume the
  generic profile without our Cloud.gov-specific logic, and keeps this repo and its
  PR tightly focused.
- **Cloud.gov / AWS-RDS-specific checks** live as overlay controls in *this* repo.

## Client and runtime

This feature branch will use the Go query client and the Docker setup from
[PR #10](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/pull/10).

That approach currently commits a binary executable, which violates the OpenSSF
allstar binary-artifacts policy
(<https://deepwiki.com/ossf/allstar/3.2-binary-artifacts-policy>). For the MVP we are
deliberately overlooking this, but it must not ship this way. How the binary is
built/provided (or whether we adopt a client that needs no in-repo build) is tracked
in [#11](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/11).
The validation/runner container work is tracked in
[#7](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/7).

## Benchmark version

The target benchmark must be pinned to a specific DISA release. `control-layers.yml`
currently carries `benchmark_version: unverified`; before this profile is treated as
authoritative, confirm the exact DISA Oracle Database 19c STIG version + release date
and cite the benchmark filename (tracked with the accuracy verification in
[#9](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/9)).

## Organization

- SQL hardening lives in `hardening/sql/` (with reversals in
  `hardening/sql/rollback/`). This layout is non-standard for InSpec repos, but it
  provides a reference to the open-source community on what scripts might support
  their hardening effort.
- The Go query client and its Docker setup will be added from
  [PR #10](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/pull/10)
  (directory name TBD; not yet in the tree). See
  [#11](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/11).

## MVP

For initial testing, we will only `require_control` for **SV-270495**
(concurrent sessions per user / `SESSIONS_PER_USER`). It is a good first target
because it exercises the Go query client via `oracledb_session` and has the
simplest possible check logic — a single `SELECT limit FROM SYS.DBA_PROFILES`
with a flat `should_not include 'UNLIMITED'/'DEFAULT'` assertion (no allowlist
exceptions or branching). This validates the full `depends` → overlay →
SQL-verify path end to end without control-specific complexity obscuring the
architecture test.

## Suggested implementation

From [PR #10](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/pull/10):

- Move the profile material to the **top level** so `inspec.yml` lives at the repo
  root — a profile must have its `inspec.yml` at the top to be consumable. (Today the
  `controls/` and `profile/` directories exist but are empty, and there is no
  top-level `inspec.yml` yet; this is tracked in
  [#3](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/3).)
- Do **not** vendor the baseline — we consume the upstream Cloud.gov fork via
  `depends` (no committed `vendor/`).
- Keep the runners and architecture.
- Keep the local validation (development signal only — never compliance evidence).
