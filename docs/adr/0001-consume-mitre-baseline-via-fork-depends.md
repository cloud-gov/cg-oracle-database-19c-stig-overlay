---
title: "Consume the MITRE Oracle 19c baseline via a pinned git depends on the cloud-gov fork"
status: "accepted"
date: "2026-07-29"
decision_makers: ["pburkholder", "wz-gsa"]
category: "dependency-management"
nist_controls: ["CM-2", "SR-3", "SR-11", "SA-11", "CM-7"]
impact_level: "moderate"
ato_relevance: "yes-internal"
risk_treatment: "mitigate"
---

# Consume the MITRE Oracle 19c baseline via a pinned git depends on the cloud-gov fork

> **Note (pre-production):** These ADRs are development-phase records. Before this
> repo goes to production, the ADR set may be **consolidated** — decisions that are
> no longer relevant (e.g., superseded by a later choice or tied to scaffolding that
> is removed) may be pruned or merged. Development-phase PR/issue references in this
> record are not permanent fixtures.

## Context and Problem Statement

The Cloud.gov Oracle 19c STIG overlay must reuse the DISA Oracle 19c STIG checks
rather than reimplement them, but the upstream MITRE profile is not directly
consumable: a control with mismatched quotes/parens is a syntax error that prevents
the profile from even *loading*, so a `depends` against upstream fails before any
control runs
([mitre/oracle-database-19c-stig-baseline#1](https://github.com/mitre/oracle-database-19c-stig-baseline/issues/1)),
and the profile is also substantially incomplete (~35+/96 empty stubs, plus a
12c-mislabeled `inspec.yml`) — tracked in
[#6](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/6).
We need a dependency strategy that gives reproducible resolution while letting us
carry fixes and eventually contribute them upstream.

## Decision Drivers

- **Reproducibility / supply-chain integrity (SR-3, SR-11, CM-2):** dependency
  resolution must be pinned and repeatable across machines and CI, not a floating
  branch HEAD.
- **Do not reimplement generic checks:** reuse the authoritative DISA/MITRE checks;
  keep this repo focused on Cloud.gov / AWS-RDS-specific overlay logic.
- **Upstream is currently unusable** (load-blocking syntax error; incompleteness).
- **Contribute-back path:** generic fixes should be easy to route to MITRE via our
  fork, without entangling Cloud.gov-specific logic.
- **Repo hygiene / focus (CM-7):** avoid committing a large vendored tree that
  obscures the small overlay and drifts from its source.

## Considered Options

1. **Vendor a pinned copy of the baseline committed into the overlay** — commit the
   baseline profile (pinned SHA + checksum) into `vendor/` for air-gapped/FedRAMP
   reproducibility.
2. **git `depends` on the cloud-gov fork's `cloudgov` branch + committed
   `inspec.lock`** — pin the dependency in the lockfile; regenerate the (gitignored)
   `vendor/` at build time via `cinc-auditor vendor`.
3. **git `depends` on the fork with no lockfile** — resolve the `cloudgov` branch
   HEAD live on every vendor.

## Decision Outcome

Chosen option: **Option 2 — git `depends` on the cloud-gov fork's `cloudgov` branch
with a committed `inspec.lock`.** The lockfile pins the exact fork commit (reproducible
resolution) while the resolved `vendor/` tree stays a gitignored build artifact, so the
repo stays focused on the overlay. Generic fixes live in the fork (and flow upstream to
MITRE via PR); Cloud.gov/RDS-specific checks live here. Discussed and agreed between
@pburkholder and @wz-gsa; this supersedes the "commit a vendored, pinned baseline into
the overlay" assumption in
[#7](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/7).

### Positive Consequences

- Reproducible dependency resolution via the committed `inspec.lock` (pinned fork ref).
- Small, focused repo; no large vendored tree to review or drift.
- Clear generic-vs-Cloud.gov boundary; a clean contribute-back path to MITRE.
- The fork's `cloudgov` branch carries the load-blocking syntax fix and the 12c→19c
  `inspec.yml` identity fix, so the overlay actually loads.

### Negative Consequences

- Vendoring requires network access to the fork at build time (mitigated by pinning;
  a future air-gapped posture may still need a cached/mirrored source).
- Two places to maintain (fork + overlay) until upstream PRs are accepted.
- Lockfile must be regenerated and re-committed whenever the pinned fork ref advances.

### Compliance Consequences

- **CM-2 / SR-3 / SR-11:** dependency baseline is pinned and integrity-relevant;
  `inspec.lock` is the configuration record and MUST be committed.
- **SA-11:** authoritative pass/fail still requires a live brokered GovCloud RDS run;
  local/CI runs are development signal only.
- If an air-gapped/FedRAMP-image requirement later forbids build-time fetches, revisit
  this decision (a mirrored/cached source or a committed vendor tree may be needed) and
  supersede this ADR.

## Links

- [FEATURE plan → PR #12](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/pull/12)
- [#3 — commit/generate runnable 19c controls + `port` input](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/3)
- [#6 — MITRE baseline incomplete + 12c-mislabeled](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/6)
- [#7 — CINC-Auditor validation/runner container](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/7)
- [mitre/oracle-database-19c-stig-baseline#1 — upstream load-blocking syntax error](https://github.com/mitre/oracle-database-19c-stig-baseline/issues/1)
- `control-layers.yml` — control → implementation-layer map (`set_by` / `verified_by`)
