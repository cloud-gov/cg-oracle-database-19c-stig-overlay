---
title: "Package the SQLcl runner as a Java-buildpack app (not a Docker image)"
status: "proposed"
date: "2026-08-17"
decision_makers: ["pburkholder"]
category: "deployment"
nist_controls: ["CM-2", "CM-6", "CM-7", "SR-3", "SR-11", "SC-8", "SC-13", "SI-3", "SI-7", "SA-15"]
impact_level: "moderate"
ato_relevance: "yes-internal"
risk_treatment: "mitigate"
---

# Package the SQLcl runner as a Java-buildpack app (not a Docker image)

> **Note (pre-production):** These ADRs are development-phase records. Before this
> repo goes to production, the ADR set may be **consolidated** — decisions that are
> no longer relevant (e.g., superseded by a later choice or tied to scaffolding that
> is removed) may be pruned or merged. Development-phase PR/issue references in this
> record are not permanent fixtures.

## Context and Problem Statement

The overlay ships a SQLcl runner — a full SQL\*Plus/SQLcl interpreter — to run the
`hardening/sql/*.sql` assessment scripts and an interactive REPL against the
brokered GovCloud RDS Oracle, reached over `cf ssh`. SQLcl is pure Java, so it can
be delivered to Cloud.gov either as a **Docker image** (`cf push --docker-image`)
or via the **Cloud.gov Java buildpack** (`cf push` of a vendored SQLcl
distribution). Both were implemented (`runner/sqlcl/` Docker image; `runner/sqlcl-cf/`
buildpack app). We need to decide which packaging is authoritative for the
Cloud.gov target, because the choice drives supply-chain posture, the Oracle OTN
license surface, reproducibility, and — decisively — whether the artifact must pass
Cloud.gov's mandatory in-boundary **container scanning/hardening pipeline**.

## Decision Drivers

- **In-boundary container policy (CM-2, CM-6, CM-7, SI-3, SI-7):** Cloud.gov
  Engineering Practices make container scanning/hardening **mandatory** for
  in-boundary images and **forbid pulling images from Docker Hub or other public
  registries** — images must come from the private AWS ECR, built on the
  `ubuntu-hardened` base and passed through the Grype (CVE) + ClamAV + `usg` audit
  pipeline (see internal `ADR-0007-container-scanning-and-validation.md`,
  `runbooks/Container-Scanning/container-scanning-and-hardening.md`, and
  `resources/Engineering-Practices/Containers.md`). A Docker-image SQLcl runner is
  an in-boundary image and would therefore have to be re-based on `ubuntu-hardened`
  and onboarded to that pipeline — a substantial, cross-team effort. **Buildpack
  apps built on the `cflinuxfs` stack are explicitly out of scope of that pipeline
  today** (Containers.md "Implementation progress and deviations"), so the buildpack
  path does not incur it.
- **Oracle OTN license (SR-11, CM-7):** SQLcl carries the OTN EULA. Baking it into
  a *derived* Docker image is redistribution, forcing a **private** registry and
  registry credentials on the cell. The `ubuntu-hardened` + ECR requirement above
  compounds this. Vendoring the distribution into our own buildpack app droplet in a
  single space is a lighter redistribution surface and pulls from no public registry.
- **Reproducibility / supply-chain integrity (CM-2, SR-3, SR-11):** SQLcl and its
  runtime must be pinned and repeatable. The buildpack path pins the SQLcl zip
  checksum, the named platform buildpack, and the JRE line (`JBP_CONFIG_OPEN_JDK_JRE`
  → 17). The Docker path pins by image **digest** but adds the ECR/hardened-base
  supply chain.
- **Fail-closed TLS to live RDS (SC-8, SC-13):** verify-ca on TCPS 2484 must work
  identically regardless of packaging; the PKCS12 truststore is built from the same
  checksum-verified public RDS CA PEM either way. **Validated live** on the buildpack
  path (see Decision Outcome).
- **No logic drift (SA-15):** connection discovery (`lib/db-connect.sh`) and the
  connect wrapper (`sqlcl-connect.sh`) remain single-source; the buildpack app
  delegates to them (staged copies), and a `jq` VCAP parser was added to the shared
  lib so cflinuxfs (no Ruby/python3) uses the SAME resolver — no fork.
- **Operational simplicity for reviewers/ISSO:** fewer pinned dependencies, no
  registry credentials on the cell, no cross-arch build, and — critically — no
  dependency on onboarding a new image to the container pipeline.
- **Shareability with Cloud.gov customers (who own final DB hardening):** the STIG
  hardening of a brokered Oracle DB is ultimately the **customer's** responsibility;
  this runner is a tool they run against their own bound DB. A `cf push` buildpack app
  is something a customer can deploy into **their own space** with the standard,
  self-service `cf` workflow — no access to a private registry, no registry
  credentials, and no dependency on the internal ECR/hardened-base pipeline (which is
  cloud.gov-operator infrastructure customers cannot use). The Docker-image path is
  effectively **not distributable to customers** for in-boundary use. This makes the
  buildpack path not just the internal choice but the **shareable** one.

## Considered Options

1. **Docker image (thin overlay on Oracle's official OTN SQLcl image)** — pin the
   base image by digest; bake truststore + scripts at build time. To run this
   **in-boundary** it would additionally have to be re-based on `ubuntu-hardened` and
   onboarded to the ECR + Grype + ClamAV + `usg`-audit container pipeline (internal
   ADR-0007), which also collides with the OTN redistribution restriction. Implemented
   at `runner/sqlcl/`, but scoped to **local 23ai dev testing only** (see Decision).
2. **Java-buildpack app (vendor the SQLcl distribution)** — `cf push` the vendored
   SQLcl zip through the Cloud.gov Java buildpack; build the truststore at start via
   the buildpack JRE's `keytool`; no registry, no registry creds, no cross-arch
   build, and — as a `cflinuxfs` buildpack app — outside the mandatory container
   pipeline's current scope. Implemented at `runner/sqlcl-cf/`.
3. **Both, in-boundary** — maintain the Docker image and the buildpack app as
   co-equal, supported **Cloud.gov** deployment options.

## Decision Outcome

Chosen option: **Option 2 — the Java-buildpack app is the ONLY supported Cloud.gov
(in-boundary) SQLcl runner.** The deciding factor is Cloud.gov's mandatory in-boundary
container policy: a Docker-image runner (Option 1) is a public-registry-derived,
non-`ubuntu-hardened` image and therefore **may not be run in-boundary** until it is
re-based on the hardened Ubuntu stack and onboarded to the ECR/Grype/ClamAV/`usg`
scanning pipeline (internal ADR-0007, Containers.md). That is a large, cross-team
effort and conflicts directly with the OTN redistribution restriction. The buildpack
path avoids all of it: it pulls from no public registry, needs no registry credentials
on the cell, and — as a `cflinuxfs` buildpack app — is outside the container pipeline's
current scope.

The buildpack path is not merely cheaper; it is **live-validated end-to-end**. On
2026-08-17 the deployed app (`cg-sqlcl-oracle-cf`), bound to the brokered GovCloud
RDS, connected with **verify-ca TLS on TCPS 2484** using the start-built PKCS12
truststore and ran `hardening/sql/00_connectivity_check.sql`: it reported Oracle 19c
SE2, a non-SYS effective user, and the expected assessment output — exercising the
full chain (buildpack JRE 17 → shared `jq` VCAP resolver → verified TLS → live query).

The Docker image (`runner/sqlcl/`) is **retained for LOCAL 23ai dev testing only** —
one-off queries and running the `hardening/sql/*.sql` scripts against the compose dev
DB while iterating. It is **built locally and never pushed to any registry**, which
keeps it clear of both the OTN redistribution restriction and the in-boundary
container pipeline. It is **not** an in-boundary option, and it is **not** a Cloud.gov
fallback. Keeping it local-only also preserves useful test parity: `make sqlcl-run`
exercises the **same** `sqlcl-connect.sh` wrapper and `hardening/sql/` scripts the
customer runs on Cloud.gov. Option 3 (dual in-boundary support) is rejected.

> This ADR is **proposed** pending review by the decision makers and the ISSO. Both
> implementations are committed so the trade-off — and the live validation — are
> reviewable. The Docker image's role is deliberately narrowed to local dev.

### Positive Consequences

- **No in-boundary container-pipeline dependency:** avoids re-basing on
  `ubuntu-hardened` and onboarding to ECR/Grype/ClamAV/`usg` (internal ADR-0007),
  which a Docker image would require before it could run in-boundary.
- **No public-registry pull and no registry credentials on the cell** — aligns with
  the "no Docker Hub in-boundary" rule and lightens the OTN redistribution surface.
- **No cross-arch (`buildx`) build**; the platform stages on the cell.
- **Live-validated** against real GovCloud RDS with verified TLS (see above), so this
  is a proven path, not a theoretical one.
- **Distributable to Cloud.gov customers:** because final DB hardening is the
  customer's responsibility, they can `cf push` this runner into their own space with
  the standard self-service workflow and run the `hardening/sql/*.sql` scripts against
  their bound DB — no private registry, no registry credentials, and no dependency on
  operator-only container infrastructure. The Docker-image path could not be shared
  this way for in-boundary use.
- **Local dev unaffected + test parity:** the local Docker image
  (`make sqlcl-repl` / `make sqlcl-run`) still runs the SAME wrapper and SQL scripts
  against the compose 23ai DB, so local iteration and the Cloud.gov runner cannot
  drift on script behavior.
- **Single-source logic preserved:** the shared `db-connect.sh`/`sqlcl-connect.sh`
  are reused; a `jq` VCAP parser (jq 1.6-compatible) was added so cflinuxfs uses the
  same resolver as the Ruby/python paths — no drift.

### Negative Consequences

- **More runtime pins than a single image digest:** the SQLcl zip checksum, the named
  platform buildpack, and the JRE line (`JBP_CONFIG_OPEN_JDK_JRE` → 17) must each be
  pinned and updated deliberately.
- **SQLcl distribution is vendored** (~128 MB) and OTN-licensed, so it is git-ignored
  and must be re-vendored (with checksum) on upgrade (`runner/sqlcl-cf/vendor/README.md`).
- **Buildpack-environment quirks** had to be handled explicitly (the buildpack does
  not export `JAVA_HOME`/`PATH` to `cf ssh` exec sessions, and default JRE was Java 8;
  `entrypoint.sh` resolves `JAVA_HOME` and the manifest pins JRE 17). These are
  encoded and validated but are more moving parts than a self-contained image.
- The `cflinuxfs` stack itself is not yet hardened/scanned to the same bar as
  `ubuntu-hardened` (a known, tracked platform gap, per Containers.md) — this applies
  to all buildpack apps, not uniquely to this runner.

### Compliance Consequences

- **CM-6 / CM-7 / SI-3 / SI-7:** choosing the buildpack path keeps this tool within
  the platform's existing `cflinuxfs` buildpack-app posture and out of the Docker-image
  container-pipeline requirements of internal ADR-0007. If the tool is ever repackaged
  as a Docker image for in-boundary use, that image MUST be re-based on
  `ubuntu-hardened` and onboarded to the ECR/Grype/ClamAV/`usg` pipeline first —
  **supersede this ADR** at that point.
- **SR-11 / CM-7 (OTN):** the in-boundary buildpack app pushes **no image** to any
  registry — the OTN-licensed SQLcl binaries are vendored into the app droplet only.
  The local Docker image is likewise **built locally and never pushed**. Do not
  publish either the vendored zip or the local image.
- **CM-2 / SR-3:** the configuration record is the set of pins (SQLcl checksum, named
  buildpack, JRE line) plus the committed `manifest.yml`; updates are deliberate.
- **SC-8 / SC-13:** verify-ca on TCPS 2484 with the checksum-verified public RDS CA
  truststore is **validated live**; a plaintext/unverified connection to a live RDS
  remains refused (fail closed).
- **SA-11:** authoritative pass/fail still requires a live brokered GovCloud RDS run;
  a local 23ai run is development signal only, not compliance evidence.

## Links

- `runner/sqlcl-cf/README.md` — Java-buildpack SQLcl runner (Option 2, **chosen** for
  Cloud.gov; live-validated).
- `runner/sqlcl/README.md` — Docker-image SQLcl runner, **retained for LOCAL 23ai dev
  testing only** (built locally, never pushed; not an in-boundary option).
- Internal `ADRs/ADR-0007-container-scanning-and-validation.md` — Cloud.gov container
  scanning/validation decision (ECR + Grype); the pipeline a Docker image would need.
- Internal `runbooks/Container-Scanning/container-scanning-and-hardening.md` — the
  scan/harden runbook (Grype, ClamAV, `usg`, `ubuntu-hardened` base).
- Internal `resources/Engineering-Practices/Containers.md` — mandatory container
  practices: no public-registry pulls in-boundary; `cflinuxfs` buildpack apps noted
  as outside the pipeline's current scope.
- `docs/adr/0001-consume-mitre-baseline-via-fork-depends.md` — related dependency /
  supply-chain decision for the baseline profile.
- `runner/certs/README.md` — provenance + rotation runbook for the public RDS CA
  bundle shared by both packaging paths.
