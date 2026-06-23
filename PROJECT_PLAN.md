---
title: "Project Plan"
description:
  "Starting point for a new federal coding project — fill this out and let the
  AI agent set up everything else"
status: canonical
tier: 3
load_priority: reference-only
audience: ["developers", "tech-leads", "managers"]
---

# Project Plan

## Project Identity

| Field                   | Value                                               |
| ----------------------- | --------------------------------------------------- |
| **Project Name**        | Oracle 19c STIG compliance validation for Cloud.gov |
| **Repository Name**     | oracle-database-19c-stig-baseline                   |
| **Organization/Agency** | Cloud.gov                                           |
| **Project Owner**       | Peter Burkholder                                    |
| **Start Date**          | 2026-06-01                                          |
| **Target Completion**   | 2026-08-01                                          |

## Business Objective

## Tech Stack

| Component         | Choice    | Rationale |
| ----------------- | --------- | --------- |
| **Language**      | InSpec    |
| **Cloud/Hosting** | Cloud.gov |

## Compliance Level

- [ ] **FIPS Low** — Public-facing informational content, no PII, no CUI
- [x] **FIPS Moderate** — Most federal systems: PII, financial data, internal
      tools
- [ ] **FIPS High** — National security systems, critical infrastructure

## Data Classification

<!-- Check all that apply: -->

- [x] Public data only
- [ ] PII (Personally Identifiable Information)
- [ ] CUI (Controlled Unclassified Information)
- [ ] PHI (Protected Health Information)
- [ ] Financial data (FTI, payment info)
- [ ] Authentication credentials/secrets

## Key Requirements

<!-- List the 3-5 most important functional requirements. These help the agent understand what to build. -->

1. Be able to run the STIG Oracle 19c checks
2. Reuse the existing 12c checks (in 12c_to_19c) when possible
3. Update the NIST controls when not currently available

## Constraints

<!-- List any hard constraints the project must work within. -->

- [ ] Must use FedRAMP-authorized services only
- [ ] Must support Section 508 accessibility
- [ ] Must integrate with existing system: <!-- name -->
- [ ] Must support offline/air-gapped operation
- [ ] Other: <!-- describe -->

## Agent Environment

<!-- Where will the AI coding agent run? Check all that apply: -->

- [ ] **Local machine** — developer's workstation with CLI access
- [ ] **GitHub Codespace** — cloud-hosted dev environment
- [x] **Sandboxed container** — isolated Docker/Podman environment
- [ ] **CI/CD only** — agent runs in GitHub Actions, no local access

<!-- What services does the agent need access to? Check all that apply: -->

- [ ] **GitHub** — push code, create PRs, manage issues
- [ ] **cloud.gov** — deploy applications
- [ ] **workshop.cloud.gov (GitLab)** — alternative code hosting
- [ ] **npm/PyPI** — publish packages
- [ ] **Container registry** — push images

<!-- The `agent-permissions` skill will configure minimal-scope credentials for each checked service. -->

## Implementation Approach

The main agent job here is update a number of InSpec controls developed for
Oracle 12c, STIG version 1, to the needed controls for Oracle 19c, STIG
version 1.

There are far more 12c controls than 19c controls, so we are going to iterate
over the 19c controls, and for each one, convert it to InSpec format, and then
use the control check logic from the closest applicable 12c control.

## What Happens Next

After you fill out this template and place it in your repository:

1. **The AI agent reads this file** and understands your project
2. **It runs the project-bootstrap skill** which:
   - Creates the directory structure appropriate for your stack
   - Generates AGENTS.md (behavioral contract for AI agents)
   - Copies CODING_PRACTICES.md (secure coding standards)
   - Creates ADR-001 from your implementation approach
   - Generates a risk assessment from your compliance level + data
     classification
   - Sets up CI/CD workflows for your stack
   - Creates SECURITY.md, CONTRIBUTING.md, LICENSE
3. **You review the generated files** and adjust as needed
4. **Start building** — the agent follows the standards automatically

The entire setup takes about 5 minutes of human input and 2 minutes of agent
work.
