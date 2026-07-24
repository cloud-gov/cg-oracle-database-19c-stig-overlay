# STIG profile validation harness (#7)

Executes the vendored MITRE Oracle 19c STIG InSpec profile against an Oracle
database using **CINC Auditor** (Apache-2.0 FOSS distribution of InSpec) + **sqlcl**
(pure-Java, no Oracle Instant Client), and reports **pass/fail/skip/error per
control**. This is how we get the *authoritative* implemented-vs-stub count for
[#6](https://github.com/cloud-gov/cg-oracle-database-19c-stig-overlay/issues/6) —
static analysis of the profile proved unreliable, so we run it.

The same runner image is intended to double as the **Concourse InSpec runner** for
the live-RDS scan ([aws-broker#558](https://github.com/cloud-gov/aws-broker/issues/558)).

## ⚠️ Fidelity — read before trusting any result

| Layer | What it proves |
|-------|----------------|
| **This harness** (Oracle **23ai Free**, gvenzl) | The check LOGIC executes and is coherent; which controls are real vs. empty stubs; which error. |
| **NOT proven here** | 19c-specific, SE2-specific, or RDS-specific behavior. |
| **Live RDS proof** (aws-broker#558) | The only source of actual compliance evidence. |

Local runs target **Oracle 23ai Free** because there is no exact-19c gvenzl image
and the Oracle EE image was dropped (aws-broker#545). Some controls will behave
differently on 23ai than on 19c/SE2 — those are tagged
`local-validation-inconclusive → defer to live RDS`, never silently passed.

**Nothing this harness produces is compliance evidence.**

## Run

```bash
cd validation
mkdir -p out
docker compose up --build --abort-on-container-exit
# results in validation/out/results.json + a per-control summary in the runner log
```

## What's here

| Path | Purpose |
|------|---------|
| `runner/Dockerfile` | CINC Auditor + sqlcl + the vendored profile; runs non-root |
| `runner/run-validation.sh` | Runs the profile, emits per-control status + summary |
| `docker-compose.yml` | gvenzl/oracle-free (23ai) + the runner |
| `vendor/oracle-database-19c-stig-baseline/` | Pinned MITRE profile (Apache-2.0; see its LICENSE/NOTICE). `inspec.yml` name corrected 12c→19c per #6. |

## Vendoring / supply chain

The MITRE profile is **vendored (committed), not fetched at run time**, for
air-gapped/FedRAMP reproducibility and supply-chain integrity. Record the upstream
commit SHA + SHA256 when updating. Upstream: <https://github.com/mitre/oracle-database-19c-stig-baseline>
(Apache-2.0; DISA STIG content is public-domain US-Gov work).

## Credentials

Injected at runtime via env (`DB_USER`/`DB_PASSWORD`/`DB_HOST`/`DB_SERVICE`/`DB_PORT`),
never baked into the image. For the live-RDS Concourse run, use the master cred from
the secret store and TCPS port 2484 with enforced cert validation.
