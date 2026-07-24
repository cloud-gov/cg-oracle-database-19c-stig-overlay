# MITRE Oracle 19c STIG profile — validation results (overlay #6 / #7)

**Harness:** CINC Auditor 6.8.24 + **`oraquery`** (pure-Go go-ora wrapper, MIT) →
Oracle **23ai Free** (gvenzl). **Date:** 2026-07-24.

> ⚠️ **FIDELITY / NOT COMPLIANCE EVIDENCE.** Target is Oracle **23ai Free**, not
> 19c, not SE2, not RDS, against an **un-hardened** dev DB. This proves the check
> *logic executes and is coherent* and that no control silently passes. It does
> **not** establish STIG compliance — that requires the live GovCloud RDS proof
> (aws-broker#558). The 35 "fails" below are largely expected on an un-hardened
> dev DB, not broken checks.

## Fixes required just to make the upstream profile usable
1. **Would not load** — `SV-270580.rb` `%q(...)` delimiter collided with unbalanced
   parens in SQL examples → SyntaxError → *entire profile* failed to load.
   Fixed to `%q{...}`. (Upstream: mitre/oracle-database-19c-stig-baseline#1.)
2. **`inspec.yml` mislabeled 12c** → corrected name/title/summary to 19c.
3. **Only `sqlplus_bin` declared** → added `sqlcl_bin` input so the resource can
   take a non-sqlplus path.
4. **Client**: replaced sqlplus (Instant Client OTN license — not redistributable
   in a public image) / sqlcl (CSV output breaks the InSpec parser) with
   **`oraquery`**, a pure-Go go-ora wrapper that emits exactly the CSV the resource
   expects. License-clean (MIT), CGO-free, TCPS-capable.

## Final disposition (96 controls)

| Disposition | Count | Meaning |
|---|---:|---|
| PASS | 17 | check ran; DB satisfied it |
| REAL FAIL | 35 | check ran; genuine finding (expected vs. un-hardened 23ai) |
| SKIP (manual / N-A) | 42 | explicit manual-review or documented not-applicable-on-RDS |
| ERROR (upstream check) | 2 | SV-270505, SV-270556 — upstream queries hit ORA-00942 / ORA-41900 on 23ai (view/priv gap; fix during port) |
| **EMPTY / STUB** | **0** | **was 35 — every stub now dispositioned** |

**From 35 silently-passing stubs → 0.** Breakdown of the original 35:
- **12 automated checks** ported from MITRE's complete+executed 12c profile
  (SV-270504/510/511/513/519/523/526/550/553/561/587) + validated.
- **1 authored from DISA text** (SV-270497 `max_idle_time` — no 12c analogue).
- **17 explicit manual-review skips** (were silent stubs).
- **6 documented not_applicable_rds** (host/listener/filesystem — see control-layers.yml).

## Accuracy caveats (must be reviewed against DISA V1R5 before relying on them)
- **SV-270519** — 19c title references DB-structure-modify roles but the ported
  check follows 12c V-61591's direct-sys-priv query. Confirm intent vs. DISA text.
- **SV-270587** — implements the "password-verify function is set" baseline; the
  "not on a compromised-password list" nuance is NOT automatable and needs manual
  verification.
- **SV-270497** — authored from the check text (MAX_IDLE_TIME > 0 and ≥ documented
  expectation); confirm the org expectation via the `max_idle_time` input.
- **SV-270505 / SV-270556** — upstream checks error on 23ai (view/priv); re-verify
  on 19c/RDS and add the needed grant or view adjustment.

## Reproduce
```bash
cd validation && mkdir -p out
docker compose up -d oracle           # gvenzl 23ai
docker build -t cg-stig-runner:dev -f runner/Dockerfile .   # (add --build-arg CORP_CA=runner/corp-ca.pem behind a TLS-proxy)
docker run --rm --network <compose-net> \
  -e DB_USER=system -e DB_PASSWORD=... -e DB_HOST=oracle -e DB_SERVICE=FREEPDB1 -e DB_PORT=1521 \
  -v "$PWD/out:/out" cg-stig-runner:dev
```

## Next
- Re-run against a *hardened* instance, then a *live RDS SE2* instance
  (aws-broker#558) for real evidence (via TCPS 2484 — `oraquery` supports it).
- Fix SV-270505/556; confirm the accuracy caveats vs. DISA V1R5.
