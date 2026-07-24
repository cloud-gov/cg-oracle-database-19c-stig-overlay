# CINC Auditor + sqlcl STIG validation / Concourse runner image (#7)
#
# Purpose: execute the vendored MITRE Oracle 19c STIG InSpec profile against an
# Oracle DB, hostless, via oracledb_session over the network. Doubles as the
# Concourse runner image for the live-RDS scan (aws-broker#558).
#
# Engine: CINC Auditor (Apache-2.0 FOSS distribution of InSpec) — not Chef InSpec.
# SQL client: sqlcl (pure-Java, no Oracle Instant Client EULA). oracledb_session
#   is pointed at it via the `sqlcl_bin` input.
#
# NOTE (fidelity): local validation runs against Oracle 23ai Free (gvenzl) — NOT
# 19c/SE2/RDS. Results prove the check LOGIC runs; version/RDS-specific behavior
# is deferred to the live proof (aws-broker#558).
#
# Runs as non-root. Pin versions before shipping to a FedRAMP pipeline.

# =============================================================================
# STIG validation / Concourse runner image (#7)
#
# ┌── REAL (cloud.gov / Concourse) BUILD ──────────────────────────────────────┐
# │ FROM <cloud.gov custom PRE-HARDENED Ubuntu 22.04 base image>                │
# │ - layer CINC Auditor on top (or start from a hardened-base+auditor image)  │
# │ - build oraquery from the INTERNAL Go module mirror.                        │
# │ - no public internet, no CORP_CA, no Oracle client download needed.         │
# └────────────────────────────────────────────────────────────────────────────┘
#
# Oracle SQL client: a purpose-built pure-Go wrapper `oraquery` (go-ora, MIT,
# CGO_ENABLED=0) — NOT sqlplus (Oracle Instant Client OTN license forbids
# redistribution in a public image) and NOT sqlcl (its CSV output breaks the
# InSpec CSV parser). InSpec's oracledb_session is pointed at oraquery via
# sqlplus_bin/sqlcl_bin; oraquery emits exactly the clean CSV the parser expects.
#
# Engine: CINC Auditor (Apache-2.0 FOSS distribution of InSpec).
# =============================================================================

# --- stage 1: build the pure-Go Oracle query wrapper ---
FROM golang:1.22-bookworm AS oraquery-build
ARG CORP_CA=""
COPY ${CORP_CA:-oraquery/go.mod} /tmp/corp-ca.crt
RUN if grep -q "BEGIN CERTIFICATE" /tmp/corp-ca.crt 2>/dev/null; then \
      cp /tmp/corp-ca.crt /usr/local/share/ca-certificates/corp-ca.crt && update-ca-certificates; \
    fi || true
WORKDIR /src
COPY oraquery/ .
RUN CGO_ENABLED=0 go build -trimpath -o /oraquery .

# --- stage 2: the CINC Auditor runner ---
FROM cincproject/auditor:6

USER root

# --- vendored, pinned MITRE profile (committed into the repo) ---
COPY vendor/oracle-database-19c-stig-baseline /profile

# --- the pure-Go Oracle client wrapper (replaces sqlplus/sqlcl) ---
COPY --from=oraquery-build /oraquery /usr/local/bin/oraquery
RUN chmod 0755 /usr/local/bin/oraquery

# --- the run harness ---
COPY runner/run-validation.sh /usr/local/bin/run-validation.sh
RUN chmod 0755 /usr/local/bin/run-validation.sh

# non-root; ensure the scanner user can read the profile + write /out
RUN useradd -u 10001 -m scanner \
    && chown -R scanner:scanner /profile \
    && mkdir -p /out && chown scanner:scanner /out
USER scanner

ENTRYPOINT ["/usr/local/bin/run-validation.sh"]
