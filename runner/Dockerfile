# CINC Auditor + oraquery STIG validation / Concourse runner image (#7)
#
# Purpose: execute the Cloud.gov Oracle 19c STIG overlay profile against an Oracle
# DB, hostless, via oracledb_session over the network. Doubles as the Concourse
# runner image for the live-RDS scan (aws-broker#558).
#
# Engine: CINC Auditor (Apache-2.0 FOSS distribution of InSpec) — not Chef InSpec
#   (commercial-license entanglement in a public FedRAMP image).
# SQL client: a purpose-built pure-Go wrapper `oraquery` (go-ora, MIT,
#   CGO_ENABLED=0) — NOT sqlplus (Oracle Instant Client OTN license forbids
#   redistribution in a public image) and NOT sqlcl (its CSV output breaks the
#   InSpec CSV parser). oracledb_session is pointed at oraquery via sqlplus_bin.
#
# oraquery is BUILT FROM SOURCE in this image (stage 1); no prebuilt binary is
# committed to the repository (resolves #11 / OpenSSF allstar binary-artifacts).
#
# Profile dependency: the overlay consumes the MITRE baseline via git `depends` +
# committed inspec.lock (ADR-0001) and vendors it at build time with
# `cinc-auditor vendor`. No committed vendor/ tree.
#
# NOTE (fidelity): local validation runs against Oracle 23ai Free (gvenzl) — NOT
# 19c/SE2/RDS. Results prove the check LOGIC runs; version/RDS-specific behavior
# is deferred to the live proof (aws-broker#558).
#
# Runs as non-root. Pin base + tool versions before shipping to a FedRAMP pipeline.

# --- stage 1: build the pure-Go Oracle query wrapper from source ---
# Build context is the REPOSITORY ROOT (see runner/docker-compose.yml), so
# all COPY sources are repo-root-relative.
FROM golang:1.22-bookworm AS oraquery-build
WORKDIR /src
# Only the module files first, for layer-cached dependency download.
COPY runner/oraquery/go.mod runner/oraquery/go.sum ./
RUN go mod download
COPY runner/oraquery/ .
RUN CGO_ENABLED=0 go build -trimpath -o /oraquery .

# --- stage 2: the CINC Auditor runner ---
FROM cincproject/auditor:6

USER root

# --- the overlay profile (SV-270495 MVP; depends on the cloud-gov fork) ---
# Copy the overlay profile source and vendor its git dependency at build time
# (ADR-0001: depends + inspec.lock, no committed vendor/). Requires network to
# the fork at build time; in the cloud.gov/Concourse build this is the internal
# mirror. The committed inspec.lock pins the exact fork ref for reproducibility.
COPY inspec.yml inspec.lock /profile/
COPY controls /profile/controls
RUN cinc-auditor vendor /profile --overwrite

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
