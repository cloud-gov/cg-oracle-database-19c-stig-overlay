# Thin overlay on Oracle's OFFICIAL SQLcl image (OTN license) for **LOCAL 23ai
# testing ONLY** — one-off queries + running the hardening/sql scripts against the
# compose dev DB. For Cloud.gov, the in-boundary runner is the Java-buildpack app
# (runner/sqlcl-cf/, see docs/adr/0002-sqlcl-runner-docker-vs-java-buildpack.md);
# this image is NOT used in-boundary.
#
# It adds ONLY:
#   1) the shared connection-discovery library (lib/db-connect.sh) so this tool
#      reaches the DB exactly like the buildpack runner (env + VCAP_SERVICES),
#   2) the SQLcl connect wrapper (sqlcl-connect.sh) that builds the EZConnect/JDBC
#      string and picks a fail-closed TLS mode, and
#   3) a PKCS12 truststore built from the SAME checksum-verified public RDS CA PEM
#      oraquery uses (unused locally — the compose 23ai DB is plaintext loopback —
#      but kept so the overlay matches what sqlcl-connect.sh expects).
#
# We deliberately do NOT rebuild SQLcl or bundle a JRE — the base image provides
# both. Because SQLcl carries the Oracle OTN EULA AND this image is not built on the
# hardened base, it is BUILT LOCALLY and NEVER pushed to any registry — that keeps
# it clear of both the OTN redistribution restriction and the mandatory in-boundary
# container-scanning/hardening pipeline (internal ADR-0007). The Makefile has no push
# target for it.
#
# Build context is the repo root (see runner/docker-compose.yml), so paths below
# are repo-relative — matching runner/Dockerfile.
#
# NOTE: BASE_IMAGE is pinned to an exact digest (dependency policy forbids floating
# tags). Resolved from container-registry.oracle.com/database/sqlcl:latest
# (SQLcl 26.2.1.0) on 2026-08-17. To update: pull the tag, read the RepoDigest
#   docker inspect <img> --format '{{index .RepoDigests 0}}'
# and replace the digest below.
ARG BASE_IMAGE=container-registry.oracle.com/database/sqlcl@sha256:c039d51466cea7c76f1e3b3ae4b125e2a73381a884a548737cb65b26e6dd7db1
FROM ${BASE_IMAGE}

# The base image ships a JRE (keytool) and the `sql` launcher; we run everything
# as root only for the build steps, then hand execution back to the base image's
# default (non-root) user — we do not change it.
USER root

# --- AWS GovCloud RDS CA truststore (verify-ca / TCPS 2484) -----------------
# Same PUBLIC, non-secret bundle the oraquery runner bakes; integrity is
# checksum-verified so a tampered/truncated file fails the build closed. Provenance
# and rotation runbook: runner/certs/README.md (single source of truth).
COPY runner/certs/rds-govcloud-global-bundle.crt.bundle /opt/certs/rds-govcloud-global-bundle.pem
# Checksum literal inlined in the RUN (not an ARG) so it can't be overridden via
# --build-arg to match a swapped file.
RUN set -eux; \
    echo "bae59f78f2e2ba789e734cdcac78c13a0f0e99aa3f7bd49f1f37477c815b9b33  /opt/certs/rds-govcloud-global-bundle.pem" | sha256sum -c -; \
    chmod 0644 /opt/certs/rds-govcloud-global-bundle.pem

# Wrapper + shared connection library + truststore builder.
RUN mkdir -p /opt/sqlcl-run/lib
COPY runner/lib/db-connect.sh          /opt/sqlcl-run/lib/db-connect.sh
COPY runner/sqlcl/sqlcl-connect.sh     /opt/sqlcl-run/sqlcl-connect.sh
COPY runner/sqlcl/build-truststore.sh  /opt/sqlcl-run/build-truststore.sh

# Build the PKCS12 truststore at BUILD time (reproducible; no per-start work).
RUN set -eux; \
    chmod 0755 /opt/sqlcl-run/build-truststore.sh /opt/sqlcl-run/sqlcl-connect.sh; \
    chmod 0644 /opt/sqlcl-run/lib/db-connect.sh; \
    /opt/sqlcl-run/build-truststore.sh \
        /opt/certs/rds-govcloud-global-bundle.pem \
        /opt/sqlcl-run/rds-truststore.p12 \
        changeit; \
    chmod 0644 /opt/sqlcl-run/rds-truststore.p12

# The hardening SQL scripts are copied in so `-f /opt/hardening/<x>.sql` works
# without mounting anything (make sqlcl-run). They are plain SQL text (no secrets).
COPY hardening/sql /opt/hardening

# Run as the base image's non-root software owner (oracle, uid 54321) rather than
# root. (The stock image leaves USER unset = root; we drop privileges here.) The
# baked truststore/scripts are world-readable, so no ownership change is needed.
USER 54321

ENV RDS_TRUSTSTORE=/opt/sqlcl-run/rds-truststore.p12 \
    RDS_TRUSTSTORE_PASS=changeit

# Default to the connect wrapper; with no args it starts an interactive REPL, with
# `-f <file>` / `@<file>` it runs a script. Override the entrypoint for other uses.
ENTRYPOINT ["/opt/sqlcl-run/sqlcl-connect.sh"]
