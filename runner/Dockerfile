# CINC Auditor runner for the Cloud.gov Oracle 19c STIG overlay (#7).
# Builds oraquery from source (no committed binary, #11), vendors the pinned
# InSpec dependency at build time (ADR-0001), and runs non-root.
# Local runs prove check logic only; live RDS proof remains aws-broker#558.

# Build context is the repo root (see runner/docker-compose.yml).
FROM golang:1.22-bookworm AS oraquery-build
WORKDIR /src
COPY runner/oraquery/go.mod runner/oraquery/go.sum ./
RUN go mod download
COPY runner/oraquery/ .
RUN CGO_ENABLED=0 go build -trimpath -o /oraquery .

FROM cincproject/auditor:7

USER root

# --- AWS GovCloud RDS CA bundle (#23) -------------------------------------
# Trust anchor for verified TLS (ORAQUERY_TLS=verify-ca) to a live brokered RDS.
# The bundle is a PUBLIC, non-secret artifact committed at runner/certs/ and
# copied in here; its integrity is checksum-verified so a tampered/truncated
# file fails the build closed. Full provenance, contents, and rotation runbook:
# see runner/certs/README.md (single source of truth).
COPY runner/certs/rds-govcloud-global-bundle.crt.bundle /opt/certs/rds-govcloud-global-bundle.pem
# Checksum literal is inlined in the RUN (not an ARG) so it can't be overridden
# via --build-arg to match a swapped file.
RUN set -eux; \
    echo "bae59f78f2e2ba789e734cdcac78c13a0f0e99aa3f7bd49f1f37477c815b9b33  /opt/certs/rds-govcloud-global-bundle.pem" | sha256sum -c -; \
    chmod 0644 /opt/certs/rds-govcloud-global-bundle.pem
# Default oraquery's trust anchor to the baked bundle; verify-ca uses it unless
# overridden. Local dev overrides ORAQUERY_TLS=disable (see run-validation.sh).
ENV ORAQUERY_CA_BUNDLE=/opt/certs/rds-govcloud-global-bundle.pem
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------

# Copy the overlay profile and vendor its pinned git dependency at build time.
COPY inspec.yml inspec.lock rds-inputs.yml /profile/
COPY controls /profile/controls
COPY libraries /profile/libraries
RUN cinc-auditor vendor /profile --overwrite

COPY --from=oraquery-build /oraquery /usr/local/bin/oraquery
RUN chmod 0755 /usr/local/bin/oraquery

COPY runner/run-validation.sh /usr/local/bin/run-validation.sh
RUN chmod 0755 /usr/local/bin/run-validation.sh

# Ad hoc query wrapper + the shared connection-discovery library it and
# run-validation.sh both source. The lib is resolved relative to the script via
# $(dirname "$0")/lib, so it must sit under /usr/local/bin/lib.
COPY runner/db-query.sh /usr/local/bin/db-query.sh
COPY runner/lib/db-connect.sh /usr/local/bin/lib/db-connect.sh
RUN chmod 0755 /usr/local/bin/db-query.sh \
    && chmod 0644 /usr/local/bin/lib/db-connect.sh

RUN useradd -u 10001 -m scanner \
    && chown -R scanner:scanner /profile \
    && mkdir -p /out && chown scanner:scanner /out
USER scanner

ENTRYPOINT ["/usr/local/bin/run-validation.sh"]
