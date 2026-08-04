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

FROM cincproject/auditor:6

USER root

# --- AWS GovCloud RDS root CA bundle (#23) --------------------------------
# The trust anchor for verified TLS (ORAQUERY_TLS=verify-ca) to a live brokered
# RDS-for-Oracle instance. It is a PUBLIC, non-secret root CA published by AWS
# only as PEM; the cloud.gov aws-rds binding does NOT carry it, so it must be
# baked into this image. cloud.gov RDS runs in AWS GovCloud (us-gov-west-1), so
# we use the GovCloud truststore bundle, not the commercial one.
#
# The bundle is COMMITTED to the repo (runner/certs/) rather than fetched at
# build time: it is a public artifact, and committing it makes the build fully
# reproducible + auditable (no network dependency, no floating URL, and it works
# behind a TLS-inspecting egress proxy). Its integrity is CHECKSUM-VERIFIED here
# so a tampered/truncated file fails the build closed.
#
# Provenance / rotation (see runner/certs/README.md):
#   source: https://truststore.pki.us-gov-west-1.rds.amazonaws.com/global/global-bundle.pem
#   AWS rotates RDS server certs automatically; the root bundle is long-lived.
#   To update: re-download, verify, replace the PEM + the pinned SHA-256 below.
ARG RDS_CA_BUNDLE_SHA256=bae59f78f2e2ba789e734cdcac78c13a0f0e99aa3f7bd49f1f37477c815b9b33
# Source file uses the .crt.bundle extension (a bundle of public CA certs); the
# pre-commit forbidden-files guard blocks committed *.pem (which usually carry
# private keys). It is copied to a .pem path inside the image for convention.
COPY runner/certs/rds-govcloud-global-bundle.crt.bundle /opt/certs/rds-govcloud-global-bundle.pem
RUN set -eux; \
    echo "${RDS_CA_BUNDLE_SHA256}  /opt/certs/rds-govcloud-global-bundle.pem" | sha256sum -c -; \
    chmod 0644 /opt/certs/rds-govcloud-global-bundle.pem
# Default oraquery's trust anchor to the baked bundle; verify-ca uses it unless
# overridden. Local dev overrides ORAQUERY_TLS=disable (see run-validation.sh).
ENV ORAQUERY_CA_BUNDLE=/opt/certs/rds-govcloud-global-bundle.pem
# --------------------------------------------------------------------------

# Copy the overlay profile and vendor its pinned git dependency at build time.
COPY inspec.yml inspec.lock /profile/
COPY controls /profile/controls
RUN cinc-auditor vendor /profile --overwrite

COPY --from=oraquery-build /oraquery /usr/local/bin/oraquery
RUN chmod 0755 /usr/local/bin/oraquery

COPY runner/run-validation.sh /usr/local/bin/run-validation.sh
RUN chmod 0755 /usr/local/bin/run-validation.sh

RUN useradd -u 10001 -m scanner \
    && chown -R scanner:scanner /profile \
    && mkdir -p /out && chown scanner:scanner /out
USER scanner

ENTRYPOINT ["/usr/local/bin/run-validation.sh"]
