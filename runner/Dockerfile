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
