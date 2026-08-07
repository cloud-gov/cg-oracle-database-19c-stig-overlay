# Makefile — one-command bootstrap/verify for the Cloud.gov Oracle 19c STIG overlay.
#
# Everything runs in Docker; the only host prerequisite is Docker (+ compose).
# No local Ruby, CINC Auditor, or Go install is required.
#
#   make verify   → prove the profile + runner build and load, WITHOUT a live DB
#   make run      → full end-to-end: stand up Oracle 23ai Free and exec the profile
#
# See runner/README.md for fidelity caveats (a local 23ai run is NOT compliance
# evidence).

# Pinned so `make` behaviour matches the runner image's CINC Auditor major
# (runner/Dockerfile uses cincproject/auditor:7). Override on the CLI, e.g.
#   make check AUDITOR_IMAGE=cincproject/auditor:6
AUDITOR_IMAGE ?= cincproject/auditor:7
RUNNER_IMAGE  ?= cg-cinc-audit-oracle-runner:local
CLOUDGOV_IMAGE ?= cloudgov/cg-cinc-audit-oracle-runner:amd64
CLOUDGOV_PLATFORM ?= linux/amd64
DOCKERHUB_IMAGE ?= $(CLOUDGOV_IMAGE)
CLOUDGOV_APP ?= cg-cinc-audit-oracle-runner
CF_IDLE_COMMAND ?= sleep infinity
CF_PUSH_FLAGS ?= --no-route -u process -k 2GB -c '$(CF_IDLE_COMMAND)'
COMPOSE_FILE  ?= runner/docker-compose.yml
# Local directory for saved JSON reports (mounted at the container's /out).
RESULTS_DIR ?= out
# Compose project name (see `name:` in the compose file); used to derive the
# network name the `retest` container joins to reach the running DB.
COMPOSE_PROJECT ?= cg-cinc-audit-oracle
COMPOSE_NETWORK ?= $(COMPOSE_PROJECT)_default
# Go toolchain image for oraquery unit tests (matches runner/Dockerfile builder).
GO_IMAGE      ?= golang:1.22-bookworm
# Mount the repo root into the auditor container as /share.
DOCKER_RUN    := docker run --rm -v "$(CURDIR)":/share -w /share \
                 --entrypoint cinc-auditor $(AUDITOR_IMAGE)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quickstart:  make verify   (no database needed)"
	@echo "             make run      (full end-to-end against Oracle 23ai Free)"

.PHONY: deps
deps: ## Check host prerequisites (Docker + compose)
	@command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found on PATH." >&2; exit 1; }
	@docker compose version >/dev/null 2>&1 || { echo "ERROR: 'docker compose' not available." >&2; exit 1; }
	@echo "OK: docker $$(docker --version | awk '{print $$3}' | tr -d ,) + compose present."

.PHONY: vendor
vendor: deps ## Resolve the profile's git dependency (pinned by inspec.lock)
	$(DOCKER_RUN) vendor /share --overwrite

.PHONY: check
check: deps ## Static profile validation (cinc-auditor check) — no DB needed
	$(DOCKER_RUN) check /share

.PHONY: build build-local
build: build-local ## Build the runner image for local testing

build-local: deps ## Build the runner image for local testing
	docker build -f runner/Dockerfile -t $(RUNNER_IMAGE) .

.PHONY: build-cloudgov
build-cloudgov: deps ## Build the runner image for Cloud.gov (linux/amd64) and load it locally
	docker buildx build --platform $(CLOUDGOV_PLATFORM) \
	  -f runner/Dockerfile \
	  -t $(CLOUDGOV_IMAGE) \
	  --load \
	  .

.PHONY: push-dockerhub
push-dockerhub: build-cloudgov ## Build and push the Cloud.gov linux/amd64 image to Docker Hub
	docker push $(DOCKERHUB_IMAGE)

.PHONY: push-cloudgov
push-cloudgov: push-dockerhub ## Push an idle Docker image app to Cloud.gov for cf ssh validation runs
	@command -v cf >/dev/null 2>&1 || { echo "ERROR: cf not found on PATH." >&2; exit 1; }
	cf push $(CLOUDGOV_APP) --docker-image $(DOCKERHUB_IMAGE) $(CF_PUSH_FLAGS)

.PHONY: test-go
test-go: deps ## Unit-test the oraquery client (go test, in a Go container — no host Go)
	docker run --rm -v "$(CURDIR)/runner/oraquery":/src -w /src $(GO_IMAGE) \
	  go test -v ./...

.PHONY: verify
verify: check test-go build ## One-command verify: profile loads + oraquery tests pass + runner image builds (no DB)
	@echo ""
	@echo "verify OK: profile is valid, oraquery unit tests pass, and the runner image builds."
	@echo "Next: 'make run' to execute the profile against a live Oracle 23ai Free DB."

.PHONY: run
run: deps ## Full end-to-end: start Oracle 23ai Free + exec the profile
	docker compose -f $(COMPOSE_FILE) up --build --abort-on-container-exit

# --- Fast local control iteration (no DB restart per change) ---------------
# Iterate on controls without stopping/starting the DB each change:
#   make db-up      # start Oracle 23ai Free once, leave it running
#   make retest     # edit controls/, re-run in seconds — repeat as needed
#   make db-down    # stop the DB when finished
# `retest` mounts the working tree READ-ONLY and execs it, so edits to controls/
# on disk are picked up immediately. The baseline `depends` is resolved from the
# committed inspec.lock (managed in-repo via `make vendor`); run-validation.sh
# directs CINC's dependency cache to a writable path in the container, so the
# read-only profile dir is never written to.
#
# retest/report-local do NOT rebuild the runner image (that is slow and, since the
# profile is mounted at runtime, unnecessary). They only ensure the image EXISTS,
# building it once on first use. After changing the Dockerfile/oraquery/harness,
# rebuild explicitly with `make build-local`.
#
# CONTROL(S): restrict a run to specific control IDs for the fastest iteration,
# skipping load+exec of the rest, e.g.:
#   make retest CONTROL=SV-270495
#   make retest CONTROLS="SV-270495 SV-270496"
# CONTROL is a convenience alias for a single id; CONTROLS takes a list.
CONTROL ?=
CONTROLS ?= $(CONTROL)

.PHONY: ensure-image
ensure-image: deps ## Build the runner image only if it is missing (no rebuild if present)
	@docker image inspect $(RUNNER_IMAGE) >/dev/null 2>&1 \
	  || { echo "ensure-image: $(RUNNER_IMAGE) not found — building once..."; \
	       docker build -f runner/Dockerfile -t $(RUNNER_IMAGE) .; }

.PHONY: db-up
db-up: deps ## Start Oracle 23ai Free (detached) and wait until healthy; leave it running
	docker compose -f $(COMPOSE_FILE) up -d --wait oracle
	@echo "db-up: Oracle 23ai Free is healthy. Iterate with 'make retest'; stop with 'make db-down'."

.PHONY: retest
retest: ensure-image ## Re-run the LOCAL profile (RO mount) against the running DB — fast iteration, no image rebuild
	@docker compose -f $(COMPOSE_FILE) ps --status running --services 2>/dev/null | grep -qx oracle \
	  || { echo "ERROR: Oracle DB is not running. Start it first with 'make db-up'." >&2; exit 1; }
	@echo "retest: executing local profile (controls/ mounted read-only) against the running DB"
	docker run --rm \
	  --network $(COMPOSE_NETWORK) \
	  -v "$(CURDIR)":/mnt/profile:ro \
	  -e DB_USER=system \
	  -e DB_PASSWORD=devpw_ChangeMe1 \
	  -e DB_HOST=oracle \
	  -e DB_SERVICE=FREEPDB1 \
	  -e DB_PORT=1521 \
	  -e PROFILE_SOURCE=/mnt/profile \
	  -e CONTROLS="$(CONTROLS)" \
	  $(RUNNER_IMAGE)

.PHONY: report-local
report-local: ensure-image ## Like retest, but --json: saves a timestamped JSON report to $(RESULTS_DIR)/ (no image rebuild)
	@docker compose -f $(COMPOSE_FILE) ps --status running --services 2>/dev/null | grep -qx oracle \
	  || { echo "ERROR: Oracle DB is not running. Start it first with 'make db-up'." >&2; exit 1; }
	@mkdir -p "$(RESULTS_DIR)"
	@echo "report-local: running --json; JSON report → $(RESULTS_DIR)/"
	@# Mount $(RESULTS_DIR) at the container's /out so the JSON report is written
	@# straight to the host — no copy step needed for local runs. Run as the host
	@# user (uid:gid) so the bind-mounted /out is writable and the resulting files
	@# are owned by the caller, not the image's scanner user (uid 10001). CINC exits
	@# 100/101 on failed/skipped controls; that is an expected finding, not a runner
	@# error, so tolerate it (the report file is still produced).
	docker run --rm \
	  --user "$$(id -u):$$(id -g)" \
	  --network $(COMPOSE_NETWORK) \
	  -v "$(CURDIR)":/mnt/profile:ro \
	  -v "$(CURDIR)/$(RESULTS_DIR)":/out \
	  -e HOME=/tmp \
	  -e DB_USER=system \
	  -e DB_PASSWORD=devpw_ChangeMe1 \
	  -e DB_HOST=oracle \
	  -e DB_SERVICE=FREEPDB1 \
	  -e DB_PORT=1521 \
	  -e PROFILE_SOURCE=/mnt/profile \
	  -e CONTROLS="$(CONTROLS)" \
	  $(RUNNER_IMAGE) --json \
	  || [ $$? -ge 100 ]
	@echo "report-local: saved JSON report(s) under $(RESULTS_DIR)/"

.PHONY: db-down
db-down: ## Stop and remove the iteration DB (and its volume)
	-docker compose -f $(COMPOSE_FILE) down --volumes --remove-orphans

.PHONY: clean
clean: ## Tear down compose + remove local results and built image
	-docker compose -f $(COMPOSE_FILE) down --volumes --remove-orphans
	-docker image rm $(RUNNER_IMAGE) 2>/dev/null || true
