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
RUNNER_IMAGE  ?= cg-cinc-auditor:local
# SQLcl image — LOCAL 23ai testing ONLY (one-off queries + running hardening/sql
# scripts against the compose dev DB). Thin overlay on Oracle's official OTN image;
# SQLCL_BASE_IMAGE is pinned by digest (dependency policy forbids floating tags) —
# SQLcl 26.2.1.0, resolved 2026-08-17. To update: pull the tag and read
# `docker inspect <img> --format '{{index .RepoDigests 0}}'`.
#
# NOT for Cloud.gov: the in-boundary SQLcl runner uses the Java-buildpack app
# (runner/sqlcl-cf/). This image is built locally and NEVER pushed to a registry —
# that keeps it clear of both the OTN redistribution restriction and the mandatory
# in-boundary container-scanning/hardening pipeline (internal ADR-0007).
SQLCL_IMAGE       ?= cg-sqlcl-oracle:local
SQLCL_BASE_IMAGE  ?= container-registry.oracle.com/database/sqlcl@sha256:c039d51466cea7c76f1e3b3ae4b125e2a73381a884a548737cb65b26e6dd7db1
CLOUDGOV_IMAGE ?= cloudgov/cg-cinc-auditor:amd64
CLOUDGOV_PLATFORM ?= linux/amd64
DOCKERHUB_IMAGE ?= $(CLOUDGOV_IMAGE)
CLOUDGOV_APP ?= cg-cinc-auditor
# ECR image for the in-boundary Cloud.gov push (pulled directly from AWS ECR, no
# local build). To (re)build + publish the image to ECR, that happens out of band
# in the AWS pipeline — push-cloudgov only PULLS it. AWS_ACCT is NOT defaulted
# here: it is sourced from the environment (e.g. `source .env`) and the
# push-cloudgov recipe fails closed if it is unset.
AWS_REGION ?= us-gov-west-1
ECR_IMAGE ?= $(AWS_ACCT).dkr.ecr.$(AWS_REGION).amazonaws.com/cg-cinc-auditor:latest
# CF service instance (brokered aws-rds Oracle) the runner app binds to so its
# VCAP_SERVICES carries the ORCL coordinates db-connect.sh reads at runtime.
DB_SERVICE_INSTANCE ?= test-oracle-9-23
CF_IDLE_COMMAND ?= sleep infinity
CF_PUSH_FLAGS ?= --no-route -u process -k 2GB -c '$(CF_IDLE_COMMAND)'
# App instance targeted for cf ssh; both the run and the fetch must hit the same
# instance since the report file is instance-local.
CF_APP_INSTANCE ?= 0
COMPOSE_FILE  ?= runner/docker-compose.yml
# Local directory for saved JSON reports (mounted at the container's /out).
RESULTS_DIR ?= out
# Compose project name (see `name:` in the compose file); used to derive the
# network name the `retest` container joins to reach the running DB.
COMPOSE_PROJECT ?= cg-cinc-auditor
COMPOSE_NETWORK ?= $(COMPOSE_PROJECT)_default
# --- Local dev DB connection (matches runner/docker-compose.yml) ------------
# NOT a secret: a well-known password for a loopback-only (127.0.0.1) throwaway
# 23ai DB. Defined once here and reused by retest/report-local so it can't drift.
# Override on the CLI to point those targets at a different local DB.
LOCAL_DB_USER     ?= system
LOCAL_DB_PASSWORD ?= devpw_ChangeMe1
LOCAL_DB_HOST     ?= oracle
LOCAL_DB_SERVICE  ?= FREEPDB1
LOCAL_DB_PORT     ?= 1521
LOCAL_DB_ENV := \
  -e DB_USER=$(LOCAL_DB_USER) \
  -e DB_PASSWORD=$(LOCAL_DB_PASSWORD) \
  -e DB_HOST=$(LOCAL_DB_HOST) \
  -e DB_SERVICE=$(LOCAL_DB_SERVICE) \
  -e DB_PORT=$(LOCAL_DB_PORT)
# Go toolchain image for oraquery unit tests (matches runner/Dockerfile builder).
GO_IMAGE      ?= golang:1.22-bookworm
# Bats image for the pure-shell db-connect helper tests (no Ruby/jq/DB needed).
BATS_IMAGE    ?= bats/bats:1.11.0
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

# --- SQLcl image — LOCAL 23ai testing ONLY --------------------------------
# A full SQL*Plus/SQLcl interpreter (unlike the pure-Go oraquery wrapper) for one-off
# queries + running the hardening/sql/*.sql scripts against the compose dev DB. Thin
# overlay on Oracle's official OTN SQLcl image, BUILT LOCALLY and NEVER pushed. For
# Cloud.gov use the Java-buildpack app instead (make push-sqlcl-cf).
.PHONY: build-sqlcl
build-sqlcl: deps ## Build the SQLcl image for LOCAL 23ai testing (thin overlay on the official OTN image)
	docker build -f runner/sqlcl/Dockerfile \
	  --build-arg BASE_IMAGE=$(SQLCL_BASE_IMAGE) \
	  -t $(SQLCL_IMAGE) .

.PHONY: sqlcl-repl
sqlcl-repl: build-sqlcl ## Interactive SQLcl REPL against the running local 23ai DB (needs 'make db-up')
	@docker compose -f $(COMPOSE_FILE) ps --status running --services 2>/dev/null | grep -qx oracle \
	  || { echo "ERROR: Oracle DB is not running. Start it first with 'make db-up'." >&2; exit 1; }
	docker run --rm -it \
	  --network $(COMPOSE_NETWORK) \
	  $(LOCAL_DB_ENV) \
	  -e ORAQUERY_TLS=disable \
	  $(SQLCL_IMAGE)

# Run one hardening/assessment SQL script against the running local 23ai DB.
# The scripts are baked into the image at /opt/hardening; pick one with SQL=<name>.
#   make sqlcl-run SQL=00_connectivity_check.sql
SQL ?= 00_connectivity_check.sql
.PHONY: sqlcl-run
sqlcl-run: build-sqlcl ## Run a hardening/sql script (SQL=<file>) against the running local 23ai DB
	@docker compose -f $(COMPOSE_FILE) ps --status running --services 2>/dev/null | grep -qx oracle \
	  || { echo "ERROR: Oracle DB is not running. Start it first with 'make db-up'." >&2; exit 1; }
	docker run --rm \
	  --network $(COMPOSE_NETWORK) \
	  $(LOCAL_DB_ENV) \
	  -e ORAQUERY_TLS=disable \
	  $(SQLCL_IMAGE) -f /opt/hardening/$(SQL)

# --- SQLcl via the Java buildpack (Cloud.gov — the ONLY supported in-boundary path) --
# For Cloud.gov we cf push the pure-Java SQLcl through the Java buildpack:
# no Docker image, no registry, no registry creds, no cross-arch build, and outside
# the mandatory in-boundary container-scanning pipeline (internal ADR-0007). SQLcl
# is downloaded directly from Oracle and vendored into the app before each push.
SQLCL_CF_DIR ?= runner/sqlcl-cf
SQLCL_CF_APP ?= cg-sqlcl-oracle-cf
SQLCL_CF_VERSION := 26.3.0.260.1620
SQLCL_CF_ARCHIVE := sqlcl-$(SQLCL_CF_VERSION).zip
SQLCL_CF_URL := https://download.oracle.com/otn_software/java/sqldeveloper/$(SQLCL_CF_ARCHIVE)
SQLCL_CF_MD5 := 52fb8905e90a99caf23ac022b609e3f8
SQLCL_CF_SHA1 := c858adea26aca18496a8b638b953285839fecbce
# Override only for offline verification, e.g. SQLCL_CF_ARCHIVE_PATH=$(CURDIR)/$(SQLCL_CF_ARCHIVE).
SQLCL_CF_ARCHIVE_PATH ?=

.PHONY: vendor-sqlcl-cf
vendor-sqlcl-cf: ## Download, verify, and extract the pinned SQLcl distribution
	@command -v unzip >/dev/null 2>&1 || { echo "ERROR: unzip not found on PATH." >&2; exit 1; }
	@command -v md5sum >/dev/null 2>&1 || { echo "ERROR: md5sum not found on PATH." >&2; exit 1; }
	@command -v sha1sum >/dev/null 2>&1 || { echo "ERROR: sha1sum not found on PATH." >&2; exit 1; }
	@set -eu; \
	  tmp="$$(mktemp -d)"; \
	  trap 'rm -rf "$$tmp"' EXIT HUP INT TERM; \
	  archive="$$tmp/$(SQLCL_CF_ARCHIVE)"; \
	  if [ -n "$(SQLCL_CF_ARCHIVE_PATH)" ]; then \
	    [ -f "$(SQLCL_CF_ARCHIVE_PATH)" ] \
	      || { echo "ERROR: SQLCL_CF_ARCHIVE_PATH is not a file: $(SQLCL_CF_ARCHIVE_PATH)" >&2; exit 1; }; \
	    cp "$(SQLCL_CF_ARCHIVE_PATH)" "$$archive"; \
	  else \
	    command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found on PATH." >&2; exit 1; }; \
	    echo "vendor-sqlcl-cf: downloading $(SQLCL_CF_URL)"; \
	    curl --fail --location --proto '=https' --tlsv1.2 --output "$$archive" "$(SQLCL_CF_URL)"; \
	  fi; \
	  printf '%s  %s\n' '$(SQLCL_CF_MD5)' "$$archive" | md5sum --check --status - \
	    || { echo "ERROR: SQLcl archive MD5 verification failed." >&2; exit 1; }; \
	  printf '%s  %s\n' '$(SQLCL_CF_SHA1)' "$$archive" | sha1sum --check --status - \
	    || { echo "ERROR: SQLcl archive SHA1 verification failed." >&2; exit 1; }; \
	  unzip -q "$$archive" -d "$$tmp/extracted"; \
	  [ -x "$$tmp/extracted/sqlcl/bin/sql" ] \
	    || { echo "ERROR: verified SQLcl archive lacks executable sqlcl/bin/sql." >&2; exit 1; }; \
	  grep -qx 'RELEASE=$(SQLCL_CF_VERSION)' "$$tmp/extracted/sqlcl/bin/version.txt" \
	    || { echo "ERROR: SQLcl archive version does not match $(SQLCL_CF_VERSION)." >&2; exit 1; }; \
	  rm -rf "$(SQLCL_CF_DIR)/vendor/sqlcl.new"; \
	  mv "$$tmp/extracted/sqlcl" "$(SQLCL_CF_DIR)/vendor/sqlcl.new"; \
	  rm -rf "$(SQLCL_CF_DIR)/vendor/sqlcl"; \
	  mv "$(SQLCL_CF_DIR)/vendor/sqlcl.new" "$(SQLCL_CF_DIR)/vendor/sqlcl"; \
	  echo "vendor-sqlcl-cf: verified and installed SQLcl $(SQLCL_CF_VERSION)."

.PHONY: stage-sqlcl-cf
stage-sqlcl-cf: ## Copy the single-source files into runner/sqlcl-cf/ (no drift) before cf push
	@# These staged copies are git-ignored; the sources under runner/lib, runner/sqlcl,
	@# hardening/sql, and runner/certs stay authoritative.
	@mkdir -p "$(SQLCL_CF_DIR)/lib" "$(SQLCL_CF_DIR)/hardening" "$(SQLCL_CF_DIR)/certs"
	cp runner/lib/db-connect.sh          "$(SQLCL_CF_DIR)/lib/db-connect.sh"
	cp runner/sqlcl/sqlcl-connect.sh     "$(SQLCL_CF_DIR)/sqlcl-connect.sh"
	cp -R hardening/sql/.                 "$(SQLCL_CF_DIR)/hardening/"
	cp runner/certs/rds-govcloud-global-bundle.crt.bundle \
	   "$(SQLCL_CF_DIR)/certs/rds-govcloud-global-bundle.pem"
	@echo "stage-sqlcl-cf: staged shared files into $(SQLCL_CF_DIR)/ (git-ignored copies)."

.PHONY: push-sqlcl-cf
push-sqlcl-cf: vendor-sqlcl-cf stage-sqlcl-cf ## Download verified SQLcl and deploy it via the Java buildpack
	@command -v cf >/dev/null 2>&1 || { echo "ERROR: cf not found on PATH." >&2; exit 1; }
	@set -a; [ ! -f .env ] || . ./.env; set +a; \
	  : "$${CF_API:?ERROR: CF_API is not set. Add it to .env or export it.}"; \
	  : "$${CF_DEPLOYER_USERNAME:?ERROR: CF_DEPLOYER_USERNAME is not set. Add it to .env or export it.}"; \
	  : "$${CF_DEPLOYER_PASSWORD:?ERROR: CF_DEPLOYER_PASSWORD is not set. Add it to .env or export it.}"; \
	  cf api "$$CF_API"; \
	  cf auth "$$CF_DEPLOYER_USERNAME" "$$CF_DEPLOYER_PASSWORD"; \
	  if [ -n "$${CF_ORG:-}" ] || [ -n "$${CF_SPACE:-}" ]; then \
	    [ -n "$${CF_ORG:-}" ] && [ -n "$${CF_SPACE:-}" ] \
	      || { echo "ERROR: set both CF_ORG and CF_SPACE, or neither." >&2; exit 1; }; \
	    cf target -o "$$CF_ORG" -s "$$CF_SPACE"; \
	  fi; \
	  cf target | grep -Eq '^org:[[:space:]]+[^[:space:]]' \
	    || { echo "ERROR: no Cloud Foundry org targeted; set CF_ORG and CF_SPACE in .env." >&2; exit 1; }; \
	  cf target | grep -Eq '^space:[[:space:]]+[^[:space:]]' \
	    || { echo "ERROR: no Cloud Foundry space targeted; set CF_ORG and CF_SPACE in .env." >&2; exit 1; }; \
	  cf push -f "$(SQLCL_CF_DIR)/manifest.yml" -p "$(SQLCL_CF_DIR)"

.PHONY: build-cloudgov
build-cloudgov: deps tests ## Build the runner image for Cloud.gov (linux/amd64) and load it locally
	docker buildx build --platform $(CLOUDGOV_PLATFORM) \
	  -f runner/Dockerfile \
	  -t $(CLOUDGOV_IMAGE) \
	  --load \
	  .

.PHONY: push-dockerhub
push-dockerhub: build-cloudgov ## Build and push the Cloud.gov linux/amd64 image to Docker Hub
	docker push $(DOCKERHUB_IMAGE)

.PHONY: push-cloudgov
push-cloudgov: ## Pull the ECR image to Cloud.gov, bind the Oracle service, and start the runner app
	@command -v cf >/dev/null 2>&1 || { echo "ERROR: cf not found on PATH." >&2; exit 1; }
	@[ -n "$(AWS_ACCT)" ] || { echo "ERROR: AWS_ACCT not set (ECR account id). Export it or 'source .env'." >&2; exit 1; }
	@# Secrets stay OUT of this Makefile (and out of git). Supply them in the
	@# environment — e.g. `source .env` first (.env is git-ignored). cf reads
	@# CF_DOCKER_PASSWORD from the env, so the ECR pull secret never lands on the
	@# command line or in `ps` output. Fail closed if either is missing.
	@[ -n "$$DOCKER_USER" ] || { echo "ERROR: DOCKER_USER not set (ECR access key id). Export it or 'source .env'." >&2; exit 1; }
	@[ -n "$$CF_DOCKER_PASSWORD" ] || { echo "ERROR: CF_DOCKER_PASSWORD not set (ECR pull secret). Export it or 'source .env'." >&2; exit 1; }
	cf push $(CLOUDGOV_APP) --docker-image $(ECR_IMAGE) --docker-username "$$DOCKER_USER" $(CF_PUSH_FLAGS)
	cf bind-service $(CLOUDGOV_APP) $(DB_SERVICE_INSTANCE)
	cf start $(CLOUDGOV_APP)

.PHONY: report-cloudgov
report-cloudgov: ## Run validation --json on Cloud.gov (cf ssh) and copy the JSON report into $(RESULTS_DIR)/
	@command -v cf >/dev/null 2>&1 || { echo "ERROR: cf not found on PATH." >&2; exit 1; }
	@mkdir -p "$(RESULTS_DIR)"
	@# The runner writes /out/validation-<label>-<ts>.json in the container and
	@# emits a stable `JSON_REPORT_PATH=<path>` marker on stderr (a CONTRACT with
	@# run-validation.sh — keep the two in sync); parse that to fetch the exact
	@# file with a second cf ssh. Pin the instance so both calls hit the same one;
	@# tolerate CINC 100/101 (findings, not runner errors).
	@set -e; \
	  log="$$(mktemp)"; \
	  cf ssh $(CLOUDGOV_APP) -i $(CF_APP_INSTANCE) \
	    -c "/usr/local/bin/run-validation.sh --json" 2> "$$log" || true; \
	  cat "$$log" >&2; \
	  remote="$$(sed -n 's/^JSON_REPORT_PATH=//p' "$$log" | tail -n1)"; \
	  rm -f "$$log"; \
	  [ -n "$$remote" ] || { echo "ERROR: could not determine remote JSON path." >&2; exit 1; }; \
	  local="$(RESULTS_DIR)/$$(basename "$$remote")"; \
	  echo "report-cloudgov: fetching $$remote → $$local"; \
	  cf ssh $(CLOUDGOV_APP) -i $(CF_APP_INSTANCE) -c "cat '$$remote'" > "$$local"; \
	  echo "report-cloudgov: saved $$local"; \
	  remote_meta="$${remote%.json}.meta.json"; \
	  local_meta="$${local%.json}.meta.json"; \
	  echo "report-cloudgov: fetching $$remote_meta → $$local_meta"; \
	  if cf ssh $(CLOUDGOV_APP) -i $(CF_APP_INSTANCE) -c "cat '$$remote_meta'" > "$$local_meta" 2>/dev/null && [ -s "$$local_meta" ]; then \
	    echo "report-cloudgov: saved $$local_meta"; \
	  else \
	    rm -f "$$local_meta"; \
	    echo "report-cloudgov: WARNING: no metadata sidecar found at $$remote_meta" >&2; \
	  fi

.PHONY: test-go
test-go: deps ## Unit-test the oraquery client (go test, in a Go container — no host Go)
	docker run --rm -v "$(CURDIR)/runner/oraquery":/src -w /src $(GO_IMAGE) \
	  go test -v ./...

.PHONY: test-ruby
test-ruby: deps ## Unit-test the oracledb_session CSV stopgap (rspec, in the CINC image — no DB)
	@# Run against the SAME CINC major the runner ships (AUDITOR_IMAGE) so the
	@# spec exercises the resource that will actually be vendored. The image's
	@# embedded Ruby has inspec-core, hashie, csv, and rspec.
	docker run --rm -v "$(CURDIR)":/share -w /share \
	  --entrypoint rspec $(AUDITOR_IMAGE) spec/ --format doc

.PHONY: test-bats
test-bats: deps ## Unit-test the db-connect.sh pure-shell helpers (bats — no Ruby/jq/DB)
	@# Exercises the JSON escaper that guards the .meta.json sidecar and the report
	@# label/host helpers. Bash + sed only, so it runs in the stock bats image.
	docker run --rm -v "$(CURDIR)/runner/lib":/code -w /code $(BATS_IMAGE) db-connect.bats

.PHONY: test-vcap
test-vcap: deps ## Regression-test the VCAP ORCL binding selection (issue #21; Ruby + jq fallback)
	@# The selection contract in _dbc_parse_vcap needs a real interpreter. Run the
	@# suite in the AUDITOR_IMAGE for the Ruby path, then force the jq fallback when
	@# host jq is available (the Java-buildpack Cloud.gov path has jq but no Ruby).
	@tmp="$$(mktemp -d)"; \
	cid="$$(docker create $(BATS_IMAGE))"; \
	docker cp "$$cid":/opt/bats "$$tmp/bats" >/dev/null; \
	docker rm "$$cid" >/dev/null; \
	status=0; \
	docker run --rm \
	  -v "$$tmp/bats":/opt/bats:ro \
	  -v "$(CURDIR)/runner/lib":/code:ro \
	  -w /code --entrypoint bash $(AUDITOR_IMAGE) \
	  -c 'export PATH="/opt/cinc-auditor/embedded/bin:$$PATH"; /opt/bats/bin/bats vcap-select.bats' \
	  || status=$$?; \
	if [ "$$status" -eq 0 ]; then \
	  if command -v jq >/dev/null 2>&1; then \
	    PATH="$$tmp/bats/bin:$$PATH" VCAP_SELECT_FORCE_JQ=1 bats runner/lib/vcap-select.bats || status=$$?; \
	  else \
	    echo "test-vcap: WARNING: jq not found on host; skipping forced jq fallback coverage" >&2; \
	  fi; \
	fi; \
	rm -rf "$$tmp"; \
	exit $$status

.PHONY: tests
tests: check test-go test-ruby test-bats test-vcap ## Run all no-DB checks: profile validity + oraquery + parser unit tests

.PHONY: verify
verify: tests build ## One-command verify: profile loads + unit tests pass + runner image builds (no DB)
	@echo ""
	@echo "verify OK: profile is valid, oraquery + parser unit tests pass, and the runner image builds."
	@echo "Next: 'make run' to execute the profile against a live Oracle 23ai Free DB."

.PHONY: run
run: deps ## Full end-to-end: start Oracle 23ai Free + exec the profile
	docker compose -f $(COMPOSE_FILE) up --build --abort-on-container-exit

# --- Fast local control iteration (no DB restart per change) ---------------
# Keep the DB up (db-up) and re-run against it (retest); stop with db-down.
# retest mounts the working tree read-only, so control edits need no image
# rebuild — ensure-image builds once if missing (rebuild manually with
# build-local after runner changes). Narrow a run with CONTROL/CONTROLS:
#   make retest CONTROL=SV-270495
#   make retest CONTROLS="SV-270495 SV-270496"
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
	  $(LOCAL_DB_ENV) \
	  -e PROFILE_SOURCE=/mnt/profile \
	  -e CONTROLS="$(CONTROLS)" \
	  $(RUNNER_IMAGE)

.PHONY: report-local
report-local: ensure-image ## Like retest, but --json: saves a timestamped JSON report to $(RESULTS_DIR)/ (no image rebuild)
	@docker compose -f $(COMPOSE_FILE) ps --status running --services 2>/dev/null | grep -qx oracle \
	  || { echo "ERROR: Oracle DB is not running. Start it first with 'make db-up'." >&2; exit 1; }
	@mkdir -p "$(RESULTS_DIR)"
	@echo "report-local: running --json; JSON report → $(RESULTS_DIR)/"
	@# Run as the host uid:gid (HOME=/tmp) so the bind-mounted /out is writable and
	@# reports are caller-owned. Tolerate CINC 100/101 (findings, not runner errors).
	docker run --rm \
	  --user "$$(id -u):$$(id -g)" \
	  --network $(COMPOSE_NETWORK) \
	  -v "$(CURDIR)":/mnt/profile:ro \
	  -v "$(CURDIR)/$(RESULTS_DIR)":/out \
	  -e HOME=/tmp \
	  $(LOCAL_DB_ENV) \
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
	-docker image rm $(SQLCL_IMAGE) 2>/dev/null || true
