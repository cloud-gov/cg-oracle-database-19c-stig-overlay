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
# Local directory for retrieved JSON reports (mirrors the container's /out).
RESULTS_DIR ?= out
# App instance to target for validation over SSH. Both cf ssh calls (run, then
# fetch) MUST hit the same instance, so this is pinned rather than left to CF.
CF_APP_INSTANCE ?= 0
COMPOSE_FILE  ?= runner/docker-compose.yml
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

.PHONY: report-cloudgov
report-cloudgov: ## Run validation --json on Cloud.gov and save the JSON locally under $(RESULTS_DIR)/ with the same filename
	@command -v cf >/dev/null 2>&1 || { echo "ERROR: cf not found on PATH." >&2; exit 1; }
	@mkdir -p "$(RESULTS_DIR)"
	@echo "report-cloudgov: running --json on $(CLOUDGOV_APP) (instance $(CF_APP_INSTANCE))"
	@# Run the validation with JSON output. The runner writes the report to
	@# /out/validation-<label>-<ts>.json inside the container and echoes that
	@# path on stderr as "JSON report path: <path>". Capture stderr so we can
	@# learn the exact (timestamped) filename to fetch. CINC exits 100/101 when
	@# controls fail/skip; that is expected and must NOT abort the fetch, so we
	@# tolerate it.
	@set -e; \
	  stderr_log="$$(mktemp)"; \
	  cf ssh $(CLOUDGOV_APP) -i $(CF_APP_INSTANCE) \
	    -c "/usr/local/bin/run-validation.sh --json" 2> "$$stderr_log" || true; \
	  cat "$$stderr_log" >&2; \
	  remote_path="$$(sed -n 's/^run-validation: JSON report path: //p' "$$stderr_log" | tail -n1)"; \
	  rm -f "$$stderr_log"; \
	  if [ -z "$$remote_path" ]; then \
	    echo "ERROR: could not determine remote JSON path from run output." >&2; \
	    exit 1; \
	  fi; \
	  local_path="$(RESULTS_DIR)/$$(basename "$$remote_path")"; \
	  echo "report-cloudgov: fetching $$remote_path → $$local_path"; \
	  cf ssh $(CLOUDGOV_APP) -i $(CF_APP_INSTANCE) \
	    -c "cat '$$remote_path'" > "$$local_path"; \
	  echo "report-cloudgov: saved $$local_path"

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

.PHONY: clean
clean: ## Tear down compose + remove local results and built image
	-docker compose -f $(COMPOSE_FILE) down --volumes --remove-orphans
	-docker image rm $(RUNNER_IMAGE) 2>/dev/null || true
