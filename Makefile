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
# (runner/Dockerfile uses cincproject/auditor:6). Override on the CLI, e.g.
#   make check AUDITOR_IMAGE=cincproject/auditor:7
AUDITOR_IMAGE ?= cincproject/auditor:6
RUNNER_IMAGE  ?= cg-stig-runner:local
COMPOSE_FILE  ?= runner/docker-compose.yml
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

.PHONY: build
build: deps ## Build the runner image (builds oraquery from source; no committed binary)
	docker build -f runner/Dockerfile -t $(RUNNER_IMAGE) .

.PHONY: verify
verify: check build ## One-command verify: profile loads + runner image builds (no DB)
	@echo ""
	@echo "verify OK: profile is valid and the runner image builds."
	@echo "Next: 'make run' to execute the profile against a live Oracle 23ai Free DB."

.PHONY: run
run: deps ## Full end-to-end: start Oracle 23ai Free + exec the profile, write results
	@mkdir -p runner/out
	docker compose -f $(COMPOSE_FILE) up --build --abort-on-container-exit
	@echo ""
	@echo "run complete. Per-control report: runner/out/results.json"
	@echo "NOTE: a local 23ai run proves check LOGIC only — NOT compliance evidence."

.PHONY: clean
clean: ## Tear down compose + remove local results and built image
	-docker compose -f $(COMPOSE_FILE) down --volumes --remove-orphans
	-rm -rf runner/out
	-docker image rm $(RUNNER_IMAGE) 2>/dev/null || true
