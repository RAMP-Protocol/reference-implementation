.PHONY: help quality fmt lint typecheck test test-fast jscpd file-length install-tools sqlc
.PHONY: go-fmt go-lint go-typecheck go-test test-integration test-e2e-collect
.PHONY: db-up db-down db-logs dev-keys adr-001-check adr-008-d3-check
.PHONY: edge-% mcp-%

# Go is a single module covering src/exchange, src/broker, and internal/.
# Edge (TS) and MCP (Python) each have their own Makefile under src/.

help:
	@echo "Root targets:"
	@echo "  make quality        - fmt + lint + typecheck + test-fast + jscpd"
	@echo "  make fmt            - format Go, edge, mcp"
	@echo "  make lint           - lint Go, edge, mcp"
	@echo "  make typecheck      - typecheck Go, edge, mcp"
	@echo "  make test-fast      - fast tests across all"
	@echo "  make jscpd          - copy-paste detection across src/ + internal/"
	@echo "  make file-length    - enforce per-language file-length caps (CLAUDE.md)"
	@echo "  make sqlc           - regenerate sqlc Go code from queries + migrations"
	@echo "  make db-up          - start local Postgres + Redis via docker compose"
	@echo "  make db-down        - stop local Postgres + Redis"
	@echo "  make dev-keys       - generate gitignored local signing keys for go-run dev"
	@echo "  make test-integration - run //go:build integration tests (spins testcontainers)"
	@echo "  make install-tools  - install sqlc, golangci-lint, gofumpt, biome, jscpd, wrangler"
	@echo ""
	@echo "Per-subproject: make edge-<target>, make mcp-<target> (e.g. edge-lint, mcp-test)"

quality: fmt lint typecheck test-fast jscpd file-length adr-001-check adr-008-d3-check
	@echo "All quality gates passed!"

file-length:
	@python3 scripts/check-file-length.py

# Enforces ADR-001: Exchange authz code (service/ + transport/) MUST NOT read
# JWT claims. See docs/architecture/adr-001-three-layer-auth.md.
adr-001-check:
	@scripts/check-jwt-in-exchange-authz.sh

# Enforces ADR-008 D3: lenient pytest xfail markers (strict=False) are forbidden
# under tests/. See docs/architecture/adr-008-testing-surface-isolation.md.
adr-008-d3-check:
	@scripts/check-xfail-strict.sh

fmt: go-fmt
	@$(MAKE) -C src/edge fmt
	@$(MAKE) -C src/mcp fmt
	@$(MAKE) -C tests/e2e fmt

lint: go-lint
	@$(MAKE) -C src/edge lint
	@$(MAKE) -C src/mcp lint
	@$(MAKE) -C tests/e2e lint

typecheck: go-typecheck
	@$(MAKE) -C src/edge typecheck
	@$(MAKE) -C src/mcp typecheck

test test-fast: go-test
	@$(MAKE) -C src/edge test-fast
	@$(MAKE) -C src/mcp test-fast

go-fmt:
	@echo "==> go fmt (gofumpt)"
	gofumpt -l -w .

go-lint:
	@echo "==> go lint (golangci-lint)"
	golangci-lint run ./...

go-typecheck:
	@echo "==> go build"
	go build ./...

go-test:
	@echo "==> go test"
	go test -race -count=1 ./...

jscpd:
	@echo "==> jscpd"
	@jscpd --config .jscpd.json

sqlc:
	sqlc generate

db-up:
	docker compose up -d postgres redis

db-down:
	docker compose down

db-logs:
	docker compose logs -f postgres

# Generate gitignored local signing keys for running the Exchange via `go run`.
# The binary fails closed when no key is configured (src/exchange/cmd/server/keys.go),
# so dev provisions keys via files the same way production and e2e do.
dev-keys:
	@mkdir -p deploy/dev-keys
	@openssl genpkey -algorithm ED25519 -out deploy/dev-keys/ed25519-private.pem
	@openssl genrsa -out deploy/dev-keys/rsa-private.pem 2048
	@echo "Wrote deploy/dev-keys/ed25519-private.pem + rsa-private.pem (gitignored)."
	@echo "Export before running the exchange via go run:"
	@echo "  export RAMP_ED25519_PRIVATE_PEM_FILE=$(CURDIR)/deploy/dev-keys/ed25519-private.pem"
	@echo "  export RAMP_RSA_PRIVATE_PEM_FILE=$(CURDIR)/deploy/dev-keys/rsa-private.pem"

# Per-project isolated dev stack (random ports, named compose project).
# Call pattern for scripts and parallel executors:
#   eval "$$(PROJECT=my-executor make devstack-up)"
#   ... work ...
#   PROJECT=my-executor make devstack-down
devstack-up:
	@if [ -z "$(PROJECT)" ]; then echo "PROJECT=<name> required" >&2; exit 2; fi
	@scripts/devstack.sh up $(PROJECT)

devstack-down:
	@if [ -z "$(PROJECT)" ]; then echo "PROJECT=<name> required" >&2; exit 2; fi
	@scripts/devstack.sh down $(PROJECT)

devstack-status:
	@if [ -z "$(PROJECT)" ]; then echo "PROJECT=<name> required" >&2; exit 2; fi
	@scripts/devstack.sh status $(PROJECT)

test-integration:
	@echo "==> go test -tags integration"
	go test -tags integration -race -count=1 ./...

# Bring the full compose stack up, run the pytest E2E inside the network
# via the dedicated `runner` service, tear down. Set RAMP_E2E_KEEP_UP=1 to
# preserve the stack after the test run (useful for debugging).
test-e2e: e2e-up
	@echo "==> full-stack E2E (runner)"
	docker compose -f docker-compose.e2e.yml --profile test build runner
	# --no-deps: the stack is already up from e2e-up. Without this flag
	# compose re-reconciles every dependency and re-runs the non-idempotent
	# zitadel-init one-shot, which then 409s against the already-bootstrapped
	# instance.
	docker compose -f docker-compose.e2e.yml --profile test run --rm --no-deps runner
	@if [ -z "$${RAMP_E2E_KEEP_UP}" ]; then \
		$(MAKE) e2e-down; \
	fi

# --wait blocks until every service is healthy; --wait-timeout caps the
# wait at 120s (Wave 0 acceptance bound).
e2e-up:
	docker compose -f docker-compose.e2e.yml up -d --build --wait --wait-timeout 120

e2e-down:
	docker compose -f docker-compose.e2e.yml down -v

e2e-logs:
	docker compose -f docker-compose.e2e.yml logs -f

# Bare-pytest collection check for the E2E harness — runs `uv run pytest
# --collect-only` from inside `tests/e2e/` so the e2e venv (and its
# declared deps `biscuit-python`, `ramp-mcp-shim`) resolve. Use this
# during the audit-and-flip workflow when you need to enumerate
# xfail/xpass without spinning the full compose stack. See diagnostic
# docs/diagnostics/agentic-content-access-aemd-test-02-collection-errors.md §4-B.
# Forward extra args via E2E_PYTEST_ARGS, e.g.:
#   make test-e2e-collect E2E_PYTEST_ARGS='harness/obligations/'
test-e2e-collect:
	@cd tests/e2e && uv run pytest --collect-only $(E2E_PYTEST_ARGS)

# ───── AWS demo deploy helpers — see RUNBOOK-aws-demo.md ────────────────────
aws-rotate-keys:
	@scripts/rotate-keys.sh generate

aws-publish-keys:
	@scripts/rotate-keys.sh publish

aws-push:
	@scripts/ecr-push.sh

aws-wire-secrets:
	@scripts/wire-secrets.sh

aws-roll-services:
	@for svc in exchange broker mcp; do \
		aws ecs update-service --cluster ramp-demo --service ramp-demo-$$svc --force-new-deployment >/dev/null \
		  && echo "  rolled ramp-demo-$$svc" ; \
	done

# Real-AWS acceptance suite (noop unless RAMP_E2E_AWS=1).
test-e2e-aws:
	@echo "==> AWS acceptance pytest"
	cd tests/e2e && uv run --with-editable . pytest -q ../e2e-aws

install-tools:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install mvdan.cc/gofumpt@latest
	npm install -g @biomejs/biome jscpd@^3.5.10 wrangler
	@echo "Installed: sqlc, golangci-lint, gofumpt, biome, jscpd, wrangler"

# Per-subproject dispatch for Edge and MCP (e.g. make edge-dev, make mcp-run)
edge-%:
	$(MAKE) -C src/edge $*

mcp-%:
	$(MAKE) -C src/mcp $*
