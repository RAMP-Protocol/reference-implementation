.PHONY: help quality fmt lint typecheck test test-fast jscpd file-length install-tools proto sqlc
.PHONY: go-fmt go-lint go-typecheck go-test test-integration
.PHONY: db-up db-down db-logs ledger
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
	@echo "  make proto          - regenerate proto code from proto/"
	@echo "  make sqlc           - regenerate sqlc Go code from queries + migrations"
	@echo "  make db-up          - start local Postgres + Redis via docker compose"
	@echo "  make db-down        - stop local Postgres + Redis"
	@echo "  make test-integration - run //go:build integration tests (spins testcontainers)"
	@echo "  make install-tools  - install sqlc, golangci-lint, gofumpt, biome, jscpd, wrangler"
	@echo ""
	@echo "Per-subproject: make edge-<target>, make mcp-<target> (e.g. edge-lint, mcp-test)"
	@echo ""
	@echo "Demo:"
	@echo "  make ledger TX=<id> - render the cryptographic evidence chain for a tx"

# Renders the 6-row evidence table for a single transaction. Joins the
# Exchange transaction_log row (via /admin/ledger) and the Lambda@Edge
# access-log entry (via aws logs filter-log-events) by tx_id, asserts
# matches across parties. See scripts/ledger.py for env overrides.
ledger:
	@if [ -z "$(TX)" ]; then echo "usage: make ledger TX=<transaction_id>"; exit 2; fi
	@python3 scripts/ledger.py --tx $(TX)

quality: fmt lint typecheck test-fast jscpd file-length
	@echo "All quality gates passed!"

file-length:
	@python3 scripts/check-file-length.py

fmt: go-fmt
	@$(MAKE) -C src/edge fmt
	@$(MAKE) -C src/mcp fmt

lint: go-lint
	@$(MAKE) -C src/edge lint
	@$(MAKE) -C src/mcp lint

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

proto:
	@rm -rf proto/gen/go proto/gen/ts
	@cd proto && buf generate

sqlc:
	sqlc generate

db-up:
	docker compose up -d postgres redis

db-down:
	docker compose down

db-logs:
	docker compose logs -f postgres

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
test-e2e:
	@echo "==> full-stack E2E (docker compose + runner)"
	docker compose -f docker-compose.e2e.yml up -d --build
	docker compose -f docker-compose.e2e.yml --profile test build runner
	docker compose -f docker-compose.e2e.yml --profile test run --rm runner
	@if [ -z "$${RAMP_E2E_KEEP_UP}" ]; then \
		docker compose -f docker-compose.e2e.yml down -v; \
	fi

e2e-up:
	docker compose -f docker-compose.e2e.yml up -d --build

e2e-down:
	docker compose -f docker-compose.e2e.yml down -v

e2e-logs:
	docker compose -f docker-compose.e2e.yml logs -f

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
	npm install -g @biomejs/biome jscpd wrangler
	@echo "Installed: sqlc, golangci-lint, gofumpt, biome, jscpd, wrangler"

# Per-subproject dispatch for Edge and MCP (e.g. make edge-dev, make mcp-run)
edge-%:
	$(MAKE) -C src/edge $*

mcp-%:
	$(MAKE) -C src/mcp $*
