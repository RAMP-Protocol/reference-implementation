.PHONY: help quality quality-ci fmt fmt-check lint typecheck test test-fast jscpd file-length install-tools sqlc
.PHONY: go-fmt go-fmt-check go-lint go-typecheck go-test test-integration test-zitadel test-e2e-collect
.PHONY: db-up db-down db-logs dev-keys adr-001-check adr-008-d3-check sdk-pin-check
.PHONY: stale-proto-names-check published-refs-check published-secrets-check test-terraform
.PHONY: image-version-check
.PHONY: zitadel-up zitadel-creds zitadel-logs zitadel-down
.PHONY: edge-%
.PHONY: test-e2e e2e-keys e2e-up e2e-down e2e-logs e2e-demo

# Go is a single module covering src/exchange, src/broker, src/identity, and
# internal/. Edge (TS) has its own Makefile under src/; the Python e2e harness
# has one under tests/e2e/.

help:
	@echo "Root targets:"
	@echo "  make quality        - fmt + lint + typecheck + test-fast + jscpd"
	@echo "  make fmt            - format Go, edge, Python (e2e)"
	@echo "  make lint           - lint Go, edge, Python (e2e)"
	@echo "  make typecheck      - typecheck Go, edge, Python (e2e harness)"
	@echo "  make test-fast      - fast tests across all"
	@echo "  make jscpd          - copy-paste detection across src/ + internal/"
	@echo "  make file-length    - enforce per-language file-length caps"
	@echo "  make sqlc           - regenerate sqlc Go code from queries + migrations"
	@echo "  make db-up          - start local Postgres + Redis via docker compose"
	@echo "  make db-down        - stop local Postgres + Redis"
	@echo "  make dev-keys       - generate gitignored local signing keys for go-run dev"
	@echo "  make zitadel-up     - start + provision the local Zitadel OIDC provider"
	@echo "  make zitadel-creds  - re-print its export lines (eval-safe)"
	@echo "  make zitadel-down   - stop it and wipe its volumes (issuer is baked in)"
	@echo "  make test-integration - run //go:build integration tests (spins testcontainers)"
	@echo "  make test-terraform - terraform module test suites + config drift checks (needs terraform)"
	@echo "  make published-secrets-check - scan the published file set for secrets (needs gitleaks)"
	@echo "  make install-tools  - install sqlc, gitleaks, golangci-lint, gofumpt, biome, jscpd, wrangler"
	@echo ""
	@echo "Per-subproject: make edge-<target> (e.g. edge-lint, edge-test)"

quality: fmt lint typecheck test-fast jscpd file-length adr-001-check adr-008-d3-check sdk-pin-check stale-proto-names-check published-refs-check published-secrets-check image-version-check
	@echo "All quality gates passed!"

# CI variant of `quality`: formatting is CHECKED, never written. CI must not
# mutate the tree, and a check FAILS on violations instead of the local `fmt`
# silently auto-fixing them. (Go + edge formatting is also enforced by their
# linters; tests/e2e Python formatting is enforced ONLY here.) Local
# `make quality` keeps auto-formatting via `fmt`.
quality-ci: fmt-check lint typecheck test-fast jscpd file-length adr-001-check adr-008-d3-check sdk-pin-check stale-proto-names-check published-refs-check published-secrets-check image-version-check
	@echo "All quality gates passed (CI, check-only fmt)!"

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

# Enforces RAMP protocol/SDK git-pin agreement: one repo, one rev — Python
# pyprojects agree with each other and their uv.locks, each package.json
# agrees with its package-lock.json, and Python/TS manifests pin the same rev.
sdk-pin-check:
	@scripts/check-sdk-pin-consistency.sh

# Forbids the pre-unification proto message names RAMPRequest/RAMPResponse
# (renamed DiscoveryRequest/DiscoveryResponse) in comments and prose, where the
# compiler cannot see them.
stale-proto-names-check:
	@scripts/check-stale-proto-names.sh

# Terraform module test suites (offline: plan mode + mocked providers) plus
# config drift checks (compatibility_date vs wrangler.toml). Not part of
# `quality`: it needs the terraform binary, which not every dev machine has —
# CI runs it as its own job with zero tolerance.
test-terraform:
	@deploy/terraform/scripts/test-terraform.sh

# Forbids references from published files to anything the publish does not
# ship — such a pointer is unopenable for whoever reads the public repo. The
# script header lists what counts; a deliberate exception takes a
# `published-ref-allow:` comment on the same or preceding line.
published-refs-check:
	@scripts/check-published-refs.sh

# Runs the secret scanner over the tracked files the publish ships, so a key on
# a published path fails the branch instead of the release. The publish tool
# scans the curated tree it is about to push; this is that check moved forward
# to the commit that would cause it. Needs gitleaks — `make install-tools`.
published-secrets-check:
	@scripts/check-published-secrets.sh

# Keeps the published image version declared once per deployment document and
# identical across the three. A release edits one line per document; a partial
# edit would otherwise leave a document naming a tag nobody published, which
# reads as correct right up to the "not found".
image-version-check:
	@scripts/check-image-version.sh

fmt: go-fmt
	@$(MAKE) -C src/edge fmt
	@$(MAKE) -C tests/e2e fmt

# Check-only formatting (no writes); fails if anything is unformatted.
fmt-check: go-fmt-check
	@$(MAKE) -C src/edge fmt-check
	@$(MAKE) -C tests/e2e fmt-check

lint: go-lint
	@$(MAKE) -C src/edge lint
	@$(MAKE) -C tests/e2e lint

typecheck: go-typecheck
	@$(MAKE) -C src/edge typecheck
	@$(MAKE) -C tests/e2e typecheck

test test-fast: go-test
	@$(MAKE) -C src/edge test-fast
	@$(MAKE) -C tests/e2e test-fast

# Use golangci-lint's formatter (gofumpt + goimports per .golangci.yml), NOT a
# standalone gofumpt binary: the two disagree even at the same version, and
# golangci-lint is the authoritative gate (the `lint` step). This keeps write,
# check, and lint on one formatter.
go-fmt:
	@echo "==> go fmt (golangci-lint fmt)"
	golangci-lint fmt

# Check-only: `fmt --diff` prints the diff and exits non-zero when unformatted.
go-fmt-check:
	@echo "==> go fmt check (golangci-lint fmt --diff)"
	golangci-lint fmt --diff

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

# ── Local Zitadel: the upstream OIDC provider for developer sign-up ──────────
# These live behind the `zitadel` compose profile, so `make db-down` does NOT stop
# them — use `make zitadel-down`.
COMPOSE_ZITADEL = docker compose --profile zitadel

# Export GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first to configure Google
# sign-in; without them the bootstrap skips it and the alice login still works.
zitadel-up:
	$(COMPOSE_ZITADEL) up -d zitadel-db zitadel
	@echo "==> provisioning Zitadel (project, login policy, OIDC client, alice, google IdP)"
	$(COMPOSE_ZITADEL) run --rm --no-deps zitadel-init
	@echo ""
	@echo "Wire a shell for the identity service with:"
	@echo "  eval \"\$$(make zitadel-creds)\""

# Re-print an earlier run's exports for a new shell. The format is not restated
# here — --emit-exports is the same script that wrote them. eval-safe.
zitadel-creds:
	@$(COMPOSE_ZITADEL) run --rm --no-deps zitadel-init --emit-exports

zitadel-logs:
	$(COMPOSE_ZITADEL) logs -f zitadel

# Compose's default project name is the directory basename unless overridden.
COMPOSE_PROJECT ?= $(if $(COMPOSE_PROJECT_NAME),$(COMPOSE_PROJECT_NAME),$(notdir $(CURDIR)))

# Volumes go too: the issuer is baked at init, so reconfiguring is a wipe. Only the
# zitadel volumes — `down -v` would take pgdata/redisdata/tbdata with it. The label
# filter keeps a sibling compose project out of the blast radius.
zitadel-down:
	$(COMPOSE_ZITADEL) rm -sfv zitadel zitadel-db zitadel-init
	@vols=$$(docker volume ls -q \
		--filter label=com.docker.compose.project=$(COMPOSE_PROJECT) \
		--filter name=zitadel); \
	if [ -n "$$vols" ]; then docker volume rm $$vols; else echo "no zitadel volumes to remove"; fi

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

# INTEGRATION_PARALLEL bounds how many package test binaries run concurrently.
# Each integration package spins its own testcontainers (Postgres/Redis), so the
# default `-p` (= GOMAXPROCS, often 14) starts a burst of dozens of containers at
# once and saturates the Docker daemon on a busy/shared host — inspect calls then
# time out ("context deadline exceeded" / mapped-port failures). 4 keeps the
# daemon responsive while still overlapping the long-pole packages. Override on a
# dedicated CI Docker for more speed: `make test-integration INTEGRATION_PARALLEL=8`.
INTEGRATION_PARALLEL ?= 4

# -timeout 25m: the per-package go-test deadline (default 10m). The
# exchange/internal/transport integration package alone runs ~10-12m under CI
# docker-in-docker + -p contention (≈190s locally serial, but dind is ~3x slower
# and concurrent containers compete), tripping the 10m default. 25m is ample
# headroom for the slowest package without masking a genuine hang.
test-integration:
	@echo "==> go test -tags integration (-p $(INTEGRATION_PARALLEL))"
	go test -tags integration -race -count=1 -timeout 25m -p $(INTEGRATION_PARALLEL) ./...

# Real-Zitadel tier (developer sign-up). Brings up a real Zitadel
# v3.4.9 + its Postgres as a per-package testcontainer and drives the sign-up
# flow through the real upstream-OIDC client (real discovery, headless login,
# JWKS ID-token verification) — the mock is kept only for the upstream-failure
# case a real Zitadel cannot stage. Deliberately OUT of test-integration
# (pre-push): the ~30-45s Zitadel boot + Login-V1 HTML scrape must not gate
# every push; run it nightly / on demand. Needs Docker and a free host port
# 8080 — the tests skip cleanly if it is busy.
test-zitadel:
	@echo "==> go test -tags 'integration zitadel' (real Zitadel)"
	go test -tags "integration zitadel" -race -count=1 -timeout 25m \
		-run 'TestAuthFlow' ./src/identity/internal/transport/

# Compose invocation for the e2e stack. CI appends a registry-cache overlay
# (`-f docker-compose.e2e.cache.yml`) via E2E_COMPOSE_EXTRA so the image builds
# push/pull a BuildKit layer cache in Artifact Registry. Empty by default, so a
# plain local `make e2e-up` stays auth-free (no registry contact).
COMPOSE_E2E = docker compose -f docker-compose.e2e.yml $(E2E_COMPOSE_EXTRA)

# Bring the full compose stack up, run the pytest E2E inside the network
# via the dedicated `runner` service, tear down. Set RAMP_E2E_KEEP_UP=1 to
# preserve the stack after the test run (useful for debugging).
test-e2e: e2e-up
	@echo "==> full-stack E2E (runner)"
	$(COMPOSE_E2E) --profile test build runner
	# --no-deps: the stack is already up from e2e-up. Without this flag compose
	# re-reconciles every dependency and re-runs non-idempotent init one-shots
	# against the already-bootstrapped stack.
	$(COMPOSE_E2E) --profile test run --rm --no-deps runner
	@if [ -z "$${RAMP_E2E_KEEP_UP}" ]; then \
		$(MAKE) e2e-down; \
	fi

# Generate every signing key the E2E stack needs BEFORE `docker compose up`, so
# a fresh checkout needs zero manual keygen (no private material is
# committed). Mints:
#   * the e2e identities (contributor/agents/broker-relay/test-signer/…) —
#     private fixtures under tests/e2e/harness/fixtures/
#     (scripts/gen-e2e-keys.sh). There is no shared key registry file: each
#     identity's pubkey is served only by that identity's own well-known host
#     in docker-compose.e2e.yml. The broker-relay private fixture this mints is
#     the one the broker container mounts (BROKER_RELAY_KEY_FILE); the broker
#     publishes its pubkey in its own WBA directory at boot.
#   * the demo subscription-publisher key the publisher-jwks service signs
#     /.well-known/ramp.json with (scripts/gen-examplenews-publisher-key.sh).
# Idempotent: safe to re-run before every `make e2e-up`.
e2e-keys:
	@echo "==> generating e2e signing keys (gitignored private material)"
	@scripts/gen-e2e-keys.sh
	@scripts/gen-examplenews-publisher-key.sh

# --wait blocks until every service is healthy; --wait-timeout caps the
# wait at 120s (Wave 0 acceptance bound). e2e-keys runs first so a clean
# checkout (no committed keys) comes up with zero manual steps.
e2e-up: e2e-keys
	$(COMPOSE_E2E) up -d --build --wait --wait-timeout 120

# Phase-2a demo-catalog proof (items 2-5): register the three demo tenants,
# ingest all three demo feeds via the production cmd/ramp-ingest binary,
# DiscoverResources for a demo resource, and fetch the canary article through an
# edge. Re-runnable against an already-up stack (`make e2e-up` first).
e2e-demo:
	uv run --project tests/e2e python tests/e2e/demo_proof.py

e2e-down:
	$(COMPOSE_E2E) down -v

e2e-logs:
	$(COMPOSE_E2E) logs -f

# Bare-pytest collection check for the E2E harness — runs `uv run pytest
# --collect-only` from inside `tests/e2e/` so the e2e venv (and its
# declared deps (e.g. `biscuit-python`) resolve. Use this
# during the audit-and-flip workflow when you need to enumerate
# xfail/xpass without spinning the full compose stack.
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
	@for svc in exchange broker identity; do \
		aws ecs update-service --cluster ramp-demo --service ramp-demo-$$svc --force-new-deployment >/dev/null \
		  && echo "  rolled ramp-demo-$$svc" ; \
	done

# Real-AWS acceptance suite (noop unless RAMP_E2E_AWS=1).
test-e2e-aws:
	@echo "==> AWS acceptance pytest"
	cd tests/e2e && uv run --with-editable . pytest -q ../e2e-aws

# golangci-lint installs from its official prebuilt binary, not `go install`.
# Pinned for reproducibility; bump deliberately and re-run `make quality`.
GOLANGCI_LINT_VERSION ?= v2.12.2

# The secret scanner behind `published-secrets-check`. Pinned for the same reason
# the linters are, and one more: its rule set decides what the gate reports, and
# the reviewed exemptions in .gitleaks.toml were verified against this version.
# Bumping it means re-checking those exemptions, not just the version string.
GITLEAKS_VERSION ?= v8.18.2

install-tools:
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	go install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)
	@if ! golangci-lint version 2>/dev/null | grep -q "$(GOLANGCI_LINT_VERSION:v%=%)"; then \
		echo "==> installing golangci-lint $(GOLANGCI_LINT_VERSION) (prebuilt binary)"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh \
			| sh -s -- -b $$(go env GOPATH)/bin $(GOLANGCI_LINT_VERSION); \
	fi
	go install mvdan.cc/gofumpt@latest
	npm install -g @biomejs/biome jscpd@^3.5.10 wrangler
	@echo "Installed: sqlc, gitleaks, golangci-lint, gofumpt, biome, jscpd, wrangler"

# ───── Prebuilt CI image (deploy/ci/Dockerfile) ────────────────────────────
# Bakes the toolchain the GitLab before_scripts apt-install on every run. Built
# + pushed MANUALLY (changes rarely); CI jobs pull it (runner has read access).
# Auth once before pushing:
#   gcloud auth login
#   gcloud auth configure-docker europe-west2-docker.pkg.dev
CI_IMAGE     ?= europe-west2-docker.pkg.dev/pi-infra/prebid-agentic-content-access/ci
CI_IMAGE_TAG ?= $(shell date +%Y%m%d)

.PHONY: ci-image ci-image-push
# --platform linux/amd64: the GitLab runners are amd64; an image built natively
# on an Apple Silicon machine ships arm64 binaries and every job dies with
# "exec format error" at container start.
ci-image:
	docker build --platform linux/amd64 \
		--build-arg GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION) \
		-t $(CI_IMAGE):$(CI_IMAGE_TAG) -t $(CI_IMAGE):latest deploy/ci

ci-image-push: ci-image
	docker push $(CI_IMAGE):$(CI_IMAGE_TAG)
	docker push $(CI_IMAGE):latest
	@echo "Pushed $(CI_IMAGE):$(CI_IMAGE_TAG) and :latest"

# Per-subproject dispatch for Edge (e.g. make edge-dev, make edge-run)
edge-%:
	$(MAKE) -C src/edge $*
