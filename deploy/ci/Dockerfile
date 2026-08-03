# syntax=docker/dockerfile:1
#
# Prebuilt CI image for RAMP pipelines (quality / integration / e2e).
#
# Bakes the toolchain each job's before_script used to apt-install on every run
# (~1.5-2 min/job). CI jobs PULL this image (the GitLab runner has read access to
# the Artifact Registry); it is built and pushed MANUALLY because it changes
# rarely:
#
#   gcloud auth login                                          # once, interactive
#   gcloud auth configure-docker europe-west2-docker.pkg.dev   # once
#   make ci-image-push
#
# Pin bumps (Go, golangci-lint, node) are deliberate: edit here, rebuild, push a
# new dated tag, then point the CI pipeline definition at it.
FROM golang:1.26

# ---- system packages (union of the three jobs' apt installs) ----
#   build/scripting : bash curl git make ca-certificates gcc gnupg
#   node + python   : nodejs npm python3 python3-cryptography
#   docker client   : docker-ce-cli + compose plugin (integration/e2e drive DinD)
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      bash curl git make ca-certificates gcc gnupg \
      nodejs npm python3 python3-cryptography \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update -qq \
 && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/*

# ---- uv (Python package manager for the tests/e2e harness) ----
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# ---- terraform (deploy/terraform module test suites — the CI `terraform` job) ----
# Version-pinned zip from HashiCorp releases (the apt repo only tracks latest);
# bump deliberately, same policy as the other pins in this file.
ARG TERRAFORM_VERSION=1.15.8
RUN curl -fsSLo /tmp/terraform.zip \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_$(dpkg --print-architecture).zip" \
 # the base image ships no unzip tool; python3 is already installed above, so its
 # zipfile module extracts the archive without adding an extra package for one use
 && python3 -c "import zipfile; zipfile.ZipFile('/tmp/terraform.zip').extract('terraform', '/usr/local/bin')" \
 && chmod 0755 /usr/local/bin/terraform \
 && rm /tmp/terraform.zip

# ---- Go + npm tools (match `make install-tools`) ----
# golangci-lint: official prebuilt binary, version-pinned (script URL + binary
# both at the tag, same as the Makefile). sqlc/gofumpt via go install into a
# system bin so they are on PATH without GOPATH wiring.
# gitleaks backs the published-secrets quality gate. Pinned to the version the
# reviewed exemptions in .gitleaks.toml were verified against — its rule set is
# what the gate reports, so a bump means re-checking those exemptions. Keep the
# value in step with GITLEAKS_VERSION in the root Makefile.
ARG GOLANGCI_LINT_VERSION=v2.12.2
ARG GITLEAKS_VERSION=v8.18.2
RUN GOBIN=/usr/local/bin go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest \
 && GOBIN=/usr/local/bin go install mvdan.cc/gofumpt@latest \
 && GOBIN=/usr/local/bin go install "github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}" \
 && curl -sSfL "https://raw.githubusercontent.com/golangci/golangci-lint/${GOLANGCI_LINT_VERSION}/install.sh" \
      | sh -s -- -b /usr/local/bin "${GOLANGCI_LINT_VERSION}" \
 && npm install -g @biomejs/biome jscpd@^3.5.10 wrangler

# ---- fail the build if any tool is missing (catches drift early) ----
RUN go version && node --version && npm --version && python3 --version \
 && uv --version && sqlc version && gofumpt --version \
 && gitleaks version \
 && golangci-lint version && biome --version && jscpd --version \
 && terraform version \
 && docker --version && docker buildx version && docker compose version
