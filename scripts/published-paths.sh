#!/usr/bin/env bash
# published-paths.sh — the single definition of what ships to the public
# reference implementation.
#
# Sourced, never executed. Defines four arrays and nothing else: no side
# effects, no output, no `set` changes. Both the publish tool and the
# unresolvable-reference gate read this file, so the set they enforce and the
# set they publish cannot drift apart.
#
# That drift is the reason this file exists. The two consumers previously kept
# their own copies in OPPOSITE polarity — an allowlist in one, a denylist in the
# other — and disagreed four ways at once: ten of the eleven root files were
# published but never scanned, one script was published AND classified as
# never-published, another was scanned but never shipped, and a doc the publish
# guarantees onto the public tree was on the gate's reject list.
#
# Every consumer DERIVES from these arrays rather than restating them — the
# reference gate's search roots and doc-name patterns, the publish tool's
# forbidden-path regex, and the gate's own test fixture, which reads them back by
# sourcing this file. Extracting the data and leaving a view computed from it
# behind is the same defect one level down, and it is how the drift above
# survived a round that was meant to end it.

# --- Production directories (verbatim paths, copied from the source ref) ---
ALLOW_DIRS=(
  src
  internal
  tests
  testdata
  deploy
  schemas
  docs/architecture
  .github
)
# schemas/ is load-bearing, not documentation: src/exchange/internal/comptest/schema_test.go
# reads schemas/comp/v1/comp-v1.schema.json and carries NO build tag, so its absence fails
# `make test-fast` and `make test-integration` alike.
#
# docs/architecture is the ONLY docs/ path published, by owner decision. Cross-references
# from published files into the rest of docs/ are cleaned in the citing file rather than
# resolved by widening this list.
#
# .github holds the workflow that builds and publishes the service container images. It
# has to be authored HERE rather than on the public repository, because the publish
# rebuilds the public tree from this list and deletes everything it does not reproduce —
# a workflow created directly on GitHub would survive exactly until the next publish.
#
# CAUTION, and it applies to every entry here: an ALLOW_DIRS entry copies the WHOLE
# subtree. Anything added under .github/ later reaches the public repository on the next
# publish with no further decision. ALLOW_SCRIPTS below is per-file and this array is not,
# so if .github/ ever needs to hold something that must stay private, the granularity has
# to be built first.

# --- Root-level build/config files (required to build/test) ---
ALLOW_ROOT_FILES=(
  go.mod go.sum sqlc.yaml
  Makefile docker-compose.yml docker-compose.e2e.yml
  .golangci.yml .jscpd.json .gitignore .dockerignore .gitleaks.toml
)

# --- Curated production/ops scripts (the internal methodology tooling under
#     scripts/ is deliberately NOT published) ---
#
# Every entry is a FILE, never a directory: the publish gate compares
# `git ls-files 'scripts/*'` against this array with `grep -vx`, so a directory
# entry would fail the very publish it is meant to protect.
ALLOW_SCRIPTS=(
  # This file — the public clone needs it to run the reference gate below.
  scripts/published-paths.sh

  # Quality gates the Makefile invokes.
  scripts/check-file-length.py
  scripts/check-jwt-in-exchange-authz.sh
  scripts/check-sdk-pin-consistency.sh
  scripts/check-stale-proto-names.sh
  scripts/check-xfail-strict.sh
  # ... which is a thin wrapper that execs this AST-based checker.
  scripts/check_xfail_strict.py
  # Forbids references from published files to paths this list does not ship.
  # It derives its search roots from the arrays here — a gate the public repo
  # cannot run is not a gate.
  scripts/check-published-refs.sh
  # Scans the same derived set for secrets, so a key reaching a published path
  # fails the branch rather than the publish. Ships for the same reason.
  scripts/check-published-secrets.sh
  # Keeps the three deployment documents agreeing on one published image version.
  # Those documents ship, so the check on them has to ship with them.
  scripts/check-image-version.sh

  # Local stack + e2e bootstrap. The e2e key material is generated at bootstrap
  # (it is gitignored, never committed), so without these the published stack has
  # no signing keys at all.
  scripts/devstack.sh
  scripts/gen-broker-relay-key.sh
  scripts/gen-buyer-delegation-key.sh
  scripts/gen-demo-agent-key.sh
  scripts/gen-e2e-keys.sh
  scripts/gen-examplenews-publisher-key.sh
  # Imported by both gen-*-key scripts via an inline heredoc.
  scripts/lib/ed25519_keys.py
  # Bind-mounted read-only by docker-compose.e2e.yml into a service with no
  # profile; identity waits on it with service_completed_successfully. A missing
  # source makes Docker materialise a DIRECTORY there, so the stack fails with
  # "is a directory" rather than "not found".
  scripts/zitadel-bootstrap.sh
  scripts/zitadel-pkce-smoke.sh

  # Ops / deploy.
  scripts/ecr-push.sh
  scripts/mint-signed-url.py
  scripts/rotate-keys.sh
  scripts/wire-secrets.sh
)

# --- Public-only scaffolding inherited from the existing public snapshot
#     (these do not exist on the private branch) ---
#
# These land on the public tree even though no allowlist above produces them, so
# the reference gate must NOT treat a citation of one as unresolvable.
INHERIT_FROM_MAIN=( LICENSE README.md RUNBOOK-aws-demo.md docs/HANDOFF-aws-demo.md )

# --- docs/ subtrees that are NOT published ---
#
# docs/architecture is the only publishable one. Both consumers need this set —
# the publish tool to refuse a stray path, the reference gate to reject a
# citation of one — and each builds its own regex from it. It lived in both as a
# hand-written alternation, in different orders, until the two were found to have
# no common source.
UNPUBLISHED_DOC_DIRS=(
  design protocol diagnostics handoff obligations workdocs analysis runbooks testing
)

# --- Root files that are local-only and never published ---
#
# The publish tool and its working notes. Both consumers need these names — the
# publish tool to refuse the path, the reference gate to reject a citation of one
# — and the gate cannot read them from the tool, because the tool is itself one
# of the files that does not travel. So they live here.
#
# One line so the waiver covers every entry: this array IS the list of names the
# gate forbids, the same carve-out the conventions make for rule text that has to
# show the format it mandates.
# published-ref-allow: the definition of the forbidden names cannot avoid naming them
LOCAL_ONLY_FILES=( publish-public.sh PUBLISH-PUBLIC.md PUBLIC-REPO-FIXES.md PUBLISH-VALIDATION-FINDINGS.md PUBLISH-DOC-CITATIONS.md )
