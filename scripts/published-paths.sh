#!/usr/bin/env bash
# published-paths.sh — the single definition of what ships to the public
# reference implementation.
#
# Sourced, never executed. Defines the path arrays and nothing else: no side
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
# schemas/ is load-bearing, not documentation, and two suites read it. Neither carries a
# build tag, so the absence of either schema fails `make test-fast` and
# `make test-integration` alike: src/exchange/internal/comptest/schema_test.go reads
# schemas/comp/v1/comp-v1.schema.json, and src/exchange/internal/ingest/feedschema_test.go
# reads schemas/catalog-feed/v1/ — both the schema and the example feed beside it, which it
# validates line by line.
#
# docs/architecture is the only docs/ SUBTREE published, by owner decision. Individual
# docs/ files outside it are published one at a time through ALLOW_DOC_FILES below.
# Cross-references from published files into the rest of docs/ are cleaned in the citing
# file rather than resolved by widening either list.
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

# --- Individual docs/ files published outside docs/architecture ---
#
# Per-file, never a directory, and deliberately so: ALLOW_DIRS copies a whole subtree, so
# a `docs` entry there would ship every working note in it on the next publish with no
# further decision. Naming each file is what keeps that decision explicit.
#
# Every entry is BUILT FROM THIS TREE, unlike INHERIT_FROM_MAIN below, whose files exist
# only on the public branch. Both sets end up on the public tree, so both are resolvable
# targets for a citation and the reference gate must subtract both from the bare-basename
# patterns it derives from the unpublished docs on disk.
ALLOW_DOC_FILES=(
  # The operator-facing setup guide: what the platform is made of, what to prepare, how
  # the network must be laid out, and where each component's own deployment guide is. It
  # cites published paths throughout (src/*/CONFIGURATION.md, deploy/**, tests/e2e/), so
  # a public reader without it is left with per-component guides and no entry point.
  docs/HANDOFF-operator.md
)

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
  # Keeps the edge worker's delivery-event name and the ledger's search for it
  # in agreement; both files it compares are published, so the gate travels.
  scripts/check-delivery-event-name.sh
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
  # Keeps the deployment documents agreeing on one published image version.
  # Those documents ship, so the check on them has to ship with them.
  scripts/check-image-version.sh
  # The list of documents that check reads. It sources this file and refuses to
  # run without it, so shipping one without the other ships a gate that aborts.
  scripts/deployment-docs.sh

  # Local stack + e2e bootstrap. The e2e key material is generated at bootstrap
  # (it is gitignored, never committed), so without these the published stack has
  # no signing keys at all.
  #
  # buildx-check is the first prerequisite of `make e2e-up`, so the published
  # Makefile calls it on the reader's very first stack-up. Without it that
  # target dies on a missing script instead of building.
  scripts/check-buildx.sh
  scripts/devstack.sh
  scripts/gen-broker-relay-key.sh
  scripts/gen-buyer-delegation-key.sh
  # Named by ramp-ingest's --key help text and the Exchange RUNBOOK, both of
  # which ship — the command a published document tells the reader to run has
  # to exist in the published tree.
  scripts/gen-contributor-key.sh
  scripts/gen-e2e-keys.sh
  scripts/gen-examplenews-publisher-key.sh
  # Imported by the gen-*-key scripts via an inline heredoc.
  scripts/lib/ed25519_keys.py
  # Sourced by every key-gen script to pick a cryptography-capable interpreter.
  scripts/lib/select-python.sh
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

# --- Scaffolding taken from the existing public snapshot, not from this tree ---
#
# The publish checks each of these out of the PUBLIC base after the allowlists above have
# been staged, so the public branch's copy is what ships. LICENSE exists only there. The
# README is tracked here as well, and taking the public copy rather than this one is
# deliberate: the public README is a different document altogether, written for a reader
# arriving at the reference implementation, where this tree's is an internal working
# README. (The retired aws-demo runbook and handoff were inherited here too, for a
# different reason — their private copies carried identifiers of a live deployment — until
# the deployment they described was decommissioned and both documents were removed.)
#
# They land on the public tree all the same, so the reference gate must NOT treat a
# citation of one as unresolvable — the same subtraction it applies to ALLOW_DOC_FILES.
#
# An entry here must NOT also appear in an allow array above: that would stage the path
# from this tree and then again from the public base, and which copy survives would depend
# on the order of two statements in the publish tool. The publish tool refuses that
# combination outright.
#
# Moving an entry from here INTO an allow array is the edit to be careful with. The arrays
# stay disjoint afterwards, so no check that DERIVES its expectation from them can see it.
# That is why tests/e2e/harness/test_guards_publish_gates.py writes out which documents
# have to stay inherited, and why that list is maintained by hand rather than derived.
INHERIT_FROM_MAIN=( LICENSE README.md )

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
LOCAL_ONLY_FILES=( publish-public.sh release-version.sh PUBLISH-PUBLIC.md PUBLIC-REPO-FIXES.md PUBLISH-VALIDATION-FINDINGS.md PUBLISH-DOC-CITATIONS.md )
