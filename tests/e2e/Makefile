.PHONY: deps fmt fmt-check lint typecheck test-fast

# Lint and format targets for the full-stack E2E harness (`tests/e2e/`) and
# the sibling real-AWS acceptance tree (`tests/e2e-aws/`). The two trees
# share one uv venv: tests/e2e/pyproject.toml carries the ruff config and
# the dev dependency, and `tests/e2e-aws/` is a single test file under the
# same lint scope (mirrors `make test-e2e-aws` at root, which invokes
# pytest with `--with-editable . pytest -q ../e2e-aws`).
#
# Root delegation: the project Makefile's `fmt` and `lint` targets descend
# here, closing the lint-coverage gap the build-tag pocket audit surfaced.
#
# STACK-DRIVING test execution lives in docker-compose (`make test-e2e` at root)
# and is intentionally absent from this Makefile — the runner container resolves
# its own venv via tests/e2e/Dockerfile. The `test-fast` target below is the
# exception: it runs ONLY the harness tests that need no stack at all.

deps:
	uv sync

fmt:
	uv run ruff format . ../e2e-aws/

fmt-check:
	uv run ruff format --check . ../e2e-aws/

lint:
	uv run ruff check . ../e2e-aws/

# The root `typecheck` target descends here. When the repo's only mypy
# invocation lived under src/mcp/, deleting that tree took the whole Python
# type gate with it, so `make quality` reported green with no Python type
# checking at all while the harness kept growing. This restores the gate.
#
# Not --strict: the harness is untyped in places and interacts with untyped
# third-party stubs, so strict mode would be a wall of errors rather than a
# gate anyone keeps green. It checks what it can and is wired into `quality`,
# which is the property that was actually missing. This narrower gate is
# deliberate: the alternative on offer was no Python type gate at all.
#
# Scope MATCHES `lint` above deliberately. A typecheck narrower than its sibling
# lint gate leaves files that look covered and are not: the standalone drivers
# (`demo_proof.py`, `register_staging_agent.py`, `smoke_staging.py`) and
# `../e2e-aws/` are all linted, and the drivers construct the harness's own
# types — exactly the arity/shape drift a type checker catches and a linter
# does not.
typecheck:
	uv run mypy harness/ demo_proof.py register_staging_agent.py smoke_staging.py ../e2e-aws/

# The Python leg of the root `test-fast` (and so of `make quality`), which testing
# doctrine point 5 requires on every commit. It went missing when src/mcp was
# retired: `fmt`, `lint`, and `typecheck` each got a tests/e2e replacement for the
# deleted `-C src/mcp` call and this one did not, leaving the per-commit tier with
# no Python test execution at all.
#
# The file list is EXPLICIT, not a glob. Every other harness module needs the
# compose stack, and a glob would quietly pull the whole e2e suite into the
# per-commit tier the first time someone added a file. These are pure
# vector/primitive/source-scan tests — no stack, no Docker, ~0.1s — and they are
# exactly the kind whose breakage otherwise surfaces as a wall of unexplained
# signature rejections much later. Add a new file here only if it needs nothing
# brought up.
#
# The published-* and image-version guard modules earn their place for a
# different reason than the rest: they watch gates that `make quality` itself
# relies on. Running them in a later tier would mean a green quality run could
# keep asserting a property no longer being checked.
#
# The two publish-guard suites were one module until their combined length passed
# the cap on a test file. Both belong in this tier for the same reason, so a split
# that moved either one out would quietly halve the coverage this tier gives the
# publish tool.
#
# The workflow-script guard belongs here for a third reason: it is the only test
# that reads the real publishing workflow, and nothing else in this repository
# parses that file at all — there is no actionlint, no yamllint and no yq. Run it
# in a later tier and a green `make quality` would say nothing about the shell
# that publishes the images.
#
# The lambda-edge invoker guard belongs here for a fourth reason: the files it
# reads — the emulator's Dockerfile and its container probe — are not copied
# into the e2e runner image, so on that tier it can only skip. This is the one
# tier where it runs at all, and what it guards is a property whose breakage
# surfaces as an intermittent failure somewhere else entirely.
#
# The release-tool guard belongs here for the image-version reason: it drives the
# tool that performs the release edit, and that tool is what the image-version
# gate is protecting the tree from. The two share one fixture, so a change to
# either has to run both, and both run in the tier that gates every commit.
#
# The ver-wire guard is a pure AST scan of this tree: no stack, no Docker, well
# under a second, which is exactly the criterion above. It belongs in the
# per-commit tier because what it catches is invisible at run time — no service
# validates `ver` on the way in, and the two that read it echo it straight back
# to the caller, so a body that ships an empty or hand-written version passes the
# whole e2e suite. A guard whose subject cannot fail a test has to fail the commit.
# Note its three pure-scan siblings (single_offer_wire, denial_reason_key,
# no_redundant_or) meet the same criterion and are absent; adding them is a
# separate change, not a reason to leave this one out.
#
# The buildx guard belongs here for the lambda-edge invoker's reason, in its
# strongest form: the script it reads, scripts/check-buildx.sh, is not copied
# into the e2e runner image, so on that tier its skip mark fires and the module
# does not run. This is the one tier where it can run at all, and until it was
# listed here it ran on no tier — the gate could be inverted or emptied with
# every tier still passing. It meets the criterion above: a docker stub on PATH
# and one subprocess, no stack brought up.
test-fast:
	uv run pytest -q harness/test_rampsig.py harness/test_acceptance.py \
		harness/test_guards_published_refs.py harness/test_guards_published_secrets.py \
		harness/test_guards_publish_gates.py harness/test_guards_publish_worktree.py \
		harness/test_guards_image_version.py harness/test_guards_workflow_scripts.py \
		harness/test_guards_lambda_edge_invoker.py harness/test_guards_buildx.py \
		harness/test_guards_release_version.py harness/test_guards_deployment_docs.py \
		harness/test_guards_harness_collection.py harness/test_guards_ver_wire.py
