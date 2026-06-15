.PHONY: deps fmt lint

# Lint and format targets for the full-stack E2E harness (`tests/e2e/`) and
# the sibling real-AWS acceptance tree (`tests/e2e-aws/`). The two trees
# share one uv venv: tests/e2e/pyproject.toml carries the ruff config and
# the dev dependency, and `tests/e2e-aws/` is a single test file under the
# same lint scope (mirrors `make test-e2e-aws` at root, which invokes
# pytest with `--with-editable . pytest -q ../e2e-aws`).
#
# Root delegation: the project Makefile's `fmt` and `lint` targets descend
# here, closing the lint-coverage gap surfaced by audit task
# agentic-content-access-ygdhj §2.6 and fixed under
# agentic-content-access-gz1uo.
#
# Test execution lives in docker-compose (`make test-e2e` at root) and is
# intentionally absent from this Makefile — the runner container resolves
# its own venv via tests/e2e/Dockerfile.

deps:
	uv sync

fmt:
	uv run ruff format . ../e2e-aws/

lint:
	uv run ruff check . ../e2e-aws/
