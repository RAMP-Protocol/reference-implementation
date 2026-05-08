.PHONY: deps fmt lint typecheck test test-fast run

deps:
	uv sync

fmt:
	uv run ruff format .

lint:
	uv run ruff check .

typecheck:
	uv run mypy src tests

test test-fast:
	uv run pytest -q

run:
	uv run ramp-mcp
