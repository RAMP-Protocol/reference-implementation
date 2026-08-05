# Sourced by the key-generation scripts to select a Python interpreter that
# can import the `cryptography` package: uv (the repo standard, which
# provisions the dependency on the fly) when available, the system python3
# otherwise — and the fallback is PROBED, not assumed: a python3 that is
# absent or cannot import cryptography fails here with a clear message
# instead of dying later inside a key-generation heredoc with a bare
# traceback. Sets the PYTHON array; invoke heredocs as
#
#   "${PYTHON[@]}" - <argv...> <<'PY'
#   ...
#   PY
#
# The heredocs run under whatever interpreter this selects, which on the
# python3 fallback may be old — keep them compatible with pre-3.11 Python
# (e.g. write datetime.now(timezone.utc), never the 3.11-only datetime.UTC).
PYTHON=(python3)
if command -v uv >/dev/null 2>&1; then
    PYTHON=(uv run --with cryptography python)
elif ! python3 -c 'import cryptography' >/dev/null 2>&1; then
    echo "select-python: no uv on PATH and python3 is missing or cannot import 'cryptography'." >&2
    echo "select-python: install uv (https://docs.astral.sh/uv/) or 'pip install cryptography'." >&2
    # This file is sourced; return aborts the sourcing script under set -e,
    # and the exit fallback covers a direct (non-sourced) invocation.
    return 2 2>/dev/null || exit 2
fi
