#!/usr/bin/env bash
# check-xfail-strict.sh
#
# Enforces ADR-008 D3 (docs/architecture/adr-008-testing-surface-isolation.md):
#   Tests that document a contract production has not yet implemented use the
#   strict xfail marker (pytest.mark.xfail(strict=True)). The lenient form
#   (strict=False) is forbidden under tests/.
#
# Thin entrypoint kept for Makefile/CI compatibility (make adr-008-d3-check).
# The check itself is AST-based — see scripts/check_xfail_strict.py — so it
# flags ONLY a call to xfail carrying strict=False, never an unrelated kwarg
# (a helper's own `strict` parameter) or the token inside a docstring, and it
# catches the multi-line marker form a single-line grep would miss.
#
# Exits 0 when clean, 1 when a forbidden marker is found, 2 on a parse error.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${repo_root}/scripts/check_xfail_strict.py"
