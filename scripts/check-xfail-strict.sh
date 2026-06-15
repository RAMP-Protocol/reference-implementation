#!/usr/bin/env bash
# check-xfail-strict.sh
#
# Enforces ADR-008 D3 (docs/architecture/adr-008-testing-surface-isolation.md):
#   Tests that document a contract production has not yet implemented use
#   the strict xfail marker (pytest.mark.xfail(strict=True)). The lenient
#   form (strict=False) is forbidden across the codebase.
#
# This script scans tests/ for the literal token "strict=False" and fails
# with a non-zero exit code if any occurrence is found.
#
# Why a literal token rather than an AST query: the failure mode this gate
# guards against is forgetfulness, not subtle obfuscation. A grep is
# sufficient and runs in milliseconds even on a clean tree.
#
# Exits 0 when clean, 1 when a forbidden marker is found.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${repo_root}/tests"

if [[ ! -d "${target}" ]]; then
  echo "check-xfail-strict: tests/ directory not found at ${target}" >&2
  exit 1
fi

# Match the literal token. Limit the scan to .py files (so generated
# assets, lockfiles, and vendored archives cannot trigger) and exclude
# virtual-env, cache, and pytest-cache directories (third-party Python
# code inside .venv/ uses strict=False legitimately on stdlib calls
# like zip(strict=False) — those are not pytest.mark.xfail markers and
# are not the gate's concern).
matches="$(grep -rn --include='*.py' \
  --exclude-dir='.venv' \
  --exclude-dir='venv' \
  --exclude-dir='__pycache__' \
  --exclude-dir='.pytest_cache' \
  --exclude-dir='.mypy_cache' \
  --exclude-dir='.ruff_cache' \
  --exclude-dir='.tox' \
  --exclude-dir='node_modules' \
  --exclude-dir='*.egg-info' \
  'strict=False' "${target}" || true)"

if [[ -n "${matches}" ]]; then
  cat >&2 <<EOF
ADR-008 D3 violation — forbidden xfail(strict=False) under tests/:

${matches}

Fix: change strict=False to strict=True. If the test currently passes
under the strict marker, REMOVE the @pytest.mark.xfail decorator entirely
(the test has become an honest regression guard). See
docs/architecture/adr-008-testing-surface-isolation.md D3 for rationale.
EOF
  exit 1
fi

echo "==> ADR-008 D3 check (no xfail(strict=False) under tests/) passed"
