#!/usr/bin/env python3
"""Enforce per-language file-length caps from CLAUDE.md (Code Hygiene section).

Exits non-zero if any non-generated file exceeds its cap. No warnings — every
violation is an error.
"""

from __future__ import annotations

import fnmatch
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Caps for source files (non-test).
SRC_CAPS: dict[str, int] = {
    "**/*.go": 500,
    "**/*.py": 500,
    "**/*.ts": 400,
}

# Test files: uniform cap regardless of language.
TEST_CAP = 800
TEST_GLOBS = [
    "**/*_test.go",
    "**/*.test.ts",
    "**/test_*.py",
    "**/tests/**/*.py",
    "**/tests/**/*.ts",
    "**/__tests__/**/*.ts",
]

# Generated / vendored / virtualenv paths that are exempt.
EXCLUDE_GLOBS = [
    "**/node_modules/**",
    "**/.venv/**",
    "**/__pycache__/**",
    "**/.ruff_cache/**",
    "**/.mypy_cache/**",
    "**/.pytest_cache/**",
    "**/dist/**",
    "**/.wrangler/**",
    "**/.gocache/**",
    "**/internal/db/sqlc/**",
    "**/*.pb.go",
    "**/*connect.go",
    "**/*_pb.ts",
    "**/_pb.ts",
    "**/.git/**",
    "pkg/reporting/**",    # legacy experimental code
]

# Only walk these directories (demo production code).
# scripts/ is excluded — legacy piarch derivation tooling lives there.
INCLUDE_ROOTS = [
    "src",
    "internal",
]


def matches_any(path: Path, globs: list[str]) -> bool:
    rel = str(path.relative_to(REPO_ROOT))
    return any(fnmatch.fnmatch(rel, g) for g in globs)


def is_test_file(path: Path) -> bool:
    return matches_any(path, TEST_GLOBS)


def cap_for(path: Path) -> int | None:
    if is_test_file(path):
        return TEST_CAP
    for pattern, cap in SRC_CAPS.items():
        if fnmatch.fnmatch(path.name, pattern.split("/")[-1]):
            return cap
    return None


def line_count(path: Path) -> int:
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def iter_files() -> list[Path]:
    files: list[Path] = []
    for root in INCLUDE_ROOTS:
        root_path = REPO_ROOT / root
        if not root_path.exists():
            continue
        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if matches_any(path, EXCLUDE_GLOBS):
                continue
            if cap_for(path) is None:
                continue
            files.append(path)
    return files


def main() -> int:
    violations: list[tuple[Path, int, int]] = []
    for path in iter_files():
        cap = cap_for(path)
        if cap is None:
            continue
        lines = line_count(path)
        if lines > cap:
            violations.append((path, lines, cap))

    if violations:
        print("FAIL: file-length cap exceeded (see CLAUDE.md § Code Hygiene):", file=sys.stderr)
        for path, lines, cap in violations:
            rel = path.relative_to(REPO_ROOT)
            label = "test" if is_test_file(path) else "src"
            print(f"  [{label}] {rel}: {lines} lines (cap {cap})", file=sys.stderr)
        return 1

    scanned = len(iter_files())
    print(f"file-length check: {scanned} files scanned, all within caps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
