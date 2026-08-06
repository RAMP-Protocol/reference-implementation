#!/usr/bin/env bash
# check-published-refs.sh
#
# Structural guard against unresolvable cross-references in the published tree.
#
# src/, internal/, tests/, testdata/, deploy/, schemas/, docs/architecture/, the
# root build files, a curated scripts/ set and a curated set of individual docs/
# files are published verbatim to the public reference implementation. A file
# inside that set must not point at anything outside it: the reader cannot open
# it.
#
# What this catches:
#   - any docs/ path that does not travel, WITH or WITHOUT the docs/ prefix
#     (a bare `design-exchange.md §4` is the same violation, and is the form a
#     naive `grep docs/` misses). docs/architecture/ travels as a subtree; the
#     files named in ALLOW_DOC_FILES and INHERIT_FROM_MAIN travel one by one, and
#     citing any of those is legal
#   - CLAUDE.md, AGENTS.md, .claude/, .beads/, .gitlab-ci.yml
#   - the beads tracker and GitLab merge requests (MR !2)
#   - other repositories (currently the piarch pattern only; the pi-terraform
#     pattern is added when the old-demo ops scripts that still name it are
#     deleted — until then it would flag those known mentions on every run)
#   - absolute developer paths (/Users/..., /home/...)
#   - the vendored in-tree copy of ramp.proto, which no longer exists — the
#     protocol is the pinned module github.com/RAMP-Protocol/protocol. A bare
#     `ramp.proto` is NOT flagged: it is legitimate wherever the surrounding text
#     names that module, which is how the ADRs cite it.
#
# What it does NOT catch, and is reviewer-enforced instead: bare commit SHAs.
# A pattern broad enough to find them also matches content hashes, key
# thumbprints and conformance vectors, so gating on it would be noise.
#
# The search roots are DERIVED from scripts/published-paths.sh — the same file
# the publish tool reads to decide what ships. They were once a hand-kept second
# copy, and the two drifted: ten of the eleven published root files were never
# scanned at all, so a dangling pointer in docker-compose.yml passed clean.
#
# Deliberate exceptions take a `published-ref-allow: <reason>` comment on the
# same line or the line immediately preceding.
#
# `--root <dir>` scans a tree other than this checkout; the guard's own tests use
# it to drive synthetic trees. It is an ARGUMENT and not an environment variable
# on purpose: the publish tool runs this gate over the tree it is about to push,
# and an ambient variable could have redirected that run to a different tree
# while it reported PASS.
#
# Exits 0 when clean, 1 otherwise.

set -euo pipefail

die() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root=""

while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      [ $# -ge 2 ] || die "--root requires a directory"
      repo_root="$(cd "$2" && pwd)" || die "--root: no such directory: $2"
      shift 2
      ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ -n "${repo_root}" ] || repo_root="$(cd "${script_dir}/.." && pwd)"

# shellcheck source=scripts/published-paths.sh
source "${script_dir}/published-paths.sh"

# `.gitignore` and `.dockerignore` are published, but their entries NAME the
# unpublished paths on purpose — that is configuration, not a citation, and the
# rule exempts it explicitly. Scanning them would report every ignore line as a
# violation.
CONFIG_NOT_CITATIONS=( .gitignore .dockerignore )

# The search roots ARE the published set: the directories, every allowlisted
# docs/ file, the root build files, and every allowlisted script by name.
#
# Naming the scripts individually rather than scanning scripts/ wholesale is what
# retires the prefix denylist that used to stand in for "not published". That
# denylist was an approximation of the complement of ALLOW_SCRIPTS and it failed
# in both directions — a published gate whose name happened to start with a
# skipped prefix was never scanned, and an unpublished tool whose name did not
# reddened `make quality` for a file that never ships.
#
# Consequence worth knowing: every allowlisted script is now a required search
# root, so deleting one without updating published-paths.sh fails this gate. That
# is the intent — the publish would otherwise ship a tree missing a file it
# promises.
SEARCH_ROOTS=( "${ALLOW_DIRS[@]}" "${ALLOW_DOC_FILES[@]}" )
for f in "${ALLOW_ROOT_FILES[@]}"; do
  skip=0
  for c in "${CONFIG_NOT_CITATIONS[@]}"; do [ "$f" = "$c" ] && skip=1; done
  [ "$skip" -eq 0 ] && SEARCH_ROOTS+=("$f")
done
SEARCH_ROOTS+=( "${ALLOW_SCRIPTS[@]}" )

# --- Patterns ---------------------------------------------------------------
unpublished_docs_alt="$(printf '%s|' "${UNPUBLISHED_DOC_DIRS[@]}")"
# The publish tool and its working notes. A published file naming one sends the
# reader to something that is deliberately absent from their tree — the same
# failure as a docs/ path that does not travel, one file class further out.
local_only_alt="$(printf '%s\n' "${LOCAL_ONLY_FILES[@]}" | sed 's/\./\\./g' | paste -sd'|' -)"
PATTERNS=(
  "docs/(${unpublished_docs_alt%|})/"
  "\\b(${local_only_alt})\\b"
  '\bCLAUDE\.md\b'
  '\bAGENTS\.md\b'
  '\.claude/'
  '\.gitlab-ci\.yml'
  '\bbeads\b'
  'MR !'
  '\bpiarch\b'
  '/(Users|home)/[a-z]'
  'proto/ramp/v1/ramp\.proto'
)

# Bare basenames of every unpublished doc, derived from the tree so the list
# maintains itself. In a clone that has no unpublished docs/ (the public repo)
# this contributes nothing and the patterns above still apply.
#
# `-printf` is a GNU extension and this gate ships to a public repo, so the
# basename comes from sed instead: on BSD find the whole assignment failed under
# `set -e` with stderr muted, taking `make quality` down with no output at all.
#
# ALLOW_DOC_FILES and INHERIT_FROM_MAIN are both subtracted, because both end up
# on the public tree and citing either is therefore resolvable. They get there by
# different routes — the publish stages an ALLOW_DOC_FILES entry out of this tree
# and takes an INHERIT_FROM_MAIN entry from the public base — but the find below
# sweeps in every docs/*.md outside docs/architecture regardless of route, so
# without this subtraction it would reject a citation of a file it just shipped.
# That is exactly what happened to docs/HANDOFF-aws-demo.md before the inherited
# half of this was added.
bare_docs=""
if [ -d "${repo_root}/docs" ]; then
  published_docs="$(printf '%s\n' "${ALLOW_DOC_FILES[@]}" "${INHERIT_FROM_MAIN[@]}" \
      | sed 's#.*/##; s/\.md$//' | sort -u)"
  # `grep -v` exits 1 when nothing survives the filter, which here is the ordinary
  # "no unpublished docs" case (a public clone) rather than an error — tolerate it
  # explicitly instead of letting `set -e` abort the whole gate.
  bare_docs="$(find "${repo_root}/docs" -name '*.md' -not -path '*/docs/architecture/*' \
      | sed 's#.*/##; s/\.md$//' | sort -u \
      | { grep -vxF "${published_docs}" || true; } | paste -sd'|' -)"
fi
if [ -n "${bare_docs}" ]; then
  PATTERNS+=("\\b(${bare_docs})\\.md\\b")
fi

combined="$(printf '%s|' "${PATTERNS[@]}")"
combined="${combined%|}"

# --- Scan -------------------------------------------------------------------
cd "${repo_root}"

# Every search root must exist. A renamed or removed top-level directory used to
# leave grep writing "No such file or directory" into a muted stderr while
# `|| true` swallowed its exit status — the gate then printed PASS having read
# nothing at all. A green run has to mean something was actually read.
missing_roots=""
for r in "${SEARCH_ROOTS[@]}"; do
  [ -e "${r}" ] || missing_roots="${missing_roots} ${r}"
done
[ -z "${missing_roots}" ] \
  || die "search root(s) missing from the tree:${missing_roots}
      This gate scans the published path set; a root it cannot find is coverage
      it silently loses. Restore the path, or update scripts/published-paths.sh."

# grep's exit status carries three distinct meanings and they must not be
# collapsed: 0 = matches found, 1 = clean, >=2 = the scan itself failed.
#
# -I skips binary files: they cannot carry a citation, and without it the local
# lint/type caches report "binary file matches" on every run. The excluded dirs
# are all gitignored build output, so none of them is ever published.
set +e
hits="$(grep -rnEI "${combined}" "${SEARCH_ROOTS[@]}" \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist \
    --exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=.wrangler \
    --exclude-dir=.ruff_cache --exclude-dir=.mypy_cache --exclude-dir=.pytest_cache)"
grep_status=$?
set -e
[ "${grep_status}" -le 1 ] || die "the reference scan itself failed (grep exit ${grep_status}) — no conclusion can be drawn"

violations=""
while IFS= read -r hit; do
  [ -z "${hit}" ] && continue
  file="${hit%%:*}"
  rest="${hit#*:}"
  lineno="${rest%%:*}"

  # This script states the patterns it forbids, so it matches itself. Same
  # narrow exemption CLAUDE.md makes for rule text that must show the format it
  # mandates.
  [ "${file}" = "scripts/check-published-refs.sh" ] && continue

  # A waiver on this line or the one above suppresses the hit.
  same="$(sed -n "${lineno}p" "${file}" 2>/dev/null || true)"
  prev=""
  [ "${lineno}" -gt 1 ] && prev="$(sed -n "$((lineno - 1))p" "${file}" 2>/dev/null || true)"
  case "${same}${prev}" in
    *published-ref-allow:*) continue ;;
  esac

  violations+="${hit}"$'\n'
done <<< "${hits}"

violations="$(printf '%s' "${violations}" | sed '/^$/d')"

if [ -n "${violations}" ]; then
  count="$(printf '%s\n' "${violations}" | grep -c '' || true)"
  echo "FAIL  ${count} unresolvable reference(s) in the published tree:"
  printf '%s\n' "${violations}" | sed 's/^/      /'
  echo ""
  echo "      Each line points at something a public reader cannot open."
  echo "      Describe the substance directly instead of pointing at it, and leave"
  echo "      a complete sentence. A deliberate exception takes a"
  echo "      'published-ref-allow: <reason>' comment on the same or preceding line."
  echo ""
  echo "published-refs guard: fix the references above before merging."
  exit 1
fi

echo "PASS  no unresolvable references in the published tree"
echo "published-refs guard: all checks passed."
exit 0
