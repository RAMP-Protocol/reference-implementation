#!/usr/bin/env bash
# check-image-version.sh
#
# Structural guard against the published container image version drifting apart
# across the deployment documents.
#
# Those documents used to name the version twelve times — four per service, in
# the pull command, the digest lookup, the local build, and the compose snippet.
# A release meant twelve edits, and a partial edit is silent: a document naming a
# tag nobody published sends the operator to a "not found", which is the exact
# defect the documents were rewritten to remove. They now declare it once each,
# and every command in the document reuses that variable.
#
# What this enforces:
#   1. only sanctioned tag forms on a ghcr.io/ramp-protocol image in any TRACKED
#      file under the scanned roots. Every tagged reference is collected and the
#      sanctioned forms are subtracted from it, so a tag nobody anticipated is
#      reported rather than accepted. The sanctioned set is :$VERSION or
#      :${VERSION} inside a document that declares it, :dev for a local build,
#      and @sha256: to pin the content. Enumerating the forbidden shapes instead
#      is what used to let :latest and :v1.0.0 pass — the first is ruled out by
#      name in ADR-024 D2, and the second can never resolve, because the leading
#      v is stripped before the tag reaches the registry. This is the rule that
#      keeps the reduction from being undone one line at a time. Tracked only,
#      because a working copy holds drafts and scratch notes that never ship, and
#      failing a build over one of those would be an alarm about a file nobody
#      publishes;
#   2. exactly one VERSION= declaration per deployment document — none means the
#      reduction was reverted, two means it half was;
#   3. all three documents declaring the same value, which is the partial update
#      this guard exists to catch.
#
# What it does NOT do: it is offline, so it cannot know whether the declared
# version was ever published, or whether it matches the git tag the workflow
# builds from. It sees drift inside this repository and nothing about the
# registry. ADR-024 D2 is the authority for the tag shape assumed here.
#
# It asserts AGREEMENT and never a particular version, so it stays correct across
# every future release without being edited.
#
# `--root <dir>` scans a tree other than this checkout; the guard's own tests use
# it to drive synthetic trees. It is an ARGUMENT and not an environment variable
# on purpose: an ambient variable that selects what a gate reads can redirect it
# while it still reports PASS.
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

cd "${repo_root}"

# The three services that ship an image. The publishing workflow enumerates the
# same three in its build matrix; a fourth service would have to be added in both
# places, and the missing-document check below is what surfaces the omission here.
DOCS=(
  src/exchange/DEPLOYMENT.md
  src/broker/DEPLOYMENT.md
  src/identity/DEPLOYMENT.md
)

# scripts/ is deliberately absent: rule 1 has to spell out the string it forbids,
# so a gate that scanned its own directory would fail on itself.
SCAN_ROOTS=( src docs deploy .github )

failures=0

fail() {
  echo "FAIL  $1"
  failures=$((failures + 1))
}

for d in "${DOCS[@]}"; do
  [ -f "${d}" ] || die "deployment document missing from the tree: ${d}
      This guard reads the version from each one; a document it cannot find is a
      check it silently loses."
done

for r in "${SCAN_ROOTS[@]}"; do
  [ -e "${r}" ] || die "scan root missing from the tree: ${r}
      Restore the path, or narrow SCAN_ROOTS in this script to match the tree."
done

# ----- 1. No literal version tag on a published image -----
#
# TRACKED files only, the way the secrets gate reads them. A working copy holds
# scratch notes and drafts that never ship, and failing the build over a version
# string in one of those would be a false alarm about a file nobody publishes.
git -C "${repo_root}" rev-parse --git-dir >/dev/null 2>&1 \
  || die "not a git repository: ${repo_root}
      This guard reads the tracked file list, so it has no way to tell a shipped
      document from a scratch file without one."

# The list goes through a file rather than a variable. Command substitution
# strips NUL bytes, so `$(git ls-files -z)` silently concatenates every path into
# one — measured, and it turns the scan into a grep for a single nonexistent
# filename that reports the tree clean.
list_file="$(mktemp)" || die "could not create a temporary file for the tracked list"
trap 'rm -f "${list_file}"' EXIT

git -C "${repo_root}" ls-files -z -- "${SCAN_ROOTS[@]}" > "${list_file}" \
  || die "could not list tracked files under the scan roots"

# A read loop, not mapfile: macOS ships bash 3.2 as /bin/bash, and mapfile
# arrived in bash 4 — the gate (and its harness tests) must run there too.
tracked=()
while IFS= read -r -d '' tracked_path; do
  tracked+=("${tracked_path}")
done < "${list_file}"
[ "${#tracked[@]}" -gt 0 ] || die "no tracked files under the scan roots — nothing was
      read, so a PASS here would mean nothing."

# -H because grep omits the filename when handed exactly one path, and a
# violation reported as a bare line number names nothing. -o because the
# subtraction below is line-oriented: without it, one line naming two images
# would be dropped whole the moment either reference was sanctioned, and the
# other would go unread.
#
# The digest form never reaches that subtraction. @sha256: puts an @ where this
# pattern requires a colon, so it does not match here at all — which is why the
# filter below names every sanctioned form except that one.
#
# grep exits 1 when it matches nothing, which is the ordinary case here, so the
# status is captured and checked rather than allowed to abort the run. Anything
# above 1 is grep failing, which is not the same as a clean tree.
set +e
tagged="$(grep -HnoEI 'ghcr\.io/ramp-protocol/[a-z][a-z-]*:[A-Za-z0-9._${}-]+' -- "${tracked[@]}")"
grep_status=$?
set -e
[ "${grep_status}" -le 1 ] || die "the image-reference scan itself failed (grep exit ${grep_status}) — no conclusion can be drawn"

# Braces written as bracket expressions rather than \{ and \}, whose meaning in
# an ERE is implementation-defined. This gate ships to a public clone whose grep
# we do not choose.
#
# Anchored, so the sanctioned form has to be the WHOLE tag: :development is not
# :dev, and :$VERSION-amd64 is reported too. The second one is deliberate rather
# than an oversight — ADR-024 D3 publishes one architecture and no manifest, so
# there is no per-architecture tag for that suffix to name. The day that changes,
# this line changes with it.
#
# The set tracks a decision rather than a shape, so it moves when the decision
# does: ADR-024 D2 allows a :latest to be introduced later, once there is a
# release history for it to point at, and the day that happens this line is part
# of the change.
unsanctioned=""
if [ -n "${tagged}" ]; then
  # `set +e` suspends the errexit, not the pipefail set at the top of this file,
  # so this is the PIPELINE's status: printf failing would surface here too, and
  # that is wanted. grep's own 1 means every reference was sanctioned, which is
  # the ordinary case and not an error.
  set +e
  unsanctioned="$(printf '%s\n' "${tagged}" | grep -vE ':(\$VERSION|\$[{]VERSION[}]|dev)$')"
  filter_status=$?
  set -e
  [ "${filter_status}" -le 1 ] || die "the sanctioned-form filter itself failed (exit ${filter_status}) — no conclusion can be drawn"
fi

if [ -n "${unsanctioned}" ]; then
  fail "unsanctioned image tag(s):"
  printf '%s\n' "${unsanctioned}" | sed 's/^/      /'
  echo ""
  echo "      A literal version pins a tag a release would have to find and edit,"
  echo "      and :latest names an image that is never published. Use :\$VERSION"
  echo "      inside a document that declares it, :dev for a local build, or"
  echo "      @sha256: to pin the content."
fi

# ----- 2 and 3. One declaration per document, and all three agreeing -----
#
# The values are collected quietly and reported only when they disagree. A clean
# run says what they agreed on once, at the end; printing all three every time
# would bury the one line that carries information.
declared=""
listing=""
for d in "${DOCS[@]}"; do
  count="$(grep -c '^VERSION=' "${d}" || true)"
  if [ "${count}" != "1" ]; then
    fail "${d}: ${count} VERSION= declaration(s), expected exactly 1"
    continue
  fi
  value="$(sed -n 's/^VERSION=//p' "${d}")"
  declared="${declared}${value}"$'\n'
  listing="${listing}      ${d}: ${value}"$'\n'
done

if [ "${failures}" -eq 0 ]; then
  distinct="$(printf '%s' "${declared}" | sort -u | grep -c '' || true)"
  if [ "${distinct}" != "1" ]; then
    fail "the deployment documents declare ${distinct} different versions:"
    printf '%s' "${listing}"
    echo "      A release edits all three. One left behind names an image that was"
    echo "      never published."
  fi
fi

echo ""
if [ "${failures}" -gt 0 ]; then
  echo "image-version guard: ${failures} failure(s). Fix the above before merging."
  exit 1
fi

echo "PASS  the deployment documents agree on one image version ($(printf '%s' "${declared}" | head -1))"
echo "image-version guard: all checks passed."
exit 0
