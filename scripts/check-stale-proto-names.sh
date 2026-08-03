#!/usr/bin/env bash
# check-stale-proto-names.sh
#
# Structural guard against the pre-unification proto message names.
#
# `RAMPRequest` / `RAMPResponse` were renamed to `DiscoveryRequest` /
# `DiscoveryResponse` when the discovery messages were unified. Identifier-level
# references are already caught by the compiler at the pinned protocol module;
# this catches the compiler-blind form — doc comments and other prose, which
# quietly teach the old vocabulary to the next reader.
#
# Whole-tree, not just the sites that carried the names when the rename landed:
# a comment reintroducing them in a NEW file must fail the same way.
#
# Exits 0 when no stale name is present, 1 otherwise.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

stale=$(grep -rn --include='*.go' --include='*.ts' --include='*.py' \
    -E '\bRAMP(Request|Response)\b' \
    "${repo_root}/src" "${repo_root}/internal" "${repo_root}/tests" 2>/dev/null \
    | grep -v node_modules || true)

if [ -n "${stale}" ]; then
    echo "FAIL  stale RAMPRequest/RAMPResponse references (renamed DiscoveryRequest/DiscoveryResponse):"
    echo "${stale}" | sed 's/^/      /'
    echo ""
    echo "stale-proto-names guard: fix the references above before merging."
    exit 1
fi

echo "PASS  no RAMPRequest/RAMPResponse references anywhere in src/ internal/ tests/"
echo "stale-proto-names guard: all checks passed."
exit 0
