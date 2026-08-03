#!/usr/bin/env bash
# check-sdk-pin-consistency.sh
#
# Structural guard: the RAMP protocol/SDK git pins must not split-brain.
# The SDK is ONE repository (github.com/RAMP-Protocol/protocol) consumed by
# git rev from several manifests; a partial bump or an unrefreshed lockfile
# silently runs different SDK revisions in different components, which is
# exactly the disease this guard pins shut. It asserts REV-AGREEMENT, never a
# specific SHA literal, so it stays valid across future re-pins.
#
# Invariants enforced:
#   1. tests/e2e/pyproject.toml pins TWO git deps from the protocol repo
#      (ramp-protocol @ gen/python, ramp-protocol-sdk @ sdk/python) — their
#      revs must be byte-identical. ramp_sdk.acceptance imports wire.models, so
#      a split between the two means the harness signs one payload shape while
#      the services verify another. (This pair used to live in the Python MCP
#      shim; the shim is gone — the MCP surface is the Go adapter — so the
#      harness is now the only Python consumer.)
#   3. Each uv.lock resolves every RAMP-Protocol/protocol.git source at the
#      rev its own pyproject pins (lock refreshed after every re-pin).
#   4. Each package.json @ramp-protocol/sdk-l1 git pin equals every rev its
#      package-lock.json resolves for the protocol repo (lock refreshed
#      after every re-pin; `npm ci` installs the LOCK's rev, so a drifted
#      lock ships a different SDK than the manifest claims).
#   5. Cross-language manifest uniformity: the Python rev and both TS revs
#      must all be equal. SDK re-pins are uniform across languages (commit
#      pattern "chore(deps): re-pin the SDK to <sha> across Go/Python/TS");
#      per-language drift reintroduces split-brain SDK behavior. (go.mod is
#      excluded: its pseudo-version encodes only a 12-char prefix and may
#      legitimately become a tagged release; Go currency is checked by the
#      re-pin sweep, not this guard.)
#
# Exits 0 when all pins agree, 1 otherwise.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

fail() {
    echo "FAIL  $1"
    failures=$((failures + 1))
}

pass() {
    echo "PASS  $1"
}

# Extract the rev of a named git dep from a pyproject.toml [tool.uv.sources]
# line: `name = { git = ".../RAMP-Protocol/protocol.git", ..., rev = "<sha>" }`
pyproject_rev() {
    local file="$1" dep="$2"
    grep -E "^${dep} = \{.*RAMP-Protocol/protocol" "${file}" \
        | grep -oE 'rev = "[0-9a-f]{40}"' \
        | grep -oE '[0-9a-f]{40}' \
        | head -1
}

# All distinct 40-hex revs a lockfile records for the protocol repo
# (uv.lock: `rev=<sha>` query params + `#<sha>` fragments;
#  package-lock.json: `#<sha>` in both the dependency spec and `resolved`).
lock_revs() {
    local file="$1"
    grep -oE 'RAMP-Protocol/protocol\.git[^"]*' "${file}" \
        | grep -oE '[0-9a-f]{40}' \
        | sort -u
}

# The @ramp-protocol/sdk-l1 pin rev in a package.json.
package_json_rev() {
    local file="$1"
    grep -E '"@ramp-protocol/sdk-l1"' "${file}" \
        | grep -oE '#[0-9a-f]{40}' \
        | grep -oE '[0-9a-f]{40}' \
        | head -1
}

require_nonempty() {
    local value="$1" what="$2"
    if [ -z "${value}" ]; then
        fail "${what}: pin not found (guard needs updating if the pin moved)"
        return 1
    fi
}

# ----- 1+2. Python manifest rev uniformity -----
# `|| true`: a missing pin must reach require_nonempty's FAIL, not trip
# set -e/pipefail inside the extraction pipeline and abort silently.
e2e_proto_rev="$(pyproject_rev "${repo_root}/tests/e2e/pyproject.toml" 'ramp-protocol' || true)"
e2e_sdk_rev="$(pyproject_rev "${repo_root}/tests/e2e/pyproject.toml" 'ramp-protocol-sdk' || true)"

require_nonempty "${e2e_proto_rev}" "tests/e2e/pyproject.toml ramp-protocol" || true
require_nonempty "${e2e_sdk_rev}" "tests/e2e/pyproject.toml ramp-protocol-sdk" || true

if [ -n "${e2e_proto_rev}" ] && [ -n "${e2e_sdk_rev}" ]; then
    if [ "${e2e_proto_rev}" = "${e2e_sdk_rev}" ]; then
        pass "tests/e2e/pyproject.toml: ramp-protocol rev == ramp-protocol-sdk rev (${e2e_sdk_rev})"
    else
        fail "tests/e2e/pyproject.toml: ramp-protocol rev ${e2e_proto_rev} != ramp-protocol-sdk rev ${e2e_sdk_rev}"
    fi
fi

# ----- 3. uv.lock agrees with its pyproject -----
check_uv_lock() {
    local lock="$1" expected="$2" label="$3"
    [ -n "${expected}" ] || return 0
    local revs stale
    revs="$(lock_revs "${repo_root}/${lock}" || true)"
    if [ -z "${revs}" ]; then
        fail "${lock}: no RAMP-Protocol/protocol entries found (guard needs updating if the dep moved)"
        return 0
    fi
    stale="$(echo "${revs}" | grep -v "^${expected}$" || true)"
    if [ -n "${stale}" ]; then
        fail "${lock}: resolves rev(s) $(echo "${stale}" | tr '\n' ' ')but ${label} pins ${expected} — rerun 'uv lock'"
    else
        pass "${lock}: all protocol revs match ${label} pin (${expected})"
    fi
}

check_uv_lock "tests/e2e/uv.lock" "${e2e_sdk_rev}" "tests/e2e/pyproject.toml"

# ----- 4. package-lock.json agrees with its package.json -----
# Sets the global npm_manifest_rev (no subshell: `failures` must accumulate
# in the main shell).
npm_manifest_rev=""
check_npm_pair() {
    local dir="$1"
    local revs stale
    npm_manifest_rev="$(package_json_rev "${repo_root}/${dir}/package.json" || true)"
    require_nonempty "${npm_manifest_rev}" "${dir}/package.json @ramp-protocol/sdk-l1" || return 0
    revs="$(lock_revs "${repo_root}/${dir}/package-lock.json" || true)"
    if [ -z "${revs}" ]; then
        fail "${dir}/package-lock.json: no RAMP-Protocol/protocol entries found (guard needs updating if the dep moved)"
        return 0
    fi
    stale="$(echo "${revs}" | grep -v "^${npm_manifest_rev}$" || true)"
    if [ -n "${stale}" ]; then
        fail "${dir}: package-lock.json resolves rev(s) $(echo "${stale}" | tr '\n' ' ')but package.json pins ${npm_manifest_rev} — rerun 'npm install'"
    else
        pass "${dir}: package-lock.json matches package.json pin (${npm_manifest_rev})"
    fi
}

check_npm_pair "src/edge"
edge_rev="${npm_manifest_rev}"
check_npm_pair "tests/e2e/fastly-edge"
fastly_rev="${npm_manifest_rev}"

# ----- 5. Cross-language manifest uniformity (Python vs TS) -----
if [ -n "${e2e_sdk_rev}" ] && [ -n "${edge_rev}" ] && [ -n "${fastly_rev}" ]; then
    if [ "${e2e_sdk_rev}" = "${edge_rev}" ] && [ "${e2e_sdk_rev}" = "${fastly_rev}" ]; then
        pass "cross-language manifests agree: Python + src/edge + fastly-edge all pin ${e2e_sdk_rev}"
    else
        fail "cross-language pin split-brain: Python=${e2e_sdk_rev} src/edge=${edge_rev} fastly-edge=${fastly_rev} — re-pin uniformly"
    fi
fi

# ----- Result -----
echo ""
if [ "${failures}" -gt 0 ]; then
    echo "SDK pin guard: ${failures} failure(s). Re-pin uniformly and refresh every lockfile."
    exit 1
fi

echo "SDK pin guard: all pins agree."
exit 0
