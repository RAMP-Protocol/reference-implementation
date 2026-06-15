#!/usr/bin/env bash
# check-jwt-in-exchange-authz.sh
#
# Enforces ADR-001 (docs/architecture/adr-001-three-layer-auth.md):
#   Exchange authz code paths (service/ + handler/transport/) MUST NOT read
#   JWT claims. Authz decisions come from Biscuit only.
#
# This script scans Exchange service and transport packages for imports of
# known JWT-parsing libraries and fails with a non-zero exit code if any are
# found without an explicit waiver comment.
#
# Waiver syntax (on the same line as, or the line immediately preceding,
# the import):
#
#   // adr-001-allow-jwt: <one-line justification for non-authz use>
#   import "github.com/lestrrat-go/jwx/v2/jwt"
#
# Exits 0 when clean, 1 when a violating import is found.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

targets=(
  "src/exchange/internal/service"
  "src/exchange/internal/transport"
)

# Denylisted JWT-parsing import paths. Extend this list as new JWT helpers
# appear in the codebase.
denylist=(
  "github.com/golang-jwt/jwt"
  "github.com/lestrrat-go/jwx"
  "github.com/coreos/go-oidc"
)

violations=0

for target in "${targets[@]}"; do
  dir="${repo_root}/${target}"
  [ -d "${dir}" ] || continue

  # iterate .go files (excluding _test.go if ever desired; here we check all)
  while IFS= read -r -d '' gofile; do
    for denied in "${denylist[@]}"; do
      # Find line numbers where the denied import appears.
      matches=$(grep -n "\"${denied}" "${gofile}" || true)
      [ -z "${matches}" ] && continue

      while IFS= read -r m; do
        lineno="${m%%:*}"
        # Check the waiver on the same line or the line immediately preceding.
        same_line=$(sed -n "${lineno}p" "${gofile}")
        prev_lineno=$((lineno - 1))
        prev_line=""
        if [ "${prev_lineno}" -ge 1 ]; then
          prev_line=$(sed -n "${prev_lineno}p" "${gofile}")
        fi

        if echo "${same_line}" | grep -q "adr-001-allow-jwt:" \
          || echo "${prev_line}" | grep -q "adr-001-allow-jwt:"; then
          continue
        fi

        echo "ADR-001 violation: JWT-parsing import in Exchange authz path"
        echo "  file: ${gofile}:${lineno}"
        echo "  import: ${denied}"
        echo "  line: ${same_line}"
        echo "  fix: remove the import, or add an 'adr-001-allow-jwt:' waiver"
        echo "       comment explaining why the read is NOT an authz input."
        echo ""
        violations=$((violations + 1))
      done <<< "${matches}"
    done
  done < <(find "${dir}" -type f -name "*.go" -print0)
done

if [ "${violations}" -gt 0 ]; then
  echo "ADR-001 check failed: ${violations} violation(s). See docs/architecture/adr-001-three-layer-auth.md"
  exit 1
fi

echo "ADR-001 check passed (no JWT-parsing imports in Exchange authz paths)."
exit 0
