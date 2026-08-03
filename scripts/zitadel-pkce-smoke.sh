#!/usr/bin/env bash
# Zitadel PKCE smoke test — drives authorize → login → token against the Zitadel
# from docker-compose.yml, WITHOUT the Identity Service in the picture.
#
# It answers one question: is the local Zitadel provisioned and able to complete
# an authorization-code + PKCE flow? Run it before any browser walkthrough, so
# a failure there is unambiguous — this script passing means the fault is
# downstream, in the Identity Service.
#
# Scope is the LOCAL user only. Federated Google sign-in cannot be scripted (it
# redirects to Google's own consent UI), so it is verified by hand. The full
# sign-up round-trip THROUGH the Identity Service, including the registration
# form, is likewise out of scope here.
#
# Usage:
#   make zitadel-up
#   ./scripts/zitadel-pkce-smoke.sh
#
# Environment:
#   RAMP_ZITADEL_PORT   host port of the dev Zitadel (default 58080)
#   COMPOSE_PROJECT     compose project owning the bootstrap volume
#                       (default: the repo directory name)
#   REDIRECT_URI        must be a URI registered on the ramp-identity app
#                       (default http://localhost:8083/callback)
#   ALICE_USER/ALICE_PASS  local login (defaults alice@acme.local / Alice12345!)
#
# Exit codes:
#   0 success
#   1 the flow did not complete, or the token lacked the expected claims
#   2 unable to resolve client_id/secret from the bootstrap volume
set -euo pipefail

RAMP_ZITADEL_PORT="${RAMP_ZITADEL_PORT:-58080}"
ZITADEL_URL="${ZITADEL_URL:-http://localhost:$RAMP_ZITADEL_PORT}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8083/callback}"
ALICE_USER="${ALICE_USER:-alice@acme.local}"
ALICE_PASS="${ALICE_PASS:-Alice12345!}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-$(basename "$REPO_ROOT")}"

log() { printf '%s\n' "$*" >&2; }

CLIENT_ID=""
CLIENT_SECRET=""
resolve_client() {
    local vol="${COMPOSE_PROJECT}_zitadel-bootstrap"
    if ! docker volume inspect "$vol" >/dev/null 2>&1; then
        log "ERR: docker volume '$vol' not found. Run 'make zitadel-up' first."
        exit 2
    fi
    CLIENT_ID=$(docker run --rm -v "$vol:/b:ro" alpine:3.20 \
        cat /b/identity_client_id 2>/dev/null | tr -d '[:space:]')
    CLIENT_SECRET=$(docker run --rm -v "$vol:/b:ro" alpine:3.20 \
        cat /b/identity_client_secret 2>/dev/null | tr -d '[:space:]')
    if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
        log "ERR: client id/secret missing from $vol. Check 'make zitadel-up' output."
        exit 2
    fi
}

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

pkce_pair() {
    local v c
    v=$(openssl rand 32 | b64url)
    c=$(printf '%s' "$v" | openssl dgst -sha256 -binary | b64url)
    printf '%s\n%s\n' "$v" "$c"
}

jwt_payload() {
    local p
    p=$(printf '%s' "$1" | cut -d. -f2)
    case $(( ${#p} % 4 )) in
        2) p="${p}==" ;;
        3) p="${p}=" ;;
    esac
    printf '%s' "$p" | tr '_-' '/+' | openssl base64 -d -A 2>/dev/null
}

assert_claim() {
    local payload="$1" key="$2" expected="${3:-}"
    local val
    val=$(printf '%s' "$payload" | grep -o "\"$key\":\"[^\"]*\"" | head -n 1 | sed 's/^[^:]*:"//; s/"$//')
    if [ -z "$val" ]; then
        log "FAIL: claim '$key' absent or empty"
        return 1
    fi
    if [ -n "$expected" ] && [ "$val" != "$expected" ]; then
        log "FAIL: claim '$key' = '$val', want '$expected'"
        return 1
    fi
    log "OK: $key = $val"
}

# Extract a hidden input's value. Scans whole tags so attribute order does not matter.
extract_hidden() {
    printf '%s' "$1" | grep -o '<input[^>]*>' \
        | grep "name=\"$2\"" | head -n 1 \
        | grep -o 'value="[^"]*"' | sed 's/^value="//; s/"$//'
}
extract_action() {
    printf '%s' "$1" | grep -o '<form[^>]*action="[^"]*"' | head -n 1 \
        | sed 's/.*action="//; s/"$//'
}

smoke_alice() {
    log "===== $ALICE_USER (local) PKCE against $ZITADEL_URL ====="
    resolve_client
    local verifier challenge state jar
    { read -r verifier; read -r challenge; } < <(pkce_pair)
    state=$(openssl rand -hex 8)
    jar=$(mktemp)
    trap 'rm -f "$jar"' RETURN

    # 1. Authorize → the login-name form.
    local html csrf request_id action
    html=$(curl -sSL -c "$jar" -b "$jar" \
        "$ZITADEL_URL/oauth/v2/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20email%20profile&state=$state&code_challenge=$challenge&code_challenge_method=S256")
    csrf=$(extract_hidden "$html" "gorilla.csrf.Token")
    request_id=$(extract_hidden "$html" "authRequestID")
    action=$(extract_action "$html")
    if [ -z "$csrf" ] || [ -z "$request_id" ] || [ -z "$action" ]; then
        log "FAIL: could not parse the login-name form (csrf='$csrf' reqId='$request_id' action='$action')"
        log "      body head: $(printf '%s' "$html" | head -c 300)"
        return 1
    fi

    # 2. POST the login name. --data-urlencode is mandatory, not stylistic: the CSRF
    # token is base64 and its '+' would arrive as a space under plain -d, failing the
    # token check with a misleading "invalid request" page.
    local pw_html csrf2 action2
    pw_html=$(curl -sSL -c "$jar" -b "$jar" \
        --data-urlencode "gorilla.csrf.Token=$csrf" \
        --data-urlencode "authRequestID=$request_id" \
        --data-urlencode "loginName=$ALICE_USER" \
        "$ZITADEL_URL$action")
    csrf2=$(extract_hidden "$pw_html" "gorilla.csrf.Token")
    action2=$(extract_action "$pw_html")
    if [ -z "$csrf2" ] || [ -z "$action2" ]; then
        log "FAIL: could not parse the password form"
        log "      body head: $(printf '%s' "$pw_html" | head -c 300)"
        return 1
    fi

    # 3. POST the password, then follow the redirect chain to the redirect_uri.
    local url
    url=$(curl -sS -D - -o /dev/null -c "$jar" -b "$jar" \
        --data-urlencode "gorilla.csrf.Token=$csrf2" \
        --data-urlencode "authRequestID=$request_id" \
        --data-urlencode "password=$ALICE_PASS" \
        "$ZITADEL_URL$action2" \
        | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r' | head -n 1)

    local code="" hop=0
    while [ "$hop" -lt 15 ]; do
        hop=$((hop + 1))
        [ -n "$url" ] || break
        case "$url" in
            /*) url="$ZITADEL_URL$url" ;;
        esac
        case "$url" in
            "$REDIRECT_URI"*)
                code=$(printf '%s' "$url" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
                break
                ;;
        esac
        url=$(curl -sS -D - -o /dev/null -c "$jar" -b "$jar" "$url" \
            | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r' | head -n 1)
    done
    if [ -z "$code" ]; then
        log "FAIL: never reached $REDIRECT_URI with ?code= (last url='$url')"
        return 1
    fi
    log "authorization code obtained"

    # 4. Exchange it — confidential client, so HTTP Basic plus the PKCE verifier.
    local resp access id_token
    resp=$(curl -sS -X POST "$ZITADEL_URL/oauth/v2/token" \
        -u "$CLIENT_ID:$CLIENT_SECRET" \
        --data-urlencode "grant_type=authorization_code" \
        --data-urlencode "code=$code" \
        --data-urlencode "redirect_uri=$REDIRECT_URI" \
        --data-urlencode "code_verifier=$verifier")
    access=$(printf '%s' "$resp" | grep -o '"access_token":"[^"]*"' | sed 's/^[^:]*:"//; s/"$//')
    id_token=$(printf '%s' "$resp" | grep -o '"id_token":"[^"]*"' | sed 's/^[^:]*:"//; s/"$//')
    if [ -z "$access" ]; then
        log "FAIL: token response carried no access_token: $resp"
        return 1
    fi
    if [ -z "$id_token" ]; then
        log "FAIL: token response carried no id_token"
        return 1
    fi

    # Zitadel's JWT access token carries sub/aud/iss/client_id; the identity claims
    # (email, name) live in the id_token per OIDC. Assert each where it belongs.
    assert_claim "$(jwt_payload "$access")" sub
    assert_claim "$(jwt_payload "$id_token")" sub
    assert_claim "$(jwt_payload "$id_token")" email "$ALICE_USER"
    log "PASS: Zitadel completes authorization-code + PKCE"
}

smoke_alice
