#!/usr/bin/env sh
# Zitadel bootstrap — provisions a freshly initialised Zitadel for the Identity
# Service's developer sign-up flow. Run once on top of `start-from-init`.
#
# Provisions, in order:
#   1. project `ramp`
#   2. an org login policy with MFA off and external IdPs allowed
#   3. the confidential OIDC app `ramp-identity` — the Identity Service's own
#      upstream client. The MCP client gets none; it self-registers over DCR.
#   4. the local user alice@acme.local, so the flow works without Google
#   5. Google as a federated IdP, AND the login-policy link that renders it
#
# internal/testutil/zitadelbootstrap.go is a SECOND implementation of this, for the
# `zitadel` test tier. A change here does not reach it: they differ in app name,
# redirect URI, and whether Google federation is configured.
#
# Inputs (env):
#   ZITADEL_BASE_URL       Base URL to reach the API (default http://zitadel:8080)
#   ZITADEL_INSTANCE_HOST  Host header — Zitadel routes instances by it, and it must
#                          match ExternalDomain, not the address dialled
#                          (default localhost)
#   ZITADEL_ISSUER         Externally reachable issuer, used only for the printed
#                          exports (default http://localhost:58080)
#   ZITADEL_PAT_FILE       PAT written by FirstInstance (default /bootstrap/zadmin.pat)
#   ZITADEL_PAT            PAT value, overriding the file — for running off-volume
#   IDENTITY_AUTH_ISSUER   Identity Service's own issuer; its /callback becomes the
#                          app's redirect URI (default http://localhost:8083)
#   EXTRA_REDIRECT_URIS    Additional space-separated redirect URIs (optional)
#   ALICE_PASSWORD         Local user's password (default Alice12345!)
#   GOOGLE_CLIENT_ID       Google OAuth client id — omit to skip federation
#   GOOGLE_CLIENT_SECRET   Google OAuth client secret — omit to skip federation
#   OUT_DIR                Where the client id/secret are written (default /bootstrap)
#
# Usage:
#   zitadel-bootstrap.sh                  provision, then print the exports
#   zitadel-bootstrap.sh --emit-exports   print an earlier run's exports and exit,
#                                         touching neither Zitadel nor the PAT.
#                                         This is what `make zitadel-creds` runs —
#                                         the wire format lives here only.
#
# Outputs:
#   $OUT_DIR/identity_client_id, $OUT_DIR/identity_client_secret
#   `export ...` lines on STDOUT (all logging goes to stderr, so `eval` is safe)
#
# Idempotency: re-running against a fully bootstrapped instance is safe — every
# step tolerates AlreadyExists, and the client secret is regenerated (Zitadel
# returns a secret only on create/regenerate, never on read). It is NOT safe
# against a partially completed run; wipe the volumes and start over.
#
# Exit codes: 0 ok, 1 provisioning failure, 2 bad input / unreachable Zitadel.
set -eu

BASE="${ZITADEL_BASE_URL:-http://zitadel:8080}"
HOST_HDR="${ZITADEL_INSTANCE_HOST:-localhost}"
ISSUER="${ZITADEL_ISSUER:-http://localhost:58080}"
PAT_FILE="${ZITADEL_PAT_FILE:-/bootstrap/zadmin.pat}"
AUTH_ISSUER="${IDENTITY_AUTH_ISSUER:-http://localhost:8083}"
ALICE_PASSWORD="${ALICE_PASSWORD:-Alice12345!}"
OUT_DIR="${OUT_DIR:-/bootstrap}"
APP_NAME="ramp-identity"
IDP_NAME="google"
SCOPES="openid profile email"
ID_FILE="$OUT_DIR/identity_client_id"
SECRET_FILE="$OUT_DIR/identity_client_secret"

# Two modes: provision (default), or re-print an earlier run's credentials.
MODE="provision"
case "${1:-}" in
    --emit-exports) MODE="emit" ;;
    "") ;;
    *)
        printf 'usage: %s [--emit-exports]\n' "$0" >&2
        exit 2
        ;;
esac

RESP="$(mktemp)"
trap 'rm -f "$RESP"' EXIT

log() { printf '%s\n' "bootstrap: $*" >&2; }
die() { log "$*"; exit 1; }

# ── plumbing ────────────────────────────────────────────────────────────────

# api METHOD PATH [BODY] — sets $STATUS and leaves the body in $RESP. Non-2xx is not
# an error; the caller decides. `|| true` keeps a cold start (curl exit 7, before
# Zitadel listens) from killing the readiness loop under `set -e`; curl still
# reports %{http_code} as "000".
STATUS=""
api() {
    _m="$1"; _p="$2"; _b="${3:-}"
    if [ -n "$_b" ]; then
        STATUS="$(curl -s -o "$RESP" -w '%{http_code}' -X "$_m" "$BASE/management/v1$_p" \
            -H "Host: $HOST_HDR" -H "Authorization: Bearer $PAT" \
            -H 'Content-Type: application/json' -d "$_b" || true)"
    else
        STATUS="$(curl -s -o "$RESP" -w '%{http_code}' -X "$_m" "$BASE/management/v1$_p" \
            -H "Host: $HOST_HDR" -H "Authorization: Bearer $PAT" || true)"
    fi
}

ok() { case "$STATUS" in 200 | 201) return 0 ;; *) return 1 ;; esac; }

# field NAME — first matching string field in $RESP, on a SUCCESS response only.
# The guard matters: a Zitadel error body carries its own `"id"` (the error code,
# e.g. "V3-DKcYh"), so reading a 409 yields a convincing non-id.
field() {
    ok || return 0
    grep -o "\"$1\":\"[^\"]*\"" "$RESP" 2>/dev/null | head -n 1 | sed 's/^[^:]*:"//; s/"$//'
}

# benign — succeeded, or was a no-op. Zitadel reports both "already exists" and
# "already has these values" as 4xx; for idempotent provisioning they are success.
benign() {
    ok && return 0
    grep -qi 'alreadyexists\|already exists\|notchanged' "$RESP"
}

# body_head — a bounded slice of the last response, for error messages.
body_head() { cut -c1-300 "$RESP" | tr -d '\n'; }

# json_array LIST — renders a space-separated list as a JSON string array.
json_array() {
    _out=""
    for _item in $1; do
        if [ -n "$_out" ]; then _out="$_out,"; fi
        _out="$_out\"$_item\""
    done
    printf '[%s]' "$_out"
}

# ── 0. credentials + readiness ──────────────────────────────────────────────

read_pat() {
    if [ -n "${ZITADEL_PAT:-}" ]; then
        PAT="$ZITADEL_PAT"
        return
    fi
    _i=0
    while [ ! -s "$PAT_FILE" ]; do
        _i=$((_i + 1))
        if [ "$_i" -gt 120 ]; then
            log "timed out waiting for the admin PAT at $PAT_FILE"
            log "(FirstInstance writes it; check \`docker compose logs zitadel\`)"
            exit 2
        fi
        sleep 1
    done
    PAT="$(tr -d '[:space:]' <"$PAT_FILE")"
    [ -n "$PAT" ] || die "admin PAT at $PAT_FILE is empty"
}

wait_ready() {
    _i=0
    while :; do
        api GET /orgs/me
        if ok; then
            log "management API reachable at $BASE (Host: $HOST_HDR)"
            return
        fi
        _i=$((_i + 1))
        if [ "$_i" -gt 180 ]; then
            log "management API never became reachable at $BASE (last status $STATUS)"
            if [ "$STATUS" = "000" ]; then
                log "(status 000 = nothing listening; check \`docker compose logs zitadel\`)"
            else
                log "(body: $(body_head))"
                log "(an 'Instance not found' means the Host header does not match ExternalDomain)"
            fi
            exit 2
        fi
        if [ "$_i" = "15" ]; then
            log "still waiting for Zitadel to come up (first boot takes ~30-45s)..."
        fi
        sleep 1
    done
}

# ── 1. project ──────────────────────────────────────────────────────────────

create_project() {
    api POST /projects '{"name":"ramp","projectRoleAssertion":true,"projectRoleCheck":false}'
    PROJECT_ID="$(field id)"
    if [ -z "$PROJECT_ID" ]; then
        api POST /projects/_search \
            '{"queries":[{"nameQuery":{"name":"ramp","method":"TEXT_QUERY_METHOD_EQUALS"}}]}'
        PROJECT_ID="$(field id)"
    fi
    [ -n "$PROJECT_ID" ] || die "could not resolve project id: $(body_head)"
    log "project ramp id=$PROJECT_ID"
}

# ── 2. login policy ─────────────────────────────────────────────────────────

# The default policy forces MFA enrolment after the first password, breaking any
# scripted login. allowExternalIdp is what permits federated sign-in at all —
# without it no Google button renders, however the IdP itself is configured.
# allowRegister puts self-registration on the sign-in page, so a new developer
# can create an account without an operator pre-creating one.
LOGIN_POLICY='{
  "allowUsernamePassword": true,
  "allowRegister": true,
  "allowExternalIdp": true,
  "forceMfa": false,
  "forceMfaLocalOnly": false,
  "passwordlessType": "PASSWORDLESS_TYPE_NOT_ALLOWED",
  "hidePasswordReset": true,
  "ignoreUnknownUsernames": false,
  "passwordCheckLifetime": "864000s",
  "externalLoginCheckLifetime": "864000s",
  "mfaInitSkipLifetime": "0s",
  "secondFactorCheckLifetime": "64800s",
  "multiFactorCheckLifetime": "43200s",
  "allowDomainDiscovery": true,
  "disableLoginWithEmail": false,
  "disableLoginWithPhone": true
}'

set_login_policy() {
    api POST /policies/login "$LOGIN_POLICY"
    if ok; then
        log "org login policy created (MFA off, external IdP allowed, self-registration on)"
        return
    fi
    _create="$STATUS"
    # A custom policy already exists for this org → update it to the same shape.
    # An update that changes nothing comes back 400 NotChanged, which `benign`
    # accepts: the policy already reads the way this script wants it.
    api PUT /policies/login "$LOGIN_POLICY"
    if benign; then
        log "org login policy already applied (MFA off, external IdP allowed, self-registration on)"
        return
    fi
    die "login policy not applied (create $_create, update $STATUS): $(body_head)"
}

# ── 3. the Identity Service's OIDC client ───────────────────────────────────

app_body() {
    cat <<JSON
{
  "name": "$APP_NAME",
  "redirectUris": $(json_array "$REDIRECT_URIS"),
  "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
  "grantTypes": ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"],
  "appType": "OIDC_APP_TYPE_WEB",
  "authMethodType": "OIDC_AUTH_METHOD_TYPE_BASIC",
  "postLogoutRedirectUris": [],
  "version": "OIDC_VERSION_1_0",
  "devMode": true,
  "accessTokenType": "OIDC_TOKEN_TYPE_JWT",
  "accessTokenRoleAssertion": true,
  "idTokenRoleAssertion": true,
  "idTokenUserinfoAssertion": true,
  "clockSkew": "0s"
}
JSON
}

# regenerate_secret APP_ID — Zitadel v3 renamed this endpoint; keep the legacy
# path as a fallback for older instances left behind in a dev volume.
regenerate_secret() {
    api POST "/projects/$PROJECT_ID/apps/$1/oidc_config/_generate_client_secret" '{}'
    CLIENT_SECRET="$(field clientSecret)"
    if [ -z "$CLIENT_SECRET" ]; then
        api POST "/projects/$PROJECT_ID/apps/$1/oidc_config/_change_client_secret" '{}'
        CLIENT_SECRET="$(field clientSecret)"
    fi
}

# Creates first, unlike configure_google which searches first. Measured on v3.4.9:
# a duplicate POST apps/oidc returns 409, a duplicate POST idps/google returns 200
# and a second provider. The server guards app names, so create-first is correct
# here and cheaper; don't "fix" it into find-before-create for symmetry.
create_app() {
    # devMode lets Zitadel accept the plain-http loopback redirect a laptop uses.
    REDIRECT_URIS="$AUTH_ISSUER/callback ${EXTRA_REDIRECT_URIS:-}"
    api POST "/projects/$PROJECT_ID/apps/oidc" "$(app_body)"
    CLIENT_ID="$(field clientId)"
    CLIENT_SECRET="$(field clientSecret)"
    if [ -z "$CLIENT_ID" ]; then
        # Distinguish "already there" from a real fault; reporting both as the
        # former hides a broken create until it surfaces far from here.
        if benign; then
            log "app $APP_NAME already existed; regenerating its client secret"
        else
            die "app $APP_NAME create failed ($STATUS): $(body_head)"
        fi
        # Zitadel never reads a client secret back, so the original is
        # unrecoverable: find the app and mint a fresh secret.
        api POST "/projects/$PROJECT_ID/apps/_search" \
            "{\"queries\":[{\"nameQuery\":{\"name\":\"$APP_NAME\",\"method\":\"TEXT_QUERY_METHOD_EQUALS\"}}]}"
        _app_id="$(field id)"
        CLIENT_ID="$(field clientId)"
        [ -n "$_app_id" ] || die "could not resolve app $APP_NAME: $(body_head)"
        regenerate_secret "$_app_id"
    fi
    [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] ||
        die "could not resolve client id/secret for $APP_NAME: $(body_head)"
    log "app $APP_NAME client_id=$CLIENT_ID redirect=$AUTH_ISSUER/callback"
}

# ── 4. local user ───────────────────────────────────────────────────────────

import_alice() {
    api POST /users/human/_import "$(cat <<JSON
{
  "userName": "alice@acme.local",
  "profile": {
    "firstName": "Alice", "lastName": "Subscriber",
    "displayName": "Alice Subscriber", "preferredLanguage": "en"
  },
  "email": {"email": "alice@acme.local", "isEmailVerified": true},
  "password": "$ALICE_PASSWORD",
  "passwordChangeRequired": false
}
JSON
    )"
    if ok; then
        log "user alice@acme.local created"
    elif benign; then
        log "user alice@acme.local already exists"
    else
        die "alice import failed ($STATUS): $(body_head)"
    fi
}

# ── 5. Google federation ────────────────────────────────────────────────────

google_body() {
    cat <<JSON
{
  "name": "$IDP_NAME",
  "clientId": "$GOOGLE_CLIENT_ID",
  "clientSecret": "$GOOGLE_CLIENT_SECRET",
  "scopes": ["openid", "profile", "email"],
  "providerOptions": {
    "isLinkingAllowed": true,
    "isCreationAllowed": true,
    "isAutoCreation": true,
    "isAutoUpdate": true,
    "autoLinking": "AUTO_LINKING_OPTION_EMAIL"
  }
}
JSON
}

# find_google — id of an existing google IdP, or empty. Searched BEFORE creating:
# Zitadel accepts a second provider under the same name, so a re-run would stack
# duplicate buttons on the login page.
find_google() {
    api POST /idps/templates/_search \
        "{\"queries\":[{\"idpNameQuery\":{\"name\":\"$IDP_NAME\",\"method\":\"TEXT_QUERY_METHOD_EQUALS\"}}]}"
    field id
}

# link_to_login_policy IDP_ID — the step that actually puts the provider on the
# login page. Creating the IdP alone leaves it configured but invisible.
link_to_login_policy() {
    api POST /policies/login/idps "{\"idpId\":\"$1\",\"ownerType\":\"IDP_OWNER_TYPE_ORG\"}"
    if ok; then
        log "google IdP linked into the login policy"
    elif benign; then
        log "google IdP already linked into the login policy"
    else
        die "linking the google IdP failed ($STATUS): $(body_head)"
    fi
}

configure_google() {
    if [ -z "${GOOGLE_CLIENT_ID:-}" ] || [ -z "${GOOGLE_CLIENT_SECRET:-}" ]; then
        log "SKIP google federation — GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET unset."
        log "     Sign-in still works with alice@acme.local; set both variables"
        log "     and re-run to add Google federation."
        return
    fi
    _idp_id="$(find_google)"
    if [ -n "$_idp_id" ]; then
        # UPDATE rather than skip. The credentials in the environment are the
        # operator's current intent, so a re-run after rotating the Google secret —
        # or after replacing placeholder credentials with real ones — must take
        # effect. Skipping would leave the old secret in place and fail only later,
        # at Google, with nothing here having reported a problem.
        api PUT "/idps/google/$_idp_id" "$(google_body)"
        benign || die "google IdP update failed ($STATUS): $(body_head)"
        log "google IdP updated id=$_idp_id"
    else
        api POST /idps/google "$(google_body)"
        _idp_id="$(field id)"
        [ -n "$_idp_id" ] || die "google IdP create returned no id: $(body_head)"
        log "google IdP created id=$_idp_id"
    fi
    link_to_login_policy "$_idp_id"
    log "reminder: Google's authorized redirect URI must be EXACTLY"
    log "     $ISSUER/ui/login/login/externalidp/callback"
}

# ── 6. hand the config to the Identity Service ──────────────────────────────

write_creds() {
    mkdir -p "$OUT_DIR"
    printf '%s\n' "$CLIENT_ID" >"$ID_FILE"
    printf '%s\n' "$CLIENT_SECRET" >"$SECRET_FILE"
    log "wrote $ID_FILE and $SECRET_FILE"
}

# The ONE definition of the export format — a provisioning run and --emit-exports
# both come through here, so they cannot disagree. Reads the files, not the
# in-memory values, so both paths are identical. Only these lines go to stdout
# (logging is on stderr), which is what makes `eval "$(...)"` safe.
print_exports() {
    _id="$(cat "$ID_FILE" 2>/dev/null || true)"
    _secret="$(cat "$SECRET_FILE" 2>/dev/null || true)"
    if [ -z "$_id" ] || [ -z "$_secret" ]; then
        die "no credentials at $OUT_DIR — run \`make zitadel-up\` first"
    fi
    printf 'export IDENTITY_OIDC_ISSUER=%s\n' "$ISSUER"
    printf 'export IDENTITY_OIDC_CLIENT_ID=%s\n' "$_id"
    printf 'export IDENTITY_OIDC_CLIENT_SECRET=%s\n' "$_secret"
    printf 'export IDENTITY_OIDC_SCOPES="%s"\n' "$SCOPES"
}

# --emit-exports re-prints an earlier run's credentials without touching Zitadel:
# no PAT, no readiness wait, no provisioning. Everything below is skipped.
if [ "$MODE" = "emit" ]; then
    print_exports
    exit 0
fi

read_pat
wait_ready
create_project
set_login_policy
create_app
import_alice
configure_google
write_creds
log "done"
print_exports
