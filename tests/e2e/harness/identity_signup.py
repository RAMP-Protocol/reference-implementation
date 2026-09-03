"""Provision a real agent through the identity service's OIDC sign-up, in-network.

This is how the e2e gets a usable agent for the Go MCP endpoint: it drives the
SAME sign-up an SDK-less developer would — register an OAuth client at identity,
start the authorize flow, log in through the real Zitadel UI headlessly, and let
identity's /callback provision the agent. Provisioning mints the agent's Ed25519
key in identity's Vault and hosts its WBA directory at ``<subdomain>.rampmcp.org``
by the time the callback lands, so the agent can already sign RAMP requests —
which is all the discover/execute/report tools need.

The bearer is then minted directly with the deterministic e2e token key
(:func:`mint_bearer`) rather than by finishing the consent → token dance:
identity verifies that self-minted token with the very same key it would have
signed one with, so it is the same credential, and skipping the UI steps that add
nothing to a discover/execute test keeps this driver from scraping more of
Zitadel's and identity's HTML than it must. Provisioning is real; only the final
token issuance is short-circuited.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
import uuid
from http.cookies import SimpleCookie

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ramp_sdk.b64 import b64url_nopad

# The seeded local Zitadel login the bootstrap creates (scripts/zitadel-bootstrap.sh).
ALICE_USER = "alice@acme.local"
ALICE_PASSWORD = "Alice12345!"

# The harness's OAuth redirect — never actually dialed (we stop at /callback), but
# it must be registered and echoed consistently through the authorize flow.
_CLIENT_REDIRECT = "http://127.0.0.1:5599/callback"

# The consent page renders two spans with class "sub" — the subdomain and the
# redirect URI — so the id is what disambiguates them. The Go integration test
# asserts this same fragment, so a template edit that breaks this regex fails
# there first.
_SUB_RE = re.compile(r'<span class="sub" id="agent-subdomain">([^<]+)</span>')
_INPUT_RE = re.compile(r"(?s)<input\b[^>]*>")
_FORM_ACTION_RE = re.compile(r'(?s)<form\b[^>]*\baction="([^"]+)"')


def _body_excerpt(html: str, limit: int = 400) -> str:
    """Return an excerpt of a render starting at <body>, for a failure message.

    The consent page carries an inline stylesheet, so <body> does not start until
    roughly 700 characters in and the subdomain span not until roughly 880. An
    excerpt taken from the start of the document shows the doctype, the head and
    half the CSS — never the markup a regex mismatch is about.
    """
    start = html.find("<body")
    return html[start if start != -1 else 0 :][:limit]


class SignupError(RuntimeError):
    """A sign-up leg did not produce the expected result."""


def provision_agent(identity_base: str, zitadel_base: str) -> str:
    """Run a full sign-up and return the minted agent subdomain.

    identity_base and zitadel_base are the in-network origins (http://identity,
    http://zitadel:8080). Cookies are kept per origin: one jar for identity (the
    authorize→callback session) and a separate jar inside the Zitadel login.
    """
    # A single identity client carries the flow cookie authorize sets and
    # callback reads. Redirects are followed manually so each Location is visible.
    with httpx.Client(base_url=identity_base, timeout=15.0, follow_redirects=False) as idc:
        client_id = _register_client(idc)
        _, challenge = _pkce()
        upstream_url = _authorize(idc, client_id, challenge)
        code, state = _zitadel_login(zitadel_base, upstream_url, identity_base)
        _callback(idc, code, state)
        return _scrape_subdomain(idc)


def mint_bearer(
    subdomain: str, *, issuer: str, audience: str, seed_b64: str, ttl_s: int = 600
) -> str:
    """Mint the EdDSA bearer identity's token verifier accepts for subdomain.

    Signed with the deterministic e2e token seed (IDENTITY_TOKEN_SIGNING_KEY), so
    it verifies under the same key identity mints with. sub is the subdomain — the
    durable agent identity every tool signs as.
    """
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed_b64))
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subdomain,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_s,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"typ": "JWT"})


def _register_client(idc: httpx.Client) -> str:
    """Dynamically register the harness as an OAuth client; return its client_id."""
    resp = idc.post(
        "/register",
        json={"redirect_uris": [_CLIENT_REDIRECT], "client_name": "ramp-e2e"},
        headers={"Content-Type": "application/json"},
    )
    if resp.status_code != httpx.codes.CREATED:
        raise SignupError(f"register: {resp.status_code} {resp.text[:256]}")
    client_id = resp.json().get("client_id")
    if not client_id:
        raise SignupError(f"register returned no client_id: {resp.text[:256]}")
    return client_id


def _pkce() -> tuple[str, str]:
    """Return an (verifier, S256 challenge) PKCE pair, base64url-no-pad."""
    verifier = b64url_nopad(secrets.token_bytes(32))
    challenge = b64url_nopad(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def _authorize(idc: httpx.Client, client_id: str, challenge: str) -> str:
    """GET /authorize; return the upstream (Zitadel) authorize URL it redirects to."""
    resp = idc.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": _CLIENT_REDIRECT,
            "state": "e2e-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "openid",
        },
    )
    if resp.status_code != httpx.codes.FOUND:
        raise SignupError(f"authorize: {resp.status_code} {resp.text[:256]}")
    loc = resp.headers.get("location", "")
    if not loc:
        raise SignupError("authorize returned no upstream redirect")
    return loc


def _callback(idc: httpx.Client, code: str, state: str) -> None:
    """GET /callback with the upstream code+state; expect a 302 onward."""
    resp = idc.get("/callback", params={"code": code, "state": state})
    if resp.status_code != httpx.codes.FOUND:
        raise SignupError(f"callback: {resp.status_code} {resp.text[:256]}")


def _scrape_subdomain(idc: httpx.Client) -> str:
    """GET /consent and read the minted subdomain the render shows.

    The consent screen names the identity it is about to grant a client access
    to, which is the same subdomain /callback just provisioned. It renders from
    the sealed pending cookie alone, so it is readable at this point in the flow
    without approving anything.
    """
    resp = idc.get("/consent")
    if resp.status_code != httpx.codes.OK:
        raise SignupError(f"consent GET: {resp.status_code} {resp.text[:256]}")
    m = _SUB_RE.search(resp.text)
    if not m:
        raise SignupError(f"consent render carried no subdomain: {_body_excerpt(resp.text)}")
    return m.group(1).strip()


class _Session:
    """A tiny HTTP session that threads cookies by hand across the login hops.

    Zitadel binds the auth request to a userAgentID carried in the
    ``zitadel.useragent`` cookie, whose Domain is the single-label service name
    ``zitadel``. Python's cookie policy silently refuses to SEND a cookie scoped
    to a dot-less domain, so httpx's own jar drops it on the redirect that follows
    login and Zitadel then rejects the request with "User Agent does not
    correspond". Threading the cookies as a plain name→value map and setting the
    Cookie header explicitly sidesteps that policy — the one wrinkle of driving a
    real provider by docker-DNS name.
    """

    def __init__(self, base: str) -> None:
        self._c = httpx.Client(timeout=15.0, follow_redirects=False)
        self._jar: dict[str, str] = {}
        self._base = base

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._c.close()

    def _cookie_header(self) -> dict[str, str]:
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in self._jar.items())} if self._jar else {}

    def _absorb(self, resp: httpx.Response) -> None:
        for raw in resp.headers.get_list("set-cookie"):
            jar = SimpleCookie()
            jar.load(raw)
            for name, morsel in jar.items():
                self._jar[name] = morsel.value

    def _abs(self, loc: str) -> str:
        return self._base + loc if loc.startswith("/") else loc

    def get_following(
        self, url: str, *, stop_prefix: str | None = None
    ) -> tuple[httpx.Response, str]:
        """GET url, following redirects (threading cookies), until a 2xx or until a
        Location starts with stop_prefix. Returns (last response, matched location).
        """
        for _ in range(20):
            resp = self._c.get(url, headers=self._cookie_header())
            self._absorb(resp)
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp, ""
            loc = self._abs(resp.headers.get("location", ""))
            if stop_prefix and loc.startswith(stop_prefix):
                return resp, loc
            if not loc:
                raise SignupError("redirect with no Location")
            url = loc
        raise SignupError("redirect hop limit")

    def post(self, url: str, data: dict[str, str]) -> httpx.Response:
        resp = self._c.post(url, data=data, headers=self._cookie_header())
        self._absorb(resp)
        return resp


def _zitadel_login(zitadel_base: str, authorize_url: str, redirect_prefix: str) -> tuple[str, str]:
    """Drive Zitadel v3's server-rendered Login V1 UI headlessly to the callback.

    Mirrors the Go testutil.HeadlessLogin: scrape the login-name form, submit the
    login name, scrape the password form, submit the password, then chase the
    redirect chain until it reaches identity's /callback and pull the code+state.
    Deliberately the only thing coupled to Zitadel's login HTML.
    """
    callback_prefix = redirect_prefix.rstrip("/") + "/callback"
    with _Session(zitadel_base) as s:
        login_resp, _ = s.get_following(authorize_url)
        csrf, req_id, action = _parse_form(login_resp.text, "login-name", want_req_id=True)

        pw_resp = s.post(
            zitadel_base + action,
            {
                "gorilla.csrf.Token": csrf,
                "authRequestID": req_id,
                "loginName": ALICE_USER,
            },
        )
        pw_resp = _follow_to_page(s, pw_resp)
        csrf2, _, action2 = _parse_form(pw_resp.text, "password", want_req_id=False)

        submit = s.post(
            zitadel_base + action2,
            {
                "gorilla.csrf.Token": csrf2,
                "authRequestID": req_id,
                "password": ALICE_PASSWORD,
            },
        )
        first = s._abs(submit.headers.get("location", ""))  # noqa: SLF001 — same-module helper
        if not first:
            raise SignupError(f"password submit did not redirect: {submit.text[:300]}")
        _, matched = s.get_following(first, stop_prefix=callback_prefix)
        return _code_state(matched)


def _follow_to_page(s: _Session, resp: httpx.Response) -> httpx.Response:
    """If resp is a redirect, follow it (threading cookies) to the next rendered page."""
    if resp.status_code not in (301, 302, 303, 307, 308):
        return resp
    loc = s._abs(resp.headers.get("location", ""))  # noqa: SLF001 — same-module helper
    page, _ = s.get_following(loc)
    return page


def _parse_form(html: str, which: str, *, want_req_id: bool) -> tuple[str, str, str]:
    """Extract (csrf, authRequestID, form action) from a Zitadel login page."""
    csrf = _hidden(html, "gorilla.csrf.Token")
    action = _action(html)
    req_id = _hidden(html, "authRequestID") if want_req_id else ""
    if not (csrf and action) or (want_req_id and not req_id):
        raise SignupError(
            f"zitadel {which} form parse (csrf={bool(csrf)} action={bool(action)}): {html[:400]}"
        )
    return csrf, req_id, action


def _code_state(callback_url: str) -> tuple[str, str]:
    """Pull the OAuth code + state off the callback URL the login chain reached."""
    q = httpx.URL(callback_url).params
    if q.get("error"):
        raise SignupError(f"zitadel login error: {q.get('error')} {q.get('error_description')}")
    code = q.get("code")
    if not code:
        raise SignupError(f"reached callback without code: {callback_url}")
    return code, q.get("state", "")


def _hidden(html: str, name: str) -> str:
    for tag in _INPUT_RE.findall(html):
        if f'name="{name}"' in tag:
            m = re.search(r'value="([^"]*)"', tag)
            return m.group(1) if m else ""
    return ""


def _action(html: str) -> str:
    m = _FORM_ACTION_RE.search(html)
    return m.group(1) if m else ""
