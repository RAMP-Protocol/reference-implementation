"""Test-harness signing helper for the v1 obligation tests.

Why this exists
---------------
Post-commit ``9c3a93b`` (1rnxh), the Exchange's RFC 9421 ``httpsig``
middleware verifies every ``/ramp.v1.ExchangeService/*`` and
``/ramp.v1.BrokerService/*`` request unconditionally. The previous
"sign only when ``Signature-Input`` is present" predicate let plain
``httpx.post()`` calls fall through to the service layer; the new
predicate refuses them at the transport layer with Connect
``unauthenticated``.

The obligation tests under ``tests/e2e/harness/obligations/`` exercise
agent-direct surfaces — ``DiscoverResources``, ``ExecuteTransaction``,
``ReportUsage`` — and used to drive them with bare ``httpx.post()``.
Each such call now needs an RFC 9421 signature stamped on the request
with a ``kid`` the Exchange's global static resolver can resolve.

The global resolver is seeded from ``RAMP_KEYS_FILE`` (default
``deploy/broker/keys.json``); it does NOT consult the ``ramp.agents``
DB table. So the test signer's ``kid`` must be present in that JWKS
file at compose-build time. The repo ships a checked-in keypair —
``deploy/broker/keys.json`` carries the public half under
``kid="test-signer-e2e.v1"``; the private half lives at
``tests/e2e/harness/fixtures/test_signer_key.json``. The pairing is
deterministic and version-controlled so every contributor and every
CI run signs with the same key without a generation step.

Test signer identity vs. catalog contributor identity
-----------------------------------------------------
The catalog contributor key (``catalog-contributor-e2e``, see
``catalog_push.py``) signs ``CatalogService/PushResources``; its
verifier reads from ``ramp.agents`` (Gate 1) plus the publisher's
``ramp.json`` (Gate 2). The catalog contributor kid is intentionally
NOT in ``RAMP_KEYS_FILE`` — that file is for the global static
resolver only. Mixing the two would compromise the contributor key's
narrow scope.

The test signer is a *different* identity used only by the obligation
tests for their agent-direct ``ExchangeService`` calls. Its ``kid`` is
prefixed ``test-`` so production graders can tell at a glance that a
``test-signer-*`` signature has no business appearing in a non-test
trace.

Decoupling kid from requester.id
--------------------------------
RFC 9421's ``keyid`` parameter identifies the signing key. The Exchange's
service layer (``exchange.go::DiscoverResources``) separately requires a
non-empty ``requester.id`` in the request body — that's the *agent*
identity attached to the audit trail. The two are decoupled by design: a
single test signer ``kid`` can carry requests on behalf of many different
``agent_id`` values, and the service layer never reads the ``kid`` to
infer who the caller is.

Public surface
--------------
:func:`sign_post` — POST a JSON body to a ``/ramp.*`` URL, signing the
request with the test signer key. Returns ``httpx.Response``.

:func:`build_signed_headers` — build the four RFC 9421 headers without
issuing a request. Useful for tests that need to inspect or mutate the
headers before sending.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ramp_mcp_shim.httpsig import pop_signature_base
from ramp_mcp_shim.thumbprint import ed25519_thumbprint

from .b64 import b64url_decode, b64url_nopad

# Path to the checked-in static test signer key. Resolved relative to
# this module so the fixture follows the harness whether the runner is
# the repo checkout, the in-network compose `runner` service, or a CI
# image that COPYs the harness tree intact.
TEST_SIGNER_KEY_PATH = Path(__file__).resolve().parent / "fixtures" / "test_signer_key.json"

# Agent identities the obligation/full-stack tests act AS. Their kid equals the
# agent_id and is registered in ramp.agents by seed.py, so the Exchange's
# caller authz (resolveCaller + authorizeForAgent: kid == requester.id)
# admits them on ExecuteTransaction / ReportUsage. Distinct from the generic
# test signer above, which is a transport-only kid NOT in ramp.agents (used by
# the obligation-05 httpsig negatives that never reach the caller-authz layer).
AGENT_E2E_KEY_PATH = Path(__file__).resolve().parent / "fixtures" / "agent_e2e_key.json"
AGENT_NOBILLING_KEY_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "agent_nobilling_e2e_key.json"
)

# Components covered by the signature. Order and quoting must match the
# Exchange's verifier (``internal/httpsig/verifier.go``) and the
# matching ``catalog_push._sign_request`` helper; the duplication is
# deliberate to keep this module self-contained.
_COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
    "content-digest",
    "authorization",
)
_DEFAULT_TTL_SECONDS = 30

# Caller-supplied header carrying the target Exchange endpoint for the RAMP-56
# relay. The Go consumer names it via the ``headerExchangeEndpoint`` constant
# (src/broker/internal/transport/exchange_relay.go); a single Python constant
# keeps every harness producer in sync (MED-08). The string MUST match the Go
# side byte-for-byte — it crosses the Python→Go boundary, so the two can't share
# one literal.
EXCHANGE_ENDPOINT_HEADER = "X-RAMP-Exchange-Endpoint"


def _load_signer(key_path: Path | None = None) -> tuple[str, Ed25519PrivateKey]:
    """Return ``(kid, Ed25519PrivateKey)`` for a signing identity.

    ``key_path`` defaults to the generic test signer (``TEST_SIGNER_KEY_PATH``);
    pass ``AGENT_E2E_KEY_PATH`` / ``AGENT_NOBILLING_KEY_PATH`` to sign AS a
    registered agent (kid == agent_id), which the Exchange's caller authz
    requires for ExecuteTransaction / ReportUsage.

    The key file format mirrors ``deploy/mcp/agent-key.json``: a JSON
    object with ``kid`` + ``private_key`` (b64url, no padding) + a
    redundant ``public_key`` field.
    """
    doc = json.loads((key_path or TEST_SIGNER_KEY_PATH).read_text())
    seed = b64url_decode(doc["private_key"])
    return doc["kid"], Ed25519PrivateKey.from_private_bytes(seed)


def build_signed_headers(
    *,
    method: str,
    target_uri: str,
    body: bytes,
    content_type: str = "application/json",
    key_path: Path | None = None,
) -> dict[str, str]:
    """Build the four RFC 9421 headers + Content-Type for a request.

    By default the generic test signer (``TEST_SIGNER_KEY_PATH``) signs;
    pass ``key_path`` to sign AS a registered agent (e.g.
    ``AGENT_E2E_KEY_PATH``). Tests that want a fully custom/invalid kid
    (e.g. the obligation-05 "unknown signer" scenarios) build their own
    headers via ``httpsig_signer``.
    """
    kid, priv = _load_signer(key_path)
    digest_header = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
    created = int(time.time())
    expires = created + _DEFAULT_TTL_SECONDS
    covered_list = " ".join(f'"{c}"' for c in _COVERED_COMPONENTS)
    sig_params = f'({covered_list});keyid="{kid}";alg="ed25519";created={created};expires={expires}'
    authorization = ""
    base_lines = [
        f'"@method": {method.upper()}',
        f'"@target-uri": {target_uri}',
        f'"content-digest": {digest_header}',
        f'"authorization": {authorization}',
        f'"@signature-params": {sig_params}',
    ]
    base = "\n".join(base_lines)
    sig = priv.sign(base.encode())
    sig_b64 = base64.b64encode(sig).decode()
    return {
        "Content-Digest": digest_header,
        "Authorization": authorization,
        "Signature-Input": f"sig1={sig_params}",
        "Signature": f"sig1=:{sig_b64}:",
        "Content-Type": content_type,
    }


def sign_post(
    url: str,
    *,
    body: dict[str, Any],
    timeout: float = 30.0,
    extra_headers: dict[str, str] | None = None,
    key_path: Path | None = None,
) -> httpx.Response:
    """POST ``body`` (as JSON) to ``url`` with an RFC 9421 signature.

    ``body`` is serialised to JSON with the same canonicalisation the
    server applies (no spaces, sorted-key-free). The Content-Digest
    header commits to the exact bytes sent, so callers must NOT mutate
    the body after this call returns.

    ``key_path`` selects the signing identity (default: generic test
    signer). Agent-direct surfaces (ExecuteTransaction / ReportUsage)
    MUST pass ``AGENT_E2E_KEY_PATH`` or ``AGENT_NOBILLING_KEY_PATH`` so
    the signing kid equals ``requester.id``.

    ``extra_headers`` are merged AFTER the signed headers, allowing
    callers to add observability stubs (e.g. ``X-RAMP-Agent-Id``) that
    are not part of the signing base. The four signed headers and
    Content-Type cannot be overridden — the signer's commitment is
    cryptographic and the verifier compares the wire bytes.
    """
    payload = json.dumps(body, separators=(",", ":")).encode()
    headers = build_signed_headers(method="POST", target_uri=url, body=payload, key_path=key_path)
    if extra_headers:
        for key, value in extra_headers.items():
            if key in {"Content-Digest", "Authorization", "Signature-Input", "Signature"}:
                msg = f"sign_post: caller may not override signed header {key!r}"
                raise ValueError(msg)
            headers[key] = value
    return httpx.post(url, content=payload, headers=headers, timeout=timeout)


def build_pop_headers(
    *,
    url: str,
    key_path: Path = AGENT_E2E_KEY_PATH,
) -> dict[str, str]:
    """Build proof-of-possession headers for fetching a bound signed URL (ADR-013).

    When a signed URL carries an agent_id (the agent's RFC 7638 thumbprint),
    the edge requires proof of possession: the fetcher must present its raw
    Ed25519 public key (X-RAMP-Agent-Key) and sign the GET with RFC 9421
    over @method + @target-uri. The edge enforces 3-way identity:

        agent_id (URL param) == keyid (Signature-Input) == thumbprint(presented key)

    Args:
        url: Full signed URL to fetch (the @target-uri value)
        key_path: Agent key file (default: agent-e2e)

    Returns:
        Headers dict with X-RAMP-Agent-Key, Signature-Input, Signature
    """
    kid, priv = _load_signer(key_path)

    # Derive public key from private key (don't trust JSON public_key field)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public_key_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Compute RFC 7638 thumbprint (the agent_id / keyid for PoP)
    thumbprint_val = ed25519_thumbprint(public_key_bytes)

    # Create signature parameters for GET with @method + @target-uri coverage
    created = int(time.time())
    expires = created + _DEFAULT_TTL_SECONDS
    covered_list = '"@method" "@target-uri"'
    sig_params = f'({covered_list});keyid="{thumbprint_val}";alg="ed25519";created={created};expires={expires}'

    # Build RFC 9421 signature base for GET via the shim helper so the harness
    # and production sign the identical, vector-pinned base (MED-06).
    base = pop_signature_base(url, sig_params)
    sig = priv.sign(base.encode())
    sig_b64 = base64.b64encode(sig).decode()

    return {
        "X-RAMP-Agent-Key": b64url_nopad(public_key_bytes),
        "Signature-Input": f"sig1={sig_params}",
        "Signature": f"sig1=:{sig_b64}:",
    }


__all__ = [
    "AGENT_E2E_KEY_PATH",
    "AGENT_NOBILLING_KEY_PATH",
    "TEST_SIGNER_KEY_PATH",
    "build_signed_headers",
    "build_pop_headers",
    "sign_post",
]
