"""Sign and POST ramp.v1.CatalogService/PushResources for the e2e harness.

Why this exists
---------------
The Exchange holds its catalog in an in-memory radix trie that is loaded
once at startup and subsequently mutated ONLY through the signed
``PushResources`` RPC (see ``src/exchange/internal/service/catalog.go``).
The admin reload endpoint the harness used to call was removed — the
tripwires at ``src/exchange/cmd/server/admin_removed_test.go`` and
``src/exchange/internal/transport/admin_removed_e2e_test.go`` make that
policy loud.

This module wraps the production signing path so the harness exercises
the same auth gates every real third-party catalog pusher does:

- **Gate 1** (httpsig, RFC 9421): the request is signed with an Ed25519
  key whose ``kid`` is pre-registered in ``ramp.agents``.
- **Gate 2** (contributor authorization): the caller must appear in the
  publisher's ``ramp.json#catalog_contributors``. The e2e edge worker
  advertises the harness contributor via ``CATALOG_CONTRIBUTORS_JSON``.

Every e2e test that needs catalog data therefore implicitly verifies
that RPC + both gates still work — no separate coverage needed.

Public surface
--------------
``generate_contributor_key(path)`` — idempotent keypair materializer.
``push_catalog(exchange_url, tenant_id, entries, key_path)`` — sign + POST.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .b64 import b64url_decode, b64url_nopad

_CONTRIBUTOR_KID = "catalog-contributor-e2e"
_PUSH_PROCEDURE = "/ramp.v1.CatalogService/PushResources"
_SIGNATURE_TTL_SECONDS = 30
# The Exchange's RFC 9421 verifier covers these four components. Order
# and quoting must match the signer that ships with the MCP shim
# (src/mcp/src/ramp_mcp_shim/httpsig.py) — the signing base is stable
# across the codebase.
_COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
    "content-digest",
    "authorization",
)


@dataclass(frozen=True)
class CatalogEntry:
    """One resource to seed. Mirrors ``rampv1.ResourceEntry`` on the wire.

    ``required_scopes`` is the Path F gate: when non-empty, the Exchange
    treats the entry as subscription-restricted and emits
    ``OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT`` on resolves whose
    delegation does not cover at least one matching scope. Tests that
    need a "subscription-only" entry must populate this field; SQL
    patches alone are insufficient because PushResources rebuilds the
    in-memory snapshot from the row state at push time.
    """

    domain: str
    path: str
    content_id: str
    required_scopes: tuple[str, ...] = ()
    subscription_id: str | None = None


def generate_contributor_key(key_path: Path) -> None:
    """Ensure ``key_path`` carries a catalog-contributor Ed25519 keypair.

    The file format mirrors ``scripts/gen-demo-agent-key.sh`` so ``AgentKey``
    can load it verbatim. Regenerating on every seed run would invalidate
    the pre-registered pubkey in ``ramp.agents``; instead we only write
    when the file is absent, and callers are expected to wipe it if they
    want a fresh key. The parent directory is created on demand.
    """
    if key_path.is_file():
        return
    key_path.parent.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_path.write_text(
        json.dumps(
            {
                "kid": _CONTRIBUTOR_KID,
                "private_key": b64url_nopad(seed),
                "public_key": b64url_nopad(pub),
            },
            indent=2,
        )
        + "\n"
    )
    # Key file carries secret material; lock it down.
    os.chmod(key_path, 0o600)


def load_public_key_bytes(key_path: Path) -> bytes:
    """Return the 32-byte Ed25519 public key stored at ``key_path``."""
    doc = json.loads(key_path.read_text())
    return b64url_decode(doc["public_key"])


def push_catalog(
    *,
    exchange_url: str,
    tenant_id: str,
    entries: list[CatalogEntry],
    key_path: Path,
    timeout: float = 10.0,
) -> None:
    """Sign + POST a ``PushResourcesRequest`` covering ``entries``.

    Fails loudly when the Exchange rejects any entry — the harness cannot
    proceed with a partial catalog. The caller_id is the Ed25519 key's
    ``kid``, which must match both a ``ramp.agents.agent_id`` row (Gate 1)
    and a ``catalog_contributors[].domain`` entry in the publisher's
    ``ramp.json`` (Gate 2).
    """
    if not entries:
        return
    kid, priv = _load_keypair(key_path)
    body = _build_request_json(tenant_id=tenant_id, caller_id=kid, entries=entries)
    url = exchange_url.rstrip("/") + _PUSH_PROCEDURE
    sig_headers = _sign_request(method="POST", url=url, body=body, kid=kid, priv=priv)
    headers = {**sig_headers, "Content-Type": "application/json"}
    resp = httpx.post(url, content=body, headers=headers, timeout=timeout)
    if resp.status_code != httpx.codes.OK:
        msg = f"PushResources failed: {resp.status_code} {resp.text[:512]}"
        raise RuntimeError(msg)
    payload = resp.json()
    accepted = payload.get("accepted", 0)
    rejected = payload.get("rejected", 0)
    rejections = payload.get("rejections", [])
    if accepted != len(entries) or rejected != 0:
        msg = (
            f"PushResources partial: accepted={accepted} rejected={rejected} "
            f"rejections={rejections} body={payload}"
        )
        raise RuntimeError(msg)


def _build_request_json(*, tenant_id: str, caller_id: str, entries: list[CatalogEntry]) -> bytes:
    """Shape the body per proto3-JSON conventions (camelCase field names)."""

    def _entry_json(e: CatalogEntry) -> dict[str, Any]:
        body: dict[str, Any] = {
            "domain": e.domain,
            "path": e.path,
            "contentId": e.content_id,
        }
        if e.required_scopes:
            body["requiredScopes"] = list(e.required_scopes)
        if e.subscription_id is not None:
            body["subscriptionId"] = e.subscription_id
        return body

    payload = {
        "tenantId": tenant_id,
        "callerId": caller_id,
        "entries": [_entry_json(e) for e in entries],
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def _load_keypair(key_path: Path) -> tuple[str, Ed25519PrivateKey]:
    """Read the keyfile and return (kid, Ed25519PrivateKey)."""
    doc = json.loads(key_path.read_text())
    seed = b64url_decode(doc["private_key"])
    return doc["kid"], Ed25519PrivateKey.from_private_bytes(seed)


def _sign_request(
    *,
    method: str,
    url: str,
    body: bytes,
    kid: str,
    priv: Ed25519PrivateKey,
) -> dict[str, str]:
    """Build the RFC 9421 signing base, sign, and emit the four headers.

    Mirrors ``src/mcp/src/ramp_mcp_shim/httpsig.py::Signer.sign`` so the
    Exchange's verifier accepts the request. The covered-components list,
    parameter ordering, and canonicalization rules MUST stay aligned with
    that module — the duplication is deliberate, to keep the harness
    self-contained, and is narrow enough to stay in sync by inspection.
    """
    digest_header = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
    created = int(time.time())
    expires = created + _SIGNATURE_TTL_SECONDS
    covered_list = " ".join(f'"{c}"' for c in _COVERED_COMPONENTS)
    sig_params = f'({covered_list});keyid="{kid}";alg="ed25519";created={created};expires={expires}'
    authorization = ""
    base_lines = [
        f'"@method": {method.upper()}',
        f'"@target-uri": {url}',
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
    }


__all__ = [
    "CatalogEntry",
    "Ed25519PublicKey",  # re-export so callers can type-annotate without another import
    "generate_contributor_key",
    "load_public_key_bytes",
    "push_catalog",
]
