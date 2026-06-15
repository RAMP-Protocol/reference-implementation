"""Shared base64url-no-pad encode/decode for the MCP shim.

RFC 7515 §2 base64url without padding is the wire form for raw Ed25519 keys,
RFC 7638 thumbprints, and key seeds throughout the shim. One encode/decode pair
lives here so it is not re-spelled per module. Standard-base64 forms (RFC 9421
``Signature`` values, ``Content-Digest``) stay on :mod:`base64` directly — they
are a different alphabet and not this helper's concern.
"""

from __future__ import annotations

import base64


def b64url_nopad(raw: bytes) -> str:
    """Encode bytes as base64url with trailing padding stripped."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(raw: str) -> bytes:
    """Decode a base64url string, re-adding any stripped ``=`` padding."""
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
