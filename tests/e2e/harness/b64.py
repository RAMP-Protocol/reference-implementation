"""Shared base64url-no-pad encode/decode for the e2e harness.

One encode/decode pair so key-seed handling is not re-spelled per harness module.
Standard-base64 forms (RFC 9421 ``Signature`` values, ``Content-Digest``) stay on
:mod:`base64` directly — a different alphabet, not this helper's concern.
"""

from __future__ import annotations

import base64


def b64url_nopad(raw: bytes) -> str:
    """Encode bytes as base64url with trailing padding stripped."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """Decode a base64url string, re-adding any stripped ``=`` padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
