"""Shared well-known route constants for the E2E harness.

Single source of truth for the well-known paths the harness probes, so a spec
change (e.g. a WBA directory route rename) touches one line, not four.
"""

from __future__ import annotations

# Web Bot Auth directory: after the WBA split, identity/revocation keys moved
# off ramp.json and are served here as a JWK set (keys named by RFC 7638
# thumbprint, no kid).
WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"

# Broker-published key-revocation channel (KeyRevocationList wire shape).
REVOCATION_PATH = "/.well-known/ramp-key-revocations.json"
