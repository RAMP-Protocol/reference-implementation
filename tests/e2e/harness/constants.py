"""Shared well-known route constants for the E2E harness.

Single source of truth for the well-known paths the harness probes, so a spec
change (e.g. a WBA directory route rename) touches one line, not four. Also
holds the User-Agent pair every bot-gate check uses, for the same reason.
"""

from __future__ import annotations

# One representative on each side of the edge's bot gate: a mainstream
# browser signature (allowed through to the origin) and an AI crawler from
# the worker's built-in deny list (sent to negotiate).
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
AI_BOT_UA = "GPTBot/1.0 (+https://openai.com/gptbot)"

# Web Bot Auth directory: after the WBA split, identity/revocation keys moved
# off ramp.json and are served here as a JWK set (keys named by RFC 7638
# thumbprint, no kid).
WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"

# Broker-published key-revocation channel (KeyRevocationList wire shape).
REVOCATION_PATH = "/.well-known/ramp-key-revocations.json"
