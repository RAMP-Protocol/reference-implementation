"""Factory for httpx clients that auto-sign outbound Broker calls.

The Broker client (:mod:`ramp_mcp_shim.broker`) constructs ``httpx.AsyncClient``
per request. To keep that code path unchanged, this module exposes a single
factory ``make_signing_async_client`` that returns an ``httpx.AsyncClient`` with
a :class:`ramp_mcp_shim.httpsig.SigningTransport` bolted on.

Use by wrapping every ``httpx.AsyncClient(...)`` construction:

.. code-block:: python

   async with make_signing_async_client(timeout=timeout) as client:
       resp = await client.post(url, json=payload)

When no key material is configured (``RAMP_AGENT_KEY_FILE`` unset and no
bundled ``deploy/mcp/agent-key.json``), the factory returns a plain client so
local-only dev flows still work.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx

from .httpsig import AgentKey, Signer, SigningTransport

logger = logging.getLogger(__name__)

_DEFAULT_KEY_PATH = "/app/deploy/mcp/agent-key.json"


class AgentKeyConfigError(RuntimeError):
    """An explicitly-configured ``RAMP_AGENT_KEY_FILE`` is present but unusable.

    Raised only on the outbound-signing path (``require_valid_explicit=True``):
    an operator who points ``RAMP_AGENT_KEY_FILE`` at a real file intends that
    key to sign, so a malformed file must fail loudly rather than silently fall
    through to the keyless (unsigned) client or any other identity. The
    discovery-manifest path keeps the tolerant default, so a keyless dev run
    still answers a graceful 404.
    """


def load_agent_key(*, require_valid_explicit: bool = False) -> AgentKey | None:
    """Load the Ed25519 agent key from disk, or return None when absent.

    Resolution order:
      1. ``RAMP_AGENT_KEY_FILE`` (absolute or relative path).
      2. ``./deploy/mcp/agent-key.json`` when running from a repo checkout.
      3. ``/app/deploy/mcp/agent-key.json`` when running in the shipped container.

    A missing file is logged at INFO — callers fall back to unsigned requests.
    A present-but-malformed *fallback* file (bad JSON, missing field, or a seed
    that is not a valid 32-byte Ed25519 key) is logged at WARNING and treated as
    absent, so a corrupt bundled key degrades to unsigned rather than crashing.

    When ``require_valid_explicit`` is set, a present-but-malformed file at the
    explicitly-configured ``RAMP_AGENT_KEY_FILE`` path is a hard
    :class:`AgentKeyConfigError` instead — the operator named a key and it does
    not load, so the signing path fails closed rather than silently unsigned.
    The explicit path being *absent* still degrades gracefully.
    """
    candidates: list[Path] = []
    env_path = os.environ.get("RAMP_AGENT_KEY_FILE")
    explicit = Path(env_path) if env_path else None
    if explicit is not None:
        candidates.append(explicit)
    candidates.append(Path("deploy/mcp/agent-key.json"))
    candidates.append(Path(_DEFAULT_KEY_PATH))

    for path in candidates:
        if path.is_file():
            try:
                key = AgentKey.from_file(path)
                key.private_key()  # validate the seed now; corrupt ⇒ absent (or raise)
            except (OSError, ValueError, KeyError) as exc:
                if require_valid_explicit and explicit is not None and path == explicit:
                    msg = f"RAMP_AGENT_KEY_FILE {path} is present but unusable: {exc}"
                    raise AgentKeyConfigError(msg) from exc
                logger.warning("agent-key load failed at %s: %s", path, exc)
                continue
            return key
    logger.info("no RAMP agent key found; outbound requests will be unsigned")
    return None


def make_signing_async_client(
    *,
    timeout: httpx.Timeout | float | None = None,
    follow_redirects: bool = False,
    key: AgentKey | None = None,
) -> httpx.AsyncClient:
    """Return an httpx.AsyncClient that stamps RFC 9421 signatures on each call.

    When ``key`` is None the loader is consulted with ``require_valid_explicit``
    so a malformed, explicitly-configured ``RAMP_AGENT_KEY_FILE`` fails closed
    (raising :class:`AgentKeyConfigError`) rather than silently returning an
    unsigned client. When no key is configured at all, a plain client is
    returned so local-only flows keep working.
    """
    agent_key = key if key is not None else load_agent_key(require_valid_explicit=True)
    if agent_key is None:
        return httpx.AsyncClient(timeout=timeout, follow_redirects=follow_redirects)
    inner = httpx.AsyncHTTPTransport()
    transport = SigningTransport(inner, Signer(agent_key))
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )
