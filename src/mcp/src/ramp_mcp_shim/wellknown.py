"""Producer for the agent's ``/.well-known/ramp.json`` discovery manifest.

Every RAMP participant publishes a ``ramp.v1.WellKnownManifest`` at the fixed
path ``/.well-known/ramp.json``. This shim plays the AGENT role: it advertises
its identity (``domain``) and the Ed25519 signing key it uses for outbound
RFC 9421 request signatures (see :mod:`ramp_mcp_shim.httpsig`), so a Broker /
Exchange can fetch the manifest and verify the shim's signatures.

The served JSON mirrors the canonical wire shape exactly — protojson with
``UseProtoNames=true``: snake_case field names, full enum value names
(``ROLE_AGENT``), ``x`` = base64url (no padding) of the raw 32-byte public
key, and RFC 3339 key-validity windows. The Pydantic field names below are
already snake_case, so ``model_dump(mode="json")`` produces wire-correct JSON
that the Go ``rampwellknown`` consumer parses.

Time comes from the injected :class:`ramp_mcp_shim.clock.Clock` (ADR-008 D1);
this module never touches the wall clock directly.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, Field, field_serializer, field_validator

from .clock import Clock, system_clock
from .signing_client import load_agent_key

if TYPE_CHECKING:
    from .httpsig import AgentKey

__all__ = [
    "AgentManifest",
    "JsonWebKey",
    "build_agent_manifest",
    "load_agent_manifest",
]

# Key validity window relative to "now": opened an hour in the past to absorb
# small clock skew between the shim and a verifying peer, and a decade forward
# so the demo / e2e key never silently expires mid-run. 3650 days ~= 10 years.
_KEY_BACKDATE = timedelta(hours=1)
_KEY_LIFETIME = timedelta(days=3650)


def _public_key_x(key: AgentKey) -> str:
    """Return base64url (no padding) of the key's raw 32-byte Ed25519 public key."""
    raw = key.private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _rfc3339(instant: datetime) -> str:
    """Format a UTC-aware ``instant`` as RFC 3339 with a ``Z`` suffix.

    The Go consumer parses with ``time.RFC3339`` and the schema requires a
    ``Z`` or numeric offset; ``isoformat`` on a UTC-aware datetime yields
    ``+00:00``, so we normalise that tail to ``Z``.
    """
    return instant.astimezone(UTC).isoformat().replace("+00:00", "Z")


class JsonWebKey(BaseModel):
    """Inline Ed25519 JWK published in ``public_keys`` (RFC 8037 shape).

    Field names are the snake_case wire names; the ``Literal`` ``kty``/``crv``/
    ``use``/``alg`` constants make the only valid values unrepresentable as
    anything else. ``not_before``/``not_after`` are real ``datetime`` instants;
    a JSON dump serialises them to RFC 3339 (``…Z``) via the field serializer.
    """

    kid: str = Field(description="Key identifier; matches the signing key's kid")
    kty: Literal["OKP"] = Field(default="OKP", description="Key type — Octet Key Pair")
    crv: Literal["Ed25519"] = Field(default="Ed25519", description="Curve")
    use: Literal["sig"] = Field(default="sig", description="Public key use — signature")
    alg: Literal["EdDSA"] = Field(default="EdDSA", description="Algorithm")
    x: str = Field(description="base64url(raw 32-byte public key), no padding")
    not_before: datetime = Field(description="Start of validity (inclusive)")
    not_after: datetime = Field(description="End of validity (exclusive)")

    @field_validator("not_before", "not_after")
    @classmethod
    def _require_aware(cls, value: datetime) -> datetime:
        """Reject naive datetimes: a tz-naive instant would be misread as local
        time by the RFC 3339 serializer (``astimezone``), corrupting the wire
        value. Production always feeds tz-aware instants from the Clock; this
        guards direct construction.
        """
        if value.tzinfo is None:
            msg = "not_before/not_after must be timezone-aware"
            raise ValueError(msg)
        return value

    @field_serializer("not_before", "not_after", when_used="json")
    def _serialize_window(self, value: datetime) -> str:
        """Emit RFC 3339 with a ``Z`` suffix on the JSON wire."""
        return _rfc3339(value)


class AgentManifest(BaseModel):
    """``/.well-known/ramp.json`` document for the AGENT role.

    ``model_dump(mode="json")`` yields the exact protojson wire shape the
    ``rampwellknown`` consumer expects. ``ver``/``role`` are pinned ``Literal``
    constants: ``ver`` is the only value the consumer accepts and ``role`` is the
    full proto enum value name (protojson ``UseProtoNames``).
    """

    ver: Literal["1.0"] = Field(default="1.0", description="Protocol version (always 1.0)")
    role: Literal["ROLE_AGENT"] = Field(default="ROLE_AGENT", description="Participant role")
    domain: str = Field(description="The agent's domain / identity")
    public_keys: list[JsonWebKey] = Field(description="Active signing keys (>= 1 for agents)")


def build_agent_manifest(
    domain: str, key: AgentKey, *, clock: Clock | None = None
) -> AgentManifest:
    """Assemble the AGENT manifest from ``domain`` and the loaded signing ``key``.

    The single published JWK carries the key's ``kid`` and its base64url raw
    public key, with a validity window of ``[now - 1h, now + ~10y)`` taken from
    the injected :class:`Clock` (never the wall clock directly).
    """
    now = (clock if clock is not None else system_clock()).now()
    jwk = JsonWebKey(
        kid=key.kid,
        x=_public_key_x(key),
        not_before=now - _KEY_BACKDATE,
        not_after=now + _KEY_LIFETIME,
    )
    return AgentManifest(domain=domain, public_keys=[jwk])


def load_agent_manifest(domain: str | None, *, clock: Clock | None = None) -> AgentManifest | None:
    """Build the manifest from ``domain`` + the on-disk agent key, or ``None``.

    Returns ``None`` (so the route can answer 404) when discovery cannot be
    published: either ``domain`` (``RAMP_AGENT_ID``) is absent, or no agent key
    is configured. Key resolution reuses :func:`load_agent_key`, matching the
    tolerance the outbound signing path already applies on a keyless dev run.
    """
    if not domain:
        return None
    key = load_agent_key()
    if key is None:
        return None
    return build_agent_manifest(domain, key, clock=clock)
