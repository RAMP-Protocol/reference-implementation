"""Push ramp.v1.CatalogService/PushResources for the e2e harness, through the SDK.

Why this exists
---------------
The Exchange holds its catalog in an in-memory radix trie that is loaded
once at startup and subsequently mutated ONLY through the signed
``PushResources`` RPC (see ``src/exchange/internal/service/catalog.go``).
The admin reload endpoint the harness used to call was removed — the
tripwires at ``src/exchange/cmd/server/admin_removed_test.go`` and
``src/exchange/internal/transport/admin_removed_e2e_test.go`` make that
policy loud.

The push goes through the Python SDK's own catalog client
(``ramp_sdk.sync.CatalogClient``), so the harness sends what a real
third-party catalog pusher sends and clears the same gates:

- **Gate 1** (httpsig, RFC 9421): the request is signed with an Ed25519
  key. The Exchange resolves it for the request's ``kid`` — from the kid's
  Web Bot Auth directory on first sight — and refuses a kid that serves no
  key.
- **Gate 2** (contributor authorization): the caller must be the publisher
  itself or appear in the publisher's ``ramp.json#catalog_contributors``.
  The e2e edge worker advertises the harness contributor via
  ``CATALOG_CONTRIBUTORS_JSON``.

Every e2e test that needs catalog data therefore implicitly verifies
that RPC + both gates still work — no separate coverage needed.

What the SDK client does that a hand-built POST did not: it refuses a
request that names no recipient (``exchange`` must be a bare host), stamps
``ver``, checks the request against the generated wire schema before
signing, refuses redirects, caps the response read and validates the
answer against the schema.

All-or-nothing
--------------
``PushResources`` stores a submission whole or refuses it whole. A refusal
is a non-2xx Connect error, which the SDK raises as
``ramp_sdk.client.CallError`` carrying the HTTP ``status``, the Connect code
as ``reason`` and the Exchange's message (which names each offending entry)
as the cause. A caller therefore never sees a partially accepted response,
and there is no per-entry verdict to inspect: ``PushResourcesResponse``
carries a ``rejected`` count on the wire, but the reference Exchange never
sets it.

Public surface
--------------
``push_catalog(exchange_url, tenant_id, entries, key_path)`` — one SDK call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from ramp_sdk import ProtocolVersion
from ramp_sdk.b64 import b64url_decode
from ramp_sdk.client import ClientConfig
from ramp_sdk.sync import CatalogClient
from wire.models import PushResourcesResponse

from .exchanges import recipient_of
from .httpsig_signer import load_keypair, signing_transport


def _format_money(rate: float) -> str:
    """Render a numeric rate as the canonical RAMP wire money STRING.

    Money-as-string: ``Pricing.rate`` (and every other money field) is an
    exact decimal STRING on the wire, never a JSON number — the Exchange's
    protovalidate rejects ``{"rate": 0.0}`` ("invalid value for string field
    rate"). This mirrors the Go ``helpers.FormatMoney`` semantics the
    Exchange itself uses (sdk/go/helpers/money.go): no sign, no exponent,
    insignificant trailing fractional zeros stripped — 5.0 -> "5", 0.05 ->
    "0.05", 0 -> "0". ``Decimal(str(rate))`` takes the exact decimal from the
    literal (avoiding binary-float artefacts) before normalising.
    """
    text = format(Decimal(str(rate)), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


@dataclass(frozen=True)
class CatalogEntry:
    """One resource to seed. Mirrors ``ramp.v1.ResourceEntry`` on the wire."""

    domain: str
    path: str
    content_id: str
    # Publisher-declared licensing terms: LicenseTerm dicts under the canonical
    # snake_case wire names. Each term is surfaced on Offer.terms after the
    # Exchange projects the entry's terms by the requester's scope coverage
    # (``selectTerms`` in ``src/exchange/internal/service/termselect.go``). Use
    # :func:`license_term` to build a well-formed dict. Empty = the entry is
    # pushed with the default per-access term (``DEFAULT_ENTRY_RATE``).
    terms: tuple[dict[str, Any], ...] = ()


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
) -> PushResourcesResponse:
    """Push ``entries`` to the Exchange at ``exchange_url`` through the SDK client.

    Returns the parsed ``PushResourcesResponse`` (``accepted`` and
    ``warnings``) so callers can assert on the warning behaviour — the public
    PUSH surface this harness exercises. A refusal never returns: the SDK
    raises ``CallError`` for a non-2xx answer (a protovalidate reject at the
    RPC boundary, a Gate-1 or Gate-2 refusal, an entry the service rejects —
    all of which refuse the whole submission) and for a request it declines
    to send (no recipient, a body the wire schema refuses). There is no
    partial acceptance to assert on.

    On a 2xx, ``accepted == len(entries)`` is the Exchange's all-or-nothing
    contract, so it is checked here as an invariant: a 2xx that accepted fewer
    entries than it was sent is a server defect and raises ``RuntimeError``.

    The caller_id is the keyfile's ``kid``, which must name a Web Bot Auth
    directory that serves the key (Gate 1) and be the publisher domain or a
    ``catalog_contributors[].domain`` entry in the publisher's ``ramp.json``
    (Gate 2).
    """
    kid, priv = load_keypair(key_path)
    request = _request(
        exchange=recipient_of(exchange_url),
        tenant_id=tenant_id,
        caller_id=kid,
        entries=entries,
    )
    # No process-wide signing window here, unlike the agent clients: the
    # replay store records (keyid, signature) pairs, and a push signs its own
    # body, so two pushes collide only when they carry identical entries in
    # one second — a harness bug, not a burst to disambiguate.
    config = ClientConfig(
        base_url=exchange_url,
        signer=signing_transport(kid, priv),
        call_timeout_sec=timeout,
    )
    with CatalogClient(config) as client:
        response = client.push_resources(request)
    if response.accepted != len(entries):
        msg = (
            f"PushResources answered 2xx but accepted {response.accepted} of "
            f"{len(entries)} entries; the Exchange stores a submission whole or "
            f"refuses it whole: {response!r}"
        )
        raise RuntimeError(msg)
    return response


# Enum-name constants for LicenseTerm building, as the wire carries them.
PRICING_MODEL_FREE = "PRICING_MODEL_FREE"
PRICING_MODEL_PER_UNIT = "PRICING_MODEL_PER_UNIT"
PRICING_MODEL_FLAT = "PRICING_MODEL_FLAT"

# TermSemantics enum-name constants. Every LicenseTerm MUST declare its
# semantics (UNSPECIFIED is rejected at ingest by protovalidate CEL
# license_term.semantics_specified). ENUMERATED = the machine fields are
# authoritative (the default for priced terms with no governing document);
# REFERENCE_ONLY = the machine fields defer to a License document and MUST
# carry a non-empty license.uri.
TERM_SEMANTICS_ENUMERATED = "TERM_SEMANTICS_ENUMERATED"
TERM_SEMANTICS_REFERENCE_ONLY = "TERM_SEMANTICS_REFERENCE_ONLY"

RESTRICTION_KIND_FUNCTION = "RESTRICTION_KIND_FUNCTION"
RESTRICTION_KIND_USER_TYPE = "RESTRICTION_KIND_USER_TYPE"
RESTRICTION_KIND_GEOGRAPHY = "RESTRICTION_KIND_GEOGRAPHY"

OBLIGATION_KIND_SHARE_ALIKE = "OBLIGATION_KIND_SHARE_ALIKE"

# Every Obligation MUST declare its firing trigger; UNSPECIFIED is rejected at
# ingest (protovalidate CEL obligation.trigger_specified).
OBLIGATION_TRIGGER_ON_USE = "OBLIGATION_TRIGGER_ON_USE"
OBLIGATION_TRIGGER_ON_DISTRIBUTION = "OBLIGATION_TRIGGER_ON_DISTRIBUTION"


def restriction(
    kind: str,
    *,
    permitted: tuple[str, ...] = (),
    prohibited: tuple[str, ...] = (),
    advisory: bool = False,
) -> dict[str, Any]:
    """Build a Restriction dict under the canonical snake_case wire names.

    ``advisory`` mirrors proto ``Restriction.advisory`` (replaced the old
    ``critical``, semantics inverted): omitted/false = binding (the default),
    true = advisory. Under scope-only projection the Exchange does not evaluate
    restrictions at discovery, so this flag is offer metadata for the agent's
    self-selection (ADR-014 §Selection).
    """
    r: dict[str, Any] = {"kind": kind}
    if permitted:
        r["permitted"] = list(permitted)
    if prohibited:
        r["prohibited"] = list(prohibited)
    if advisory:
        r["advisory"] = True
    return r


def license_term(
    *,
    model: str,
    rate: float = 0.0,
    currency: str = "USD",
    unit: str | None = None,
    estimated_quantity: int | None = None,
    restrictions: tuple[dict[str, Any], ...] = (),
    obligations: tuple[dict[str, Any], ...] = (),
    semantics: str = TERM_SEMANTICS_ENUMERATED,
) -> dict[str, Any]:
    """Build a LicenseTerm dict under the canonical snake_case wire names.

    Pricing is always emitted — the Exchange hard-rejects a term with no
    Pricing. ``model=FREE`` must keep ``rate=0`` (protovalidate CEL).
    ``model=PER_UNIT`` requires ``unit`` (protovalidate CEL); pass it.
    ``semantics`` defaults to ENUMERATED (machine fields authoritative); it MUST
    be set — UNSPECIFIED is rejected at ingest. REFERENCE_ONLY additionally
    requires a non-empty ``license.uri``.
    """
    # Money-as-string: rate rides as a canonical decimal STRING on the wire.
    pricing: dict[str, Any] = {"model": model, "rate": _format_money(rate), "currency": currency}
    if unit is not None:
        pricing["unit"] = unit
    if estimated_quantity is not None:
        pricing["estimated_quantity"] = estimated_quantity
    term: dict[str, Any] = {"semantics": semantics, "pricing": pricing}
    if restrictions:
        term["restrictions"] = list(restrictions)
    if obligations:
        term["obligations"] = list(obligations)
    return term


# Default per-access rate stamped on an entry that declares no terms. Slice 5
# made offer pricing strictly term-derived — an entry with zero LicenseTerms
# yields NO offer. The pre-Slice-5 Exchange stamped a constant rate at push;
# the harness now reproduces that at ingest so legacy single-price seed sites
# (which only need "an offer exists at the platform rate") keep working without
# every call site spelling out a term. Sites that assert a SPECIFIC price (or
# need FREE) pass an explicit `terms=(...)` and bypass this default.
DEFAULT_ENTRY_RATE = 0.05


def _request(
    *, exchange: str, tenant_id: str, caller_id: str, entries: list[CatalogEntry]
) -> dict[str, Any]:
    """The ``PushResourcesRequest`` under its canonical snake_case wire names.

    ``ver`` is stamped here from ``ramp_sdk.ProtocolVersion``. The SDK would
    fill an empty one from the same constant, but the harness guard holds every
    request-body literal to that constant, so a wrong or missing value cannot
    hide behind the SDK filling it in — see the comment on the field below.
    ``exchange`` is the recipient's bare host: the SDK requires it and refuses
    to derive it from the dial address, because the field states whom the sender
    meant.
    """

    def _entry(e: CatalogEntry) -> dict[str, Any]:
        terms = e.terms or (
            license_term(
                model=PRICING_MODEL_PER_UNIT,
                rate=DEFAULT_ENTRY_RATE,
                unit="accesses",
                estimated_quantity=1,
            ),
        )
        return {
            "domain": e.domain,
            "path": e.path,
            "content_id": e.content_id,
            "terms": [dict(t) for t in terms],
        }

    return {
        # Stamped from the single constant every sender uses; the SDK would fill
        # an empty ver itself, but the harness guard holds every body literal to
        # the constant so a wrong or missing value cannot hide behind that.
        "ver": ProtocolVersion,
        # Who the push is addressed to, taken from the host it is sent to — the
        # same derivation the production ingester does.
        "exchange": exchange,
        "tenant_id": tenant_id,
        "caller_id": caller_id,
        "entries": [_entry(e) for e in entries],
    }


__all__ = [
    "OBLIGATION_KIND_SHARE_ALIKE",
    "OBLIGATION_TRIGGER_ON_DISTRIBUTION",
    "OBLIGATION_TRIGGER_ON_USE",
    "PRICING_MODEL_FLAT",
    "PRICING_MODEL_FREE",
    "PRICING_MODEL_PER_UNIT",
    "RESTRICTION_KIND_FUNCTION",
    "RESTRICTION_KIND_GEOGRAPHY",
    "RESTRICTION_KIND_USER_TYPE",
    "TERM_SEMANTICS_ENUMERATED",
    "TERM_SEMANTICS_REFERENCE_ONLY",
    "CatalogEntry",
    "license_term",
    "load_public_key_bytes",
    "push_catalog",
    "restriction",
]
