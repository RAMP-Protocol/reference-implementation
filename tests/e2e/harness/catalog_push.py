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
``push_catalog(exchange_url, tenant_id, entries, key_path)`` — sign + POST.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx

from ramp_sdk.b64 import b64url_decode
from .httpsig_signer import load_keypair, sign_request

_PUSH_PROCEDURE = "/ramp.v1.CatalogService/PushResources"


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
    # Publisher-declared licensing terms (proto3-JSON LicenseTerm dicts, camelCase
    # field names). Each term is surfaced on Offer.terms after the Exchange filters
    # them through licenseterm.Select for the requester. Use :func:`license_term`
    # to build a well-formed dict. Empty = legacy single-price entry.
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
    strict: bool = True,
) -> dict[str, Any]:
    """Sign + POST a ``PushResourcesRequest`` covering ``entries``.

    Returns the parsed ``PushResourcesResponse`` JSON (``accepted``,
    ``rejected``, ``warnings``, and the harness-side ``rejections`` detail
    when present) so callers can assert on partial-acceptance and warning
    behaviour — the public PUSH surface this slice exercises.

    The caller_id is the Ed25519 key's ``kid``, which must match both a
    ``ramp.agents.agent_id`` row (Gate 1) and a
    ``catalog_contributors[].domain`` entry in the publisher's ``ramp.json``
    (Gate 2).

    ``strict`` (default ``True``) preserves the original fail-loud contract:
    every entry MUST be accepted or the harness cannot proceed with a partial
    catalog. Tests that DELIBERATELY push rejectable or warning-bearing
    entries pass ``strict=False`` and inspect the returned counts themselves.
    An HTTP-level failure (protovalidate reject at the RPC boundary, signature
    refusal) always raises regardless of ``strict`` — it is never a per-entry
    outcome.
    """
    if not entries:
        return {"accepted": 0, "rejected": 0, "warnings": []}
    kid, priv = load_keypair(key_path)
    body = _build_request_json(tenant_id=tenant_id, caller_id=kid, entries=entries)
    url = exchange_url.rstrip("/") + _PUSH_PROCEDURE
    sig_headers = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv).headers
    headers = {**sig_headers, "Content-Type": "application/json"}
    resp = httpx.post(url, content=body, headers=headers, timeout=timeout)
    if resp.status_code != httpx.codes.OK:
        msg = f"PushResources failed: {resp.status_code} {resp.text[:512]}"
        raise RuntimeError(msg)
    payload = resp.json()
    if strict:
        accepted = payload.get("accepted", 0)
        rejected = payload.get("rejected", 0)
        rejections = payload.get("rejections", [])
        if accepted != len(entries) or rejected != 0:
            msg = (
                f"PushResources partial: accepted={accepted} rejected={rejected} "
                f"rejections={rejections} body={payload}"
            )
            raise RuntimeError(msg)
    return payload


# Proto3-JSON enum-name constants for LicenseTerm building (camelCase wire form).
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
    """Build a proto3-JSON Restriction dict (camelCase wire form).

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
    """Build a proto3-JSON LicenseTerm dict (camelCase wire form).

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


def _build_request_json(*, tenant_id: str, caller_id: str, entries: list[CatalogEntry]) -> bytes:
    """Shape the body per proto3-JSON conventions (camelCase field names)."""

    def _entry_json(e: CatalogEntry) -> dict[str, Any]:
        body: dict[str, Any] = {
            "domain": e.domain,
            "path": e.path,
            "content_id": e.content_id,
        }
        if e.required_scopes:
            body["required_scopes"] = list(e.required_scopes)
        if e.subscription_id is not None:
            body["subscription_id"] = e.subscription_id
        terms = e.terms or (
            license_term(
                model=PRICING_MODEL_PER_UNIT,
                rate=DEFAULT_ENTRY_RATE,
                unit="accesses",
                estimated_quantity=1,
            ),
        )
        body["terms"] = [dict(t) for t in terms]
        return body

    payload = {
        "tenant_id": tenant_id,
        "caller_id": caller_id,
        "entries": [_entry_json(e) for e in entries],
    }
    return json.dumps(payload, separators=(",", ":")).encode()


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
