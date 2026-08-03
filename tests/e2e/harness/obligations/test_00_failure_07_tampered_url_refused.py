"""Obligation 00 — failure 07: tampered signed URL is refused at delivery.

Scenario (verbatim — fourth failure-mode bullet):

> The URL delivered after acceptance is tampered with by the caller.
> The content is not served; the caller sees the delivery refused.

Drives the scenario against the demo ``paper-satellites`` resource (FLAT USD, no
user-type restriction so it resolves via the facet-less canonical
DiscoveryRequest) as the USD demo buyer:

1. Acceptance — the relay execute returns ``licensed=true`` + a signed URL
   pointing at the music demo domain (→ Fastly edge).
2. Tamper — flip a base64url byte inside the ``sig=`` query parameter.
3. Refusal — the edge answers 403 and serves no publisher payload.

The refusal leg is a bespoke GET rather than the shared ``fetch_signed`` helper:
that helper asserts 200 and is for content delivery, while this asserts the
delivery does NOT happen. Proof-of-possession headers are still presented, so a
403 here means the tampered signature was refused — not that the fetch was
rejected for lacking a binding proof it could have supplied.
"""

from __future__ import annotations

import re

import httpx
import pytest

from ..broker_client import execute_first_offer
from ..conftest import StackURLs
from ..edge_fetch import edge_fetch_target
from ..resolve_carriers import first_item_of, licensed_of, retrieval_endpoint_of
from ..seed import SeededFixture
from ..signing import build_pop_headers

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The URL delivered after acceptance is tampered with by the caller. "
    "The content is not served; the caller sees the delivery refused."
)


# The paper-satellites body the edge must NOT serve when it refuses. Same marker
# the happy-path capstone asserts IS present (test_full_stack.py), used here for
# the opposite property.
_PUBLISHER_MARKER = "Paper Satellites"


def _tamper_sig(signed_url: str) -> tuple[str, str]:
    sig_match = re.search(r"sig=([^&]+)", signed_url)
    assert sig_match is not None, f"signed URL has no sig= query param: {signed_url}"
    sig_val = sig_match.group(1)
    assert len(sig_val) >= 2, f"sig= value too short to mutate ({sig_val!r})"
    mid = len(sig_val) // 2
    replacement = "B" if sig_val[mid] != "B" else "C"
    tampered_sig = sig_val[:mid] + replacement + sig_val[mid + 1 :]
    assert tampered_sig != sig_val, f"tamper produced the same sig: {sig_val!r}"
    return signed_url.replace(f"sig={sig_val}", f"sig={tampered_sig}"), sig_val


def test_tampered_signed_url_refused_no_content_served(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tampered ed25519-signed URL is refused; the publisher payload never leaks."""
    res = seeded.fastly  # paper-satellites: FLAT USD, no user-type restriction

    monkeypatch.setenv("RAMP_AGENT_ID", res.buyer_agent_id)
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(res.buyer_key_path))

    # (1) Acceptance — the two-phase flow: Broker discover (discovery-only, R7)
    # then relay-execute the winning Offer (agent sig1 + Broker sig2 +
    # offer-acceptance). The signed URL the EXECUTE (TransactionResponse) hands
    # back is the delivery surface the obligation refers to. intended_use
    # ``ai-input`` is the real function paper-satellites permits; the per-call
    # nonce keeps the signed body unique for the replay store.
    exec_resp = execute_first_offer(
        compose_stack,
        {
            "agent_id": res.buyer_agent_id,
            "uri": res.uri,
            "intended_use": "ai-input",
        },
        agent_id=res.buyer_agent_id,
        domain=res.domain,
        key_path=res.buyer_key_path,
    )
    assert exec_resp.status_code == 200, exec_resp.text
    # The EXECUTE response is an items[] envelope — read the
    # per-result fields from items[0]; licensed is derived from its presence.
    payload = exec_resp.json()
    item = first_item_of(payload)
    assert item is not None, f"relay response carried no items[0]: {payload}"
    assert licensed_of(item) is True, (
        f"prerequisite — the agent must first receive a delivered URL — failed: {payload}"
    )
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, (
        f"execute returned licensed=true but no items[0].retrievalEndpoint: {payload}"
    )

    # (2) Tamper — flip a sig byte. (3) The edge refuses it with 403 and serves
    # nothing.
    tampered_url, original_sig = _tamper_sig(signed_url)
    url, headers = edge_fetch_target(tampered_url, compose_stack)
    if "agent_id=" in url:
        headers = {**headers, **build_pop_headers(url=url, key_path=res.buyer_key_path)}
    resp = httpx.get(url, headers=headers, follow_redirects=True, timeout=30.0)

    assert resp.status_code == httpx.codes.FORBIDDEN, (
        f"obligation 00 failure-7: a tampered signature must be refused with 403, "
        f"got {resp.status_code}: {resp.text[:512]}; original sig={original_sig!r}; "
        f"tampered url={tampered_url!r}"
    )
    # The obligation is "the content is NOT SERVED", which the status alone does
    # not establish: an edge answering 403 while still writing the publisher body
    # would satisfy a status-only assertion and violate the obligation.
    assert _PUBLISHER_MARKER not in resp.text, (
        "obligation 00 failure-7: the edge refused with 403 but still served the "
        f"publisher payload: {resp.text[:512]}"
    )
