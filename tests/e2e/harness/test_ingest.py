"""Full e2e: the REAL ramp-ingest binary over the live stack (demo feeds).

The seed already ingests the three demo feeds through the production
``cmd/ramp-ingest`` binary (signed ``CatalogService/PushResources`` RPCs, one
per submission of at most the wire bound; each demo feed fits in one) — there
is no SQL backdoor and no Python mapper. This module proves that path directly
and idempotently:

* re-running the binary against a demo feed exits 0 and reports every entry
  accepted (the production parse → map → sign → push pipeline is stable across
  runs);
* a requester discovers the ingested FREE socrates term, the resolved cost is
  term-derived (0), and the Exchange-signed URL delivers origin bytes through
  the Cloudflare edge;
* a requester that once mapped to a non-permitted geography (US on plato) is now
  LICENSED and receives a signed URL: per ADR-014's 2026-06-15 amendment the
  Exchange filters by resource_id + scopes ONLY and no longer excludes a term by
  the requester's self-declared user_type / geography — the restrictions ride on
  the returned offer for the agent to self-honour.

The binary ships in the runner image at ``/usr/local/bin/ramp-ingest``
(Go builder stage of tests/e2e/Dockerfile); we invoke it via subprocess,
mirroring how the seed shells out to it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import httpx

from .broker_client import execute_first_offer
from .conftest import StackURLs
from .constants import WBA_DIRECTORY_PATH
from .edge_fetch import fetch_signed
from .resolve_carriers import cost_of, first_item_of, licensed_of, retrieval_endpoint_of
from .seed import (
    CATALOG_CONTRIBUTOR_ID,
    CATALOG_DIR,
    CONTRIBUTOR_KEY_PATH,
    SELFPUB_PHILOSOPHY_KEY_PATH,
    SeededFixture,
)

# The philosophy feed (10 records) + the philosophy publisher's SELF-PUBLISH
# key (kid == demo.ramp-protocol.org). The Exchange learns this key ONLY by
# fetching the philosophy edge's Web Bot Auth directory (Gate-1
# self-signup) — there is NO ramp.agents pre-seed (Core Invariant).
#
# Taken from the seed's own CATALOG_DIR rather than rebuilt here: this test
# re-pushes the feed the seed already ingested and asserts the result is
# unchanged, so a second path would let the two drift and turn an idempotence
# test into a comparison of two different feeds.
_PHILOSOPHY_FEED = CATALOG_DIR / "philosophy.jsonl"
_PHILOSOPHY_DOMAIN = "demo.ramp-protocol.org"
_INGEST_BIN = "/usr/local/bin/ramp-ingest"


def _run_ingester(
    exchange_url: str, tenant_id: str, feed: Path, key_path: Path
) -> subprocess.CompletedProcess[str]:
    """Run the real ramp-ingest binary against the live Exchange.

    Exercises the exact production parse → map → sign → PushResources pipeline.
    ``key_path`` is the signing identity; its kid becomes the push caller_id, so
    the Exchange must learn that key via the well-known fetch (no DB pre-seed).
    Returns the completed process so callers can assert exit code + the
    structured accepted/warnings report written to stderr.
    """
    return subprocess.run(
        [
            _INGEST_BIN,
            "--exchange-url",
            exchange_url,
            "--tenant",
            tenant_id,
            "--key",
            str(key_path),
            str(feed),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def test_ingester_pushes_via_rpc_and_exits_clean(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers tenant + contributor
) -> None:
    """Re-running the real ingester on the philosophy feed is idempotent and stores every entry.

    Re-pushing via the signed RPC under the philosophy publisher's OWN
    self-publish key (kid == demo.ramp-protocol.org) must again exit 0 and
    report accepted=10 — the Exchange stores or refuses a submission whole and
    the binary exits non-zero on a refusal, so the exit code is the verdict —
    confirming the production push path (parse → map → sign → push → verdict)
    is stable and the self-publish key remains resolvable via the well-known
    fetch across runs (no DB pre-seed).
    """
    proc = _run_ingester(
        compose_stack.exchange,
        "tenant-demo-philosophy",
        _PHILOSOPHY_FEED,
        SELFPUB_PHILOSOPHY_KEY_PATH,
    )
    assert proc.returncode == 0, (
        f"ingester failed: rc={proc.returncode}\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}"
    )
    assert "push: accepted=10 warnings=" in proc.stderr, proc.stderr


def test_requester_discovers_free_term_and_gets_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A requester discovers the ingested FREE socrates term and is delivered bytes.

    The term was produced by the real ingester from the philosophy feed's FREE
    offer. The Exchange no longer filters by the requester's user_type / geography
    (ADR-014, 2026-06-15), so the requester discovers the term, the term-derived
    cost is 0 (FREE), and the Exchange-signed URL delivers the origin content
    through the Cloudflare edge.

    Two-phase relay: Broker Resolve is discovery-only (it returns ranked
    signed Offers, no signed URL). The agent then RELAY-EXECUTES the winning Offer
    (agent sig1 + Broker sig2 + offer-acceptance) through the Broker to the
    Exchange, which mints the signed URL and returns the term-derived cost on the
    TransactionResponse.
    """
    res = seeded.free  # socrates: FREE EUR
    resp = execute_first_offer(
        compose_stack,
        {"agent_id": res.buyer_agent_id, "uri": res.uri, "intended_use": "ai-input"},
        agent_id=res.buyer_agent_id,
        domain=_PHILOSOPHY_DOMAIN,
        key_path=res.buyer_key_path,
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    # The EXECUTE response is an items[] envelope — read the
    # per-result fields from items[0]. The licensed signal is the delivered
    # retrieval_endpoint on items[0], not the discovery-only Resolve.
    payload = resp.json()
    item = first_item_of(payload)
    assert item is not None, f"execute response carried no items[0]: {payload}"
    assert licensed_of(item) is True, payload
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, payload
    # ADR-019: the FREE-term delivered price rides on the canonical typed
    # per-item cost (Exchange buildBatchResultItem). socrates' headline term is
    # FREE, so the agent observes cost.amount == 0.
    cost = cost_of(item)
    assert cost is not None, payload
    # Money-as-string: Money.amount is a decimal STRING on the wire
    # (FormatMoney: 0 → "0"); the FREE term's cost is zero either as the
    # canonical "0" string or a numeric 0, so parse before comparing.
    assert float(cost["amount"]) == 0, cost

    # The relay-minted URL is bound to the executing agent — fetch_signed attaches
    # RFC 9421 proof-of-possession headers when key_path is set and the URL carries
    # agent_id= (edge enforces agent_id == keyid == thumbprint of presented key).
    content = fetch_signed(signed_url, compose_stack, timeout=15.0, key_path=res.buyer_key_path)
    assert content.text.strip(), content.text


def test_us_requester_now_licensed_on_geo_restricted_resource(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A requester whose geography plato's terms do not permit is now LICENSED (flip).

    Pre-ADR-014 a US commercial requester got no offer on plato (its terms permit
    only EU). The Exchange no longer excludes a term by the requester's
    self-declared geography — the geography restriction rides on the returned
    offer for the agent to self-honour — so the requester is licensed and
    receives a signed URL. (user_type / geography are no longer sent on the wire.)

    R7: discovery (Broker Resolve) then relay-execute the winning Offer; the
    signed URL is minted on the EXECUTE (TransactionResponse).
    """
    res = seeded.restricted  # plato
    resp = execute_first_offer(
        compose_stack,
        {"agent_id": res.buyer_agent_id, "uri": res.uri, "intended_use": "ai-input"},
        agent_id=res.buyer_agent_id,
        domain=_PHILOSOPHY_DOMAIN,
        key_path=res.buyer_key_path,
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    # C2: read the per-result fields from items[0] of the EXECUTE envelope.
    payload = resp.json()
    item = first_item_of(payload)
    assert item is not None, f"execute response carried no items[0]: {payload}"
    assert licensed_of(item) is True, payload
    assert retrieval_endpoint_of(item), payload


def test_contributor_identity_is_served_via_wellknown(compose_stack: StackURLs) -> None:
    """Guard: the contributor's served well-known key matches its signing fixture.

    The well-known-trust rule removed the ramp.agents pre-seed: the Exchange learns the
    ``catalog-contributor-e2e`` key ONLY by fetching that contributor's own
    discovery documents (the ``catalog-contributor-e2e-jwks`` compose host). This guard
    fetches them through the real host and asserts (a) the keyless overlay
    manifest's ``domain`` equals the contributor's agent_id (matched by
    caller_id), and (b) the key served in the contributor's WBA directory (x)
    byte-matches the private signing fixture's public half — so the key the
    Exchange fetches is exactly the key the harness signs with. A drift here
    would fail Gate-1 for a reason unrelated to the push path.
    """
    import base64
    import json

    doc = json.loads(Path(CONTRIBUTOR_KEY_PATH).read_text())
    assert doc["kid"] == CATALOG_CONTRIBUTOR_ID
    assert _PHILOSOPHY_FEED.is_file(), _PHILOSOPHY_FEED

    # Fetch the contributor's served overlay + WBA directory THROUGH the real
    # host alias. After the WBA split the overlay is keyless; the signing key
    # lives in the WBA directory keys[] (no kid, named by thumbprint).
    manifest = httpx.get(
        f"http://{CATALOG_CONTRIBUTOR_ID}/.well-known/ramp.json", timeout=5.0
    ).json()
    assert manifest.get("domain") == CATALOG_CONTRIBUTOR_ID, manifest
    assert "public_keys" not in manifest, manifest
    directory = httpx.get(
        f"http://{CATALOG_CONTRIBUTOR_ID}{WBA_DIRECTORY_PATH}",
        timeout=5.0,
    ).json()
    served = directory.get("keys") or []
    assert len(served) == 1, f"contributor WBA directory must serve one key; got {served!r}"
    key = served[0]
    assert "kid" not in key, f"WBA key must not carry a kid: {key!r}"
    # The served `x` (base64url, no pad) must equal the fixture's public half.
    fixture_pub = doc["public_key"].rstrip("=")
    assert key["x"].rstrip("=") == fixture_pub, (
        f"served contributor key drifted from signing fixture: "
        f"served={key['x']!r} fixture={doc['public_key']!r}"
    )
    # Sanity: the served x decodes to a 32-byte Ed25519 raw key.
    raw = base64.urlsafe_b64decode(key["x"] + "=" * (-len(key["x"]) % 4))
    assert len(raw) == 32, f"served key not 32 raw bytes: {len(raw)}"
