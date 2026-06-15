"""E2E: the Broker publishes a live key-revocation channel.

Read-only assertions that the Broker advertises ``invalidation_url`` in its
unified manifest and serves a schema-shaped ``KeyInvalidationList`` at that
route. The Exchange-side consumer (poller + revoke-on-lookup) is covered by the
Go integration test ``src/exchange/cmd/server/revocation_integration_test.go``;
this test deliberately does NOT revoke a kid, so it never mutates the shared
stack's relay identity and cannot perturb the other E2E scenarios.
"""

from __future__ import annotations

import httpx

from .conftest import StackURLs

_TIMEOUT = 15.0
_EXPECTED_INVALIDATION_URL = "http://broker:8082/.well-known/ramp-invalidations.json"


def test_broker_manifest_advertises_invalidation_url(compose_stack: StackURLs) -> None:
    resp = httpx.get(f"{compose_stack.broker}/.well-known/ramp.json", timeout=_TIMEOUT)
    assert resp.status_code == httpx.codes.OK, resp.text
    manifest = resp.json()
    assert manifest["role"] == "ROLE_BROKER", manifest
    assert manifest.get("invalidation_url") == _EXPECTED_INVALIDATION_URL, manifest


def test_broker_serves_key_invalidation_list(compose_stack: StackURLs) -> None:
    resp = httpx.get(
        f"{compose_stack.broker}/.well-known/ramp-invalidations.json", timeout=_TIMEOUT
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    doc = resp.json()
    # KeyInvalidationList wire shape: as_of required; revoked optional (the
    # default baseline serves the empty, epoch-dated "nothing revoked" snapshot).
    as_of = doc.get("as_of")
    assert isinstance(as_of, str) and as_of, doc
    assert isinstance(doc.get("revoked", []), list), doc
