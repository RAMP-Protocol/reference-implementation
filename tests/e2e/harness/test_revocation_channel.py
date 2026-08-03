"""E2E: the Broker publishes a live key-revocation channel end to end.

The producer-shape assertions confirm the Broker advertises ``revocation_url`` in
its Web Bot Auth directory (after the WBA split, identity/revocation moved off
ramp.json) and serves a schema-shaped ``KeyRevocationList`` at that route.

The cross-container test then closes the deployment-shaped gap the Go integration
test (``src/exchange/cmd/server/revocation_integration_test.go``, single-process
with an in-process origin) cannot: it revokes a THROWAWAY, non-relay thumbprint
by writing the Broker's revocation file and asserts the Exchange container then
rejects a signature by that key (401). The throwaway key is used by no other
scenario and the test restores the empty baseline on teardown, so it never
perturbs the shared stack's relay identity or the other E2E scenarios.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from .conftest import StackURLs
from .httpsig_signer import key_thumbprint
from .constants import REVOCATION_PATH, WBA_DIRECTORY_PATH
from .signing import sign_post

_TIMEOUT = 15.0
_EXPECTED_REVOCATION_URL = f"http://broker:8082{REVOCATION_PATH}"

_HARNESS_DIR = Path(__file__).parent
_THROWAWAY_KEY_PATH = _HARNESS_DIR / "fixtures" / "revocation_throwaway_key.json"
_REVOCATION_FILE = _HARNESS_DIR / "revocations" / "revocations.json"
_REVOKE_DEADLINE_S = 30.0


def test_broker_wba_directory_advertises_revocation_url(compose_stack: StackURLs) -> None:
    resp = httpx.get(f"{compose_stack.broker}{WBA_DIRECTORY_PATH}", timeout=_TIMEOUT)
    assert resp.status_code == httpx.codes.OK, resp.text
    directory = resp.json()
    # WBA directory: keys[] (no kid) plus a directory-level revocation_url.
    assert isinstance(directory.get("keys"), list) and directory["keys"], directory
    assert directory.get("revocation_url") == _EXPECTED_REVOCATION_URL, directory


def test_broker_serves_key_revocation_list(compose_stack: StackURLs) -> None:
    resp = httpx.get(f"{compose_stack.broker}{REVOCATION_PATH}", timeout=_TIMEOUT)
    assert resp.status_code == httpx.codes.OK, resp.text
    doc = resp.json()
    # KeyRevocationList wire shape: as_of required; revoked optional (the default
    # baseline serves the empty, epoch-dated "nothing revoked" snapshot). After
    # the WBA split the revoked[] entries are RFC 7638 thumbprints, not kids.
    as_of = doc.get("as_of")
    assert isinstance(as_of, str) and as_of, doc
    assert isinstance(doc.get("revoked", []), list), doc


def _now_rfc3339() -> str:
    """Current UTC time as an RFC 3339 'Z' timestamp the revocation schema accepts."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def test_broker_revocation_rejects_signature_across_containers(
    compose_stack: StackURLs,
) -> None:
    """Broker revokes a throwaway thumbprint → Exchange container rejects it (401).

    The throwaway key is published in the Broker's WBA directory (deploy/broker/
    keys.json), so the Exchange resolves it via the broker revocation channel. A
    signed DiscoverResources verifies while the key is unrevoked; after the Broker
    revocation file names its thumbprint and the Exchange's poller picks it up, the
    same signed call is rejected at the httpsig gate. This is the deployment-shaped
    revoke→poll→reject the single-process Go test cannot exercise.
    """
    thumbprint = key_thumbprint(_THROWAWAY_KEY_PATH)
    discover_url = f"{compose_stack.exchange}/ramp.v1.ExchangeService/DiscoverResources"
    body = {"ver": "1.0", "uris": ["https://example.com/revocation-probe"]}

    # Baseline: the throwaway key is not revoked, so its signature verifies (the
    # httpsig gate does not reject it). The lazy first lookup also warms the
    # Exchange's broker-directory + revocation snapshot.
    before = sign_post(discover_url, body=body, key_path=_THROWAWAY_KEY_PATH)
    assert before.status_code != httpx.codes.UNAUTHORIZED, (
        f"throwaway key must verify before revocation; got {before.status_code}: {before.text[:512]}"
    )

    try:
        # Revoke: write a KeyRevocationList naming the throwaway thumbprint. The
        # Broker re-reads the file on mtime change; the Exchange's 1s poller then
        # refreshes and the same signature is rejected within a bounded wait.
        _REVOCATION_FILE.write_text(json.dumps({"as_of": _now_rfc3339(), "revoked": [thumbprint]}))

        last = before.status_code
        deadline = time.monotonic() + _REVOKE_DEADLINE_S
        while time.monotonic() < deadline:
            resp = sign_post(discover_url, body=body, key_path=_THROWAWAY_KEY_PATH)
            last = resp.status_code
            if resp.status_code == httpx.codes.UNAUTHORIZED:
                break
            time.sleep(1.0)
        else:
            pytest.fail(
                f"Exchange never rejected the revoked key across containers "
                f"within {_REVOKE_DEADLINE_S:.0f}s; last status {last}"
            )
    finally:
        # Restore the nothing-revoked baseline so a reused stack starts clean and
        # the throwaway key does not stay revoked for any later scenario.
        _REVOCATION_FILE.unlink(missing_ok=True)
