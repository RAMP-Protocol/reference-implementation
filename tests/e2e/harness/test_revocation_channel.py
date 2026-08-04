"""E2E: the Broker publishes a live key-revocation channel end to end.

The producer-shape assertions confirm the Broker advertises ``revocation_url`` in
its Web Bot Auth directory (after the WBA split, identity/revocation moved off
ramp.json) and serves a schema-shaped ``KeyRevocationList`` at that route.

The cross-container test then closes the deployment-shaped gap the Go integration
test (``src/exchange/cmd/server/revocation_integration_test.go``, single-process
with an in-process origin) cannot: it revokes a THROWAWAY, non-relay thumbprint
by writing the Broker's revocation file and asserts the Exchange container then
rejects a signature by that key. The throwaway key is used by no other scenario
and the test restores the empty baseline on teardown, so it never perturbs the
shared stack's relay identity or the other E2E scenarios.

Two mechanisms this test depends on, both easy to break silently:

**The revocation file crosses a container boundary through a shared host
directory.** ``harness/revocations/`` is bind-mounted into the Broker at
``/revocations`` AND into the pytest runner at ``/runner/harness/revocations``.
Drop the runner's mount and the write still succeeds — into the runner image's
own layer, where the Broker never sees it.

**A 401 from the Exchange has more than one cause.** The httpsig gate answers
``unauthenticated`` for a revoked key and for a replayed signature alike, so the
status code alone cannot tell them apart. Every assertion here reads the
rejection message. Requests are built through ``discovery.discover_body``, whose
fresh query id per call makes a replay collision impossible in the first place;
the message check is what catches it if that property ever breaks.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from .conftest import StackURLs
from .discovery import DISCOVER_PATH, discover_body
from .httpsig_signer import key_thumbprint, load_keypair
from .constants import REVOCATION_PATH, WBA_DIRECTORY_PATH
from .signing import sign_post

_TIMEOUT = 15.0
_EXPECTED_REVOCATION_URL = f"http://broker:8082{REVOCATION_PATH}"

_HARNESS_DIR = Path(__file__).parent
_THROWAWAY_KEY_PATH = _HARNESS_DIR / "fixtures" / "revocation_throwaway_key.json"
_REVOCATION_FILE = _HARNESS_DIR / "revocations" / "revocations.json"
_REVOKE_DEADLINE_S = 30.0
_PROBE_URI = "https://example.com/revocation-probe"

# Substrings that identify WHY the Exchange answered 401. The revoked text is
# resolvers.ErrKeyRevoked, which reaches the client unwrapped: the verify helper
# returns the resolver's error as-is, and the reject writer marshals it into the
# Connect error body. The replay text is connectserver.ErrReplayed.
_REVOKED_MARKER = "key revoked"
_REPLAY_MARKER = "replayed within window"


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


def _rfc3339(epoch_seconds: int) -> str:
    """``epoch_seconds`` as an RFC 3339 'Z' timestamp the revocation schema accepts.

    Taking the second as an argument rather than reading the clock is what lets
    teardown publish an ``as_of`` provably newer than the revocation's. The
    consumer ignores any snapshot whose ``as_of`` is not strictly newer than the
    one it already holds, so "later by construction" is the only safe way to
    withdraw a revocation.
    """
    stamp = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    return stamp.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _publish_revocations(*, as_of: int, thumbprints: list[str]) -> None:
    """Write the Broker's KeyRevocationList file.

    The Broker re-reads the file when its mtime changes, so the write alone is
    the whole publish step — no restart, no admin call.

    The file is left world-writable because it is written from two places with
    different uids: the pytest runner container runs as root, a host-side pytest
    run does not, and both share this one host directory. Without the mode a
    container run would leave a file no host run could rewrite.
    """
    _REVOCATION_FILE.write_text(json.dumps({"as_of": _rfc3339(as_of), "revoked": thumbprints}))
    _REVOCATION_FILE.chmod(0o666)


def _published_as_of(broker_url: str) -> int:
    """Epoch seconds of the ``as_of`` the Broker currently serves."""
    resp = httpx.get(f"{broker_url}{REVOCATION_PATH}", timeout=_TIMEOUT)
    assert resp.status_code == httpx.codes.OK, resp.text
    stamp = str(resp.json()["as_of"])
    return int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())


def _next_as_of(broker_url: str) -> int:
    """An ``as_of`` strictly newer than anything already published.

    The consumer ignores a snapshot whose ``as_of`` is not strictly newer than
    the one it holds, so the wall clock alone is not enough: two runs starting
    inside the same second would publish the same stamp and the second run's
    revocation would be discarded as a rollback. Bumping past what the Broker
    currently serves makes the chain monotonic by construction — the same
    GREATEST(as_of + 1, now) rule the identity service applies in SQL.
    """
    return max(int(time.time()), _published_as_of(broker_url) + 1)


def _probe(exchange_url: str, agent_id: str) -> httpx.Response:
    """One signed DiscoverResources by the throwaway key.

    The query id is fresh per call, so no two probes ever sign identical bytes
    and the replay guard cannot fire. DiscoverResources does not require the
    signing key to match ``requester.id`` — it never resolves the caller — so the
    throwaway key, which is registered in no agent directory, is a valid signer
    here.
    """
    return sign_post(
        f"{exchange_url}{DISCOVER_PATH}",
        body=discover_body(uris=[_PROBE_URI], agent_id=agent_id),
        key_path=_THROWAWAY_KEY_PATH,
    )


def _reject_message(resp: httpx.Response) -> str:
    """The Connect error message from a rejected response, or the raw body."""
    try:
        return str(resp.json().get("message", ""))
    except ValueError:
        return resp.text[:512]


def _assert_not_replay(resp: httpx.Response) -> None:
    """Fail if a 401 was caused by replay rather than by the revocation.

    A replay 401 means two probes signed identical bytes, which means the fresh
    query id stopped being fresh. That is a broken test, not a passing one, and
    it is exactly how this scenario used to report success without ever revoking
    anything.
    """
    message = _reject_message(resp)
    assert _REPLAY_MARKER not in message, (
        f"Exchange rejected the probe as a REPLAY, not a revocation: {message}. "
        f"Two probes signed identical bytes — the per-request query id is no longer unique."
    )


def _await_revoked(exchange_url: str, agent_id: str) -> None:
    """Poll until the Exchange rejects the throwaway key as revoked.

    The Exchange refreshes its revocation snapshot on a 1s poller in this stack,
    so the flip lands in a couple of seconds; the deadline is the outer bound.
    """
    deadline = time.monotonic() + _REVOKE_DEADLINE_S
    last = "no request issued"
    while time.monotonic() < deadline:
        resp = _probe(exchange_url, agent_id)
        if resp.status_code == httpx.codes.UNAUTHORIZED:
            _assert_not_replay(resp)
            message = _reject_message(resp)
            assert _REVOKED_MARKER in message, (
                f"Exchange rejected the probe with 401 but not for revocation: {message}"
            )
            return
        assert resp.status_code == httpx.codes.OK, (
            f"probe must answer 200 while the key still verifies; "
            f"got {resp.status_code}: {resp.text[:512]}"
        )
        last = f"{resp.status_code}"
        time.sleep(1.0)
    pytest.fail(
        f"Exchange never rejected the revoked key across containers within "
        f"{_REVOKE_DEADLINE_S:.0f}s; last status {last}. The Broker serves the "
        f"revocation file from a host directory the runner must share — check "
        f"that both mounts point at tests/e2e/harness/revocations."
    )


def _await_unrevoked(exchange_url: str, agent_id: str) -> None:
    """Poll until the throwaway key verifies again, after withdrawing the revocation."""
    deadline = time.monotonic() + _REVOKE_DEADLINE_S
    last = "no request issued"
    while time.monotonic() < deadline:
        resp = _probe(exchange_url, agent_id)
        if resp.status_code == httpx.codes.OK:
            return
        assert resp.status_code == httpx.codes.UNAUTHORIZED, (
            f"probe must answer 200 or 401 while the revocation clears; "
            f"got {resp.status_code}: {resp.text[:512]}"
        )
        _assert_not_replay(resp)
        last = f"{resp.status_code}: {_reject_message(resp)}"
        time.sleep(1.0)
    pytest.fail(
        f"the throwaway key stayed revoked after the withdrawal within "
        f"{_REVOKE_DEADLINE_S:.0f}s; last {last}. A reused stack now carries a "
        f"revoked key into every later run of this test."
    )


def test_broker_revocation_rejects_signature_across_containers(
    compose_stack: StackURLs,
) -> None:
    """Broker revokes a throwaway thumbprint, the Exchange container rejects it.

    The throwaway key is published in the Broker's WBA directory (deploy/broker/
    keys.json), so the Exchange resolves it through the broker revocation
    channel. A signed DiscoverResources returns 200 while the key is unrevoked;
    once the Broker's revocation file names its thumbprint and the Exchange's
    poller picks that up, the same call is rejected at the httpsig gate with
    "key revoked". This is the deployment-shaped revoke, poll, reject that the
    single-process Go test cannot exercise.

    Teardown withdraws the revocation instead of deleting the file. An absent
    file makes the Broker serve the epoch-dated empty snapshot, and the
    Exchange's monotonic guard discards it as a rollback — the key would stay
    revoked in the running container for every later run against the same stack.
    """
    agent_id, _priv = load_keypair(_THROWAWAY_KEY_PATH)
    thumbprint = key_thumbprint(_THROWAWAY_KEY_PATH)

    # A run killed between the revoke and the withdrawal leaves the throwaway
    # thumbprint revoked in a reused stack. Publish the empty baseline first, so
    # the assertion below can only fail for reasons belonging to THIS run.
    _publish_revocations(as_of=_next_as_of(compose_stack.broker), thumbprints=[])
    _await_unrevoked(compose_stack.exchange, agent_id)

    # Baseline: the throwaway key is not revoked, so the probe is licensable-or-not
    # business, not an auth failure. A URI absent from the catalog answers 200
    # with an empty OfferGroup carrying NOT_IN_CATALOG. The lazy first lookup also
    # warms the Exchange's broker-directory and revocation snapshot.
    before = _probe(compose_stack.exchange, agent_id)
    assert before.status_code == httpx.codes.OK, (
        f"throwaway key must verify before revocation; "
        f"got {before.status_code}: {before.text[:512]}"
    )

    revoke_at = _next_as_of(compose_stack.broker)
    try:
        _publish_revocations(as_of=revoke_at, thumbprints=[thumbprint])
        _await_revoked(compose_stack.exchange, agent_id)
    finally:
        # Withdraw with a strictly newer as_of so the Exchange accepts the empty
        # snapshot, and wait for it to take effect. The file STAYS: deleting it
        # would make the Broker serve the epoch-dated empty snapshot, which the
        # Exchange discards as a rollback, leaving the running container revoked.
        # It also keeps the published as_of readable, which is what lets the next
        # run publish a stamp that is provably newer.
        _publish_revocations(as_of=revoke_at + 1, thumbprints=[])
        _await_unrevoked(compose_stack.exchange, agent_id)
