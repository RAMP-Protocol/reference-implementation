"""Drift guard: the AWS CloudFront shim and the Hono edge worker build the
publisher discovery documents from the SAME shared builders
(``src/edge/src/well-known.mjs``), so both endpoints MUST serve a
byte-for-byte identical ``/.well-known/ramp.json`` (modulo ``domain``) and a
structurally-identical WBA directory.

The raw-Node ``aws-edge`` shim (``tests/e2e/aws-edge/server.mjs``) imports a
build-time copy of that module (``tests/e2e/aws-edge/Dockerfile`` ``COPY``s it
in); the Hono edge worker (``src/edge``) imports the same module, re-exported
from ``src/edge/src/types.ts``. Both are configured from the same
``EXCHANGES_JSON`` / ``CATALOG_CONTRIBUTORS_JSON`` in ``docker-compose.e2e.yml``
and differ only in ``PROVIDER`` (the ``domain`` field) and their per-domain
self-publish key. After the WBA split the overlay manifest is KEYLESS — identity
keys moved to the WBA directory (``/.well-known/http-message-signatures-directory``)
and carry NO kid (named by RFC 7638 thumbprint).
"""

from __future__ import annotations

import httpx

from .conftest import StackURLs
from .constants import WBA_DIRECTORY_PATH


def test_aws_shim_manifest_matches_canonical_publisher(compose_stack: StackURLs) -> None:
    """aws-edge shim manifest == edge-worker (canonical) manifest, modulo domain."""
    canonical = httpx.get(f"{compose_stack.edge}/.well-known/ramp.json", timeout=5.0).json()
    shim = httpx.get(f"{compose_stack.aws_edge}/.well-known/ramp.json", timeout=5.0).json()

    # Guard against a trivially-matching empty / zero-value document on either side.
    assert canonical.get("role") == "ROLE_PUBLISHER"
    assert canonical.get("exchanges"), "canonical edge manifest unexpectedly has no exchanges"

    # Multi-exchange topology: the philosophy edge (`edge`, exchange-a) and
    # the sfx aws-edge (exchange-c) are deliberately fronted by DIFFERENT exchanges,
    # so their `exchanges[]` legitimately differ (exchange:8081 vs exchange-c:8081).
    # That is publisher config, not a buildPublisherManifest drift signal — assert
    # each side carries exactly one well-formed exchange entry (so a missing/empty
    # exchanges still fails), then normalise it away before the structural compare.
    for label, doc in (("edge", canonical), ("aws-edge", shim)):
        exchanges = doc.get("exchanges") or []
        assert len(exchanges) == 1, f"{label} must list exactly one exchange; got {exchanges!r}"
        ex = exchanges[0]
        assert isinstance(ex.get("domain"), str) and ex["domain"], ex
        assert isinstance(ex.get("endpoint"), str) and ex["endpoint"], ex

    # The overlay is keyless after the WBA split — identity keys live in the WBA
    # directory, not ramp.json. Assert neither producer republishes them here.
    for label, doc in (("edge", canonical), ("aws-edge", shim)):
        assert "public_keys" not in doc, f"{label} overlay must not carry public_keys: {doc!r}"
        assert "invalidation_url" not in doc, f"{label} overlay must not carry invalidation_url"

    # Same contributors config + shape on both producers; domain + exchanges are
    # per-publisher by design (multi-exchange topology), so normalise them away
    # before the byte-for-byte structural comparison. The keyless overlay carries
    # no public_keys (asserted above), so there is nothing to normalise there.
    for doc in (canonical, shim):
        doc.pop("domain", None)
        doc.pop("exchanges", None)
    assert shim == canonical, (
        "aws-edge shim manifest drifted from buildPublisherManifest output; "
        "rebuild the aws-edge image so tests/e2e/aws-edge/well-known.mjs "
        "matches src/edge/src/well-known.mjs"
    )


def test_edge_and_shim_serve_wba_directory_self_key(compose_stack: StackURLs) -> None:
    """Each edge serves its OWN self-publish key in a WBA directory (no kid).

    The key is LEGITIMATELY per-domain: each edge serves its own
    self-publish signing key, named by thumbprint. Assert both producers serve
    exactly one well-formed Ed25519 JWK with no kid.
    """
    for label, base in (("edge", compose_stack.edge), ("aws-edge", compose_stack.aws_edge)):
        resp = httpx.get(f"{base}{WBA_DIRECTORY_PATH}", timeout=5.0)
        assert resp.status_code == httpx.codes.OK, f"{label}: {resp.text}"
        assert "application/jwk-set+json" in resp.headers.get("content-type", ""), label
        keys = resp.json().get("keys") or []
        assert len(keys) == 1, f"{label} must serve exactly one self-publish key; got {keys!r}"
        key = keys[0]
        # A WBA key is named by its thumbprint — it carries no kid.
        assert "kid" not in key, f"{label} WBA key must not carry a kid: {key!r}"
        assert key.get("kty") == "OKP" and key.get("crv") == "Ed25519", key
        assert isinstance(key.get("x"), str) and len(key["x"]) == 43, key
