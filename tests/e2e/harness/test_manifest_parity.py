"""Drift guard: the AWS CloudFront shim and the Hono edge worker build the
publisher ``/.well-known/ramp.json`` from the SAME shared
``buildPublisherManifest`` (``src/edge/src/publisher-manifest.mjs``), so both
endpoints MUST serve a byte-for-byte identical document modulo ``domain``.

The raw-Node ``aws-edge`` shim (``tests/e2e/aws-edge/server.mjs``) imports a
build-time copy of that module (``tests/e2e/aws-edge/Dockerfile`` ``COPY``s it
in); the Hono edge worker (``src/edge``) imports the same module, re-exported
from ``src/edge/src/types.ts``. Both are configured from the same
``EXCHANGES_JSON`` / ``CATALOG_CONTRIBUTORS_JSON`` in ``docker-compose.e2e.yml``
and differ only in ``PROVIDER`` (the ``domain`` field). So with ``domain``
normalised away the two manifests MUST be equal — a stale image that missed the
copy, a config-wiring skew, or any field / enum / version change that did not
reach both producers fails here instead of silently serving a stale shape down
the AWS E2E path.
"""

from __future__ import annotations

import httpx

from .conftest import StackURLs


def test_aws_shim_manifest_matches_canonical_publisher(compose_stack: StackURLs) -> None:
    """aws-edge shim manifest == edge-worker (canonical) manifest, modulo domain."""
    canonical = httpx.get(f"{compose_stack.edge}/.well-known/ramp.json", timeout=5.0).json()
    shim = httpx.get(f"{compose_stack.aws_edge}/.well-known/ramp.json", timeout=5.0).json()

    # Guard against a trivially-matching empty / zero-value document on either side.
    assert canonical.get("role") == "ROLE_PUBLISHER"
    assert canonical.get("exchanges"), "canonical edge manifest unexpectedly has no exchanges"

    # Same exchanges/contributors config on both producers; only the domain differs.
    canonical.pop("domain", None)
    shim.pop("domain", None)
    assert shim == canonical, (
        "aws-edge shim manifest drifted from buildPublisherManifest output; "
        "rebuild the aws-edge image so tests/e2e/aws-edge/publisher-manifest.mjs "
        "matches src/edge/src/publisher-manifest.mjs"
    )
