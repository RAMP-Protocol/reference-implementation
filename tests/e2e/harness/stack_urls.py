"""Service URL tuple shared by the pytest harness and standalone scripts.

Lives outside conftest.py so non-pytest consumers (smoke_staging.py) can
import it without depending on a pytest-convention file; conftest re-exports
it for the existing test imports.
"""

from __future__ import annotations

from typing import NamedTuple


class StackURLs(NamedTuple):
    """Host-side URLs for each compose service."""

    exchange: str
    # Multi-exchange topology: exchange-a is `exchange`; exchange-b serves
    # the music catalog (DB ramp_b), exchange-c the sfx catalog (DB ramp_c).
    exchange_b: str
    exchange_c: str
    broker: str
    edge: str
    aws_edge: str
    fastly_edge: str
    # Lambda@Edge on the AWS Lambda runtime emulator. These are the base URLs of
    # the invoke endpoint's host, not of an HTTP server: the emulator answers
    # only POSTs to the function-invocation path (see harness/lambda_edge.py).
    # lambda_edge_no_wba runs the same worker built without a publisher signing
    # key, so its Web Bot Auth directory route answers 404.
    lambda_edge: str
    lambda_edge_no_wba: str
    # The identity service (Go MCP adapter) and its OIDC provider. identity is
    # empty on host runs — it publishes no host port, so the MCP-endpoint test is
    # in-network only.
    identity: str
    zitadel: str
