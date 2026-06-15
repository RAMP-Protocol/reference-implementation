"""Drift guard: the Python AGENT producer must conform to the canonical RAMP
manifest JSON Schema — the same document the Go consumer (``server.Build`` /
``ParseManifest``) and the TS edge (``src/edge/tests/manifest-schema.test.ts``)
enforce.

Go validates at build time and TS has a dedicated drift test; without this the
Python producer is guarded only by field-name convention. A schema bump that
tightens a field would otherwise leave the agent manifest stale with no
producer-side signal — surfacing only as a cross-language rejection far from the
source. This pins the Python output to the Go schema by relative path.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from ramp_mcp_shim.clock import DeterministicClock
from ramp_mcp_shim.httpsig import AgentKey
from ramp_mcp_shim.wellknown import build_agent_manifest

# repo-root/internal/rampwellknown/schema/... — parents[3] is the repo root from
# src/mcp/tests/. Resolved relatively so the guard moves with the schema.
_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "internal"
    / "rampwellknown"
    / "schema"
    / "ramp-well-known.json"
)


def _validator() -> Draft202012Validator:
    schema: Any = json.loads(_SCHEMA_PATH.read_text())
    return Draft202012Validator(schema)


def _agent_manifest_json() -> dict[str, Any]:
    priv = Ed25519PrivateKey.generate()
    seed_b64 = base64.urlsafe_b64encode(priv.private_bytes_raw()).rstrip(b"=").decode()
    key = AgentKey(kid="agent.v1", private_seed_b64=seed_b64)
    clock = DeterministicClock(datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC))
    return build_agent_manifest("agent.example", key, clock=clock).model_dump(mode="json")


def test_agent_manifest_conforms_to_canonical_schema() -> None:
    """build_agent_manifest output validates against the Go/TS canonical schema."""
    errors = [e.message for e in _validator().iter_errors(_agent_manifest_json())]
    assert errors == [], errors


def test_schema_rejects_a_tampered_manifest() -> None:
    """A wrong ver / missing public_keys must fail — proving the guard bites."""
    validator = _validator()

    bad_ver = _agent_manifest_json()
    bad_ver["ver"] = "9.9"
    assert list(validator.iter_errors(bad_ver)), "wrong ver should fail the schema"

    no_keys = _agent_manifest_json()
    del no_keys["public_keys"]
    assert list(validator.iter_errors(no_keys)), "AGENT without public_keys should fail"
