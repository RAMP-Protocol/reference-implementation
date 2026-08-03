"""Register the staging smoke agent's billing account; print its billing_ref.

Env-parameterized driver for the Terraform staging stack
(deploy/terraform/stacks/staging-aws). NOT a pytest module — a standalone
script run against a live, already-seeded staging deployment, normally via
deploy/terraform/scripts/seed-staging.sh:

    RAMP_STAGING_EXCHANGE_URL=https://exchange.<domain> \
    RAMP_STAGING_AGENT_KEY=deploy/terraform/stacks/staging-aws/keys/agent-key.json \
    uv run --project tests/e2e python tests/e2e/register_staging_agent.py

Why this exists. Seeding inserts the agent's ramp.agents row directly, which
gives the agent an identity but NOT a billing account. The billing_ref — the
handle the Exchange derives every TigerBeetle account id from — is minted only
by the Register RPC, which also creates the ledger account. Without this step
the agent has no billing_ref, and the paid leg of a transaction is denied at
authorize with "billing ref required" before any balance is ever consulted.

Register is idempotent: an agent that already carries a billing_ref gets the
stored one back and nothing changes. So this is safe to re-run, and the funding
step calls it too, purely to learn the ref through the same public surface
rather than reading the database behind the Exchange's back.

Preconditions the Exchange enforces, in the order you will hit them:

1. The caller must resolve to a row in ramp.agents whose stored public key is
   the one that signed this request — seed-staging.sh's SQL step.
2. The tenant named by EXCHANGE_DEFAULT_TENANT must exist, because Register
   reads its agent-activation policy. The stack points that at the publisher
   hostname the seed creates the tenant under.

stdout carries the billing_ref and nothing else, so a shell can capture it.
Everything informational goes to stderr.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "e2e"))

from harness.signing import sign_post  # noqa: E402

REGISTER_PATH = "/ramp.v1.ExchangeService/Register"

# Protocol version on the wire, matching every other harness producer.
RAMP_VER = "1.0"


def _require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        msg = f"missing required env var: {name}"
        raise SystemExit(msg)
    return value


def main() -> None:
    exchange_url = _require_env("RAMP_STAGING_EXCHANGE_URL").rstrip("/")
    key_path = Path(_require_env("RAMP_STAGING_AGENT_KEY"))
    if not key_path.is_file():
        msg = f"agent key not found: {key_path} — run gen-staging-keys.sh"
        raise SystemExit(msg)

    url = f"{exchange_url}{REGISTER_PATH}"
    print(f"registering billing account via {url}", file=sys.stderr)

    resp = sign_post(
        url,
        body={"ver": RAMP_VER, "registration_data": {"environment": "staging"}},
        key_path=key_path,
    )
    if resp.status_code != 200:
        msg = f"register failed: {resp.status_code} {resp.text[:512]}"
        raise SystemExit(msg)

    payload = resp.json()
    # Connect's JSON codec emits lowerCamelCase field names; accept the proto
    # snake_case spelling too so a codec change cannot silently break this.
    billing_ref = payload.get("billingRef") or payload.get("billing_ref") or ""
    if not billing_ref:
        msg = f"register returned no billing_ref: {resp.text[:512]}"
        raise SystemExit(msg)

    active = payload.get("active", False)
    print(f"billing_ref={billing_ref} active={active}", file=sys.stderr)
    if not active:
        print(
            "WARNING: the account is registered but NOT active — the tenant's "
            "activate_new_agents_by_default is false, so paid transactions "
            "will be refused until an operator activates it",
            file=sys.stderr,
        )
    print(billing_ref)


if __name__ == "__main__":
    main()
