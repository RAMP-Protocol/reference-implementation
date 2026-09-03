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
3. Where the Exchange publishes a registration schema, registration_data must
   conform to it. Publishing a schema is what turns this check on, so an
   Exchange that publishes none accepts whatever is sent.
4. Where the Exchange publishes a terms digest, the request must echo it. An
   absent echo and a stale one are refused identically, so this script reads
   the digest fresh on every run rather than holding one.

Gates 3 and 4 are reached only on an agent's FIRST registration. Once an agent
carries a billing_ref the short-circuit below returns the stored response
before either is consulted, which is why re-running this against an
already-registered agent proves nothing about them.

stdout carries the billing_ref and nothing else, so a shell can capture it.
Everything informational goes to stderr.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
from ramp_sdk import ProtocolVersion

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "e2e"))

from harness.exchanges import recipient_of  # noqa: E402
from harness.signing import sign_post  # noqa: E402

REGISTER_PATH = "/ramp.v1.ExchangeService/Register"
MANIFEST_PATH = "/.well-known/ramp.json"

# The operator this smoke agent registers on behalf of. The Exchange may publish
# a schema naming the members it wants; where it does, this is the one it
# requires. Fictional, like the rest of the demo cast.
SMOKE_AGENT_LEGAL_ENTITY = "Meridian Research Collective"


def _fresh_terms_digest(exchange_url: str) -> str | None:
    """Return the Exchange's currently published terms digest, or None.

    Fetched fresh on every run, never cached. The protocol requires this: a
    client cannot tell locally that a digest has gone stale, and a warm cache
    would make it retry a value the Exchange has already started refusing until
    the cache expired. Registration happens once per Exchange, so the extra
    request costs nothing.

    An Exchange that publishes no digest gets no echo. Sending one anyway is
    not an error — the Exchange ignores a digest it cannot verify against a
    document it never published — but omitting it keeps the request honest.
    """
    url = f"{exchange_url}{MANIFEST_PATH}"
    resp = httpx.get(url, timeout=30.0, headers={"Cache-Control": "no-cache"})
    if resp.status_code != 200:
        msg = f"manifest fetch failed: {url} -> {resp.status_code} {resp.text[:256]}"
        raise SystemExit(msg)

    manifest = resp.json()
    # terms_digest is a TOP-LEVEL manifest member, a sibling of terms_uri —
    # only data_schema sits under account_registration. Connect's JSON codec
    # emits lowerCamelCase; accept the proto spelling too.
    return manifest.get("termsDigest") or manifest.get("terms_digest") or None


def _require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        msg = f"missing required env var: {name}"
        raise SystemExit(msg)
    return value


def main() -> None:
    exchange_url = _require_env("RAMP_STAGING_EXCHANGE_URL").rstrip("/")
    # The registration names the Exchange it is meant for. Normally that is the
    # host of the URL it is sent to, because an Exchange is reached at its own
    # identity. RAMP_STAGING_EXCHANGE names it directly for the deployments
    # where it is not: a staging Exchange reached through a tunnel arrives here
    # as a loopback port, which the mapper resolves against the LOCAL compose
    # stack and cannot answer for — and this script has no other way to say
    # which Exchange is on the far end.
    exchange = os.environ.get("RAMP_STAGING_EXCHANGE", "") or recipient_of(exchange_url)
    key_path = Path(_require_env("RAMP_STAGING_AGENT_KEY"))
    if not key_path.is_file():
        msg = f"agent key not found: {key_path} — run gen-staging-keys.sh"
        raise SystemExit(msg)

    terms_digest = _fresh_terms_digest(exchange_url)
    if terms_digest:
        print(f"accepting terms {terms_digest}", file=sys.stderr)

    url = f"{exchange_url}{REGISTER_PATH}"
    print(f"registering billing account via {url}", file=sys.stderr)

    # registration_data carries the operator's business details. Where the
    # Exchange publishes a schema it is checked against it, and a member the
    # schema does not name is refused along with a missing required one — so
    # this sends exactly what a published schema asks for and nothing extra.
    body: dict[str, object] = {
        "ver": ProtocolVersion,
        "exchange": exchange,
        "registration_data": {"legal_entity": SMOKE_AGENT_LEGAL_ENTITY},
    }
    if terms_digest:
        body["terms_digest"] = terms_digest

    resp = sign_post(url, body=body, key_path=key_path)
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
