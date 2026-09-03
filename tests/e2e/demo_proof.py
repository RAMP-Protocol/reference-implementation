"""Local-stack catalog proof driver (items 2-5).

Re-runnable proof that the live e2e stack ingests and serves the multi-publisher
catalog through the REAL JSONL ingestion path. NOT a pytest module — a
standalone script run against an already-up stack (`make e2e-up`):

    uv run --project tests/e2e python tests/e2e/demo_proof.py

What it does, end to end:

1. Registers the three demo publisher tenants (one per edge runtime / signing
   scheme) by DOMAIN — the Exchange derives the owning tenant from each ResourceEntry
   domain via the UNIQUE ramp.tenants.domain mapping, so the tenant the ingest
   binary pushes under MUST be the domain's tenant.
2. Registers the catalog-contributor pubkey (Gate 1) and the broker exchange row
   (so the Broker can route a demo resolve to exchange:8081).
3. Runs the production ingest binary `cmd/ramp-ingest` ONCE PER FEED
   (philosophy/music/sfx), each as signed PushResources RPCs — one per
   submission of at most the wire bound; every demo feed fits in one. A
   non-zero exit (the binary exits non-zero on any refusal) fails the proof.
4. DiscoverResources (via the Broker resolve surface) for a demo resource
   (socrates) and prints its offer/terms — proving ingest+discovery on the real
   catalog.
5. A signed-URL fetch of the canary article thales-of-miletus.txt THROUGH the
   Cloudflare edge, asserting the body contains RAMP-DEMO-CANARY-8FK3J2-0418 —
   proving ingest -> discover -> sign -> edge -> origin.

Signed-URL host note: the Exchange signs the canonical `GET\n<url>` where the
url host is the publisher domain with NO port (http://demo.ramp-protocol.org/...).
We reach the edge on its host-mapped port but send `Host: demo.ramp-protocol.org`
(no port); the edge reconstructs the same port-less authority, so the signature
verifies byte-for-byte.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import httpx
import psycopg

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "e2e"))

from harness.broker_client import resolve  # noqa: E402
from harness.catalog_push import load_public_key_bytes  # noqa: E402
from harness.stack_urls import StackURLs  # noqa: E402
from harness.resolve_carriers import (  # noqa: E402
    licensed_of,
    retrieval_endpoint_of,
)
from harness.exchanges import EXCHANGE_A_DOMAIN, EXCHANGE_A_INTERNAL_URL  # noqa: E402
from harness.ingest_runner import ingest_succeeded, run_ingest  # noqa: E402
from harness.seed import (  # noqa: E402
    _broker_relay_pubkey_bytes,
    _BROKER_RELAY_KID,
)
from harness.signing import AGENT_E2E_KEY_PATH  # noqa: E402

COMPOSE_FILE = REPO_ROOT / "docker-compose.e2e.yml"
CONTRIBUTOR_KEY = (
    REPO_ROOT / "tests" / "e2e" / "harness" / "fixtures" / "catalog_contributor_key.json"
)
CONTRIBUTOR_ID = "catalog-contributor-e2e"

# Feed paths are REPO_ROOT-relative because ingest runs with cwd=REPO_ROOT.
CATALOG_DIR_REL = "tests/e2e/harness/fixtures/catalog"

# The catalog feeds this script ingests are the HARNESS-OWNED ones under
# harness/fixtures/catalog/, the same feeds seed.py uses — NOT the demo
# deployment's feeds under deploy/fixtures/demo/.
#
# Both this script and the pytest harness seed the SAME local stack, under the
# same publisher domains and the same URIs, and ramp.catalog has UNIQUE(uri):
# whichever ingests last wins. Pointing this script at a different feed set would
# silently replace the catalog the tests expect, and the damage would surface as
# unrelated tests failing on terms they never asked for.
#
# (tenant_id, domain, signing_scheme, feed file, edge service, edge container port).
E2E_PUBLISHERS = [
    (
        "tenant-demo-philosophy",
        "demo.ramp-protocol.org",
        "ED25519",
        f"{CATALOG_DIR_REL}/philosophy.jsonl",
        "edge",
        8787,
    ),
    (
        "tenant-demo-music",
        "music.demo.ramp-protocol.org",
        "ED25519",
        f"{CATALOG_DIR_REL}/music.jsonl",
        "fastly-edge",
        7676,
    ),
    (
        "tenant-demo-sfx",
        "sfx.demo.ramp-protocol.org",
        "AWS_CLOUDFRONT_RSA",
        f"{CATALOG_DIR_REL}/sfx.jsonl",
        "aws-edge",
        8788,
    ),
]

ED25519_KEY_REF = "exchange-primary"
RSA_KEY_REF = "cf-rsa-primary"

# The buyer this proof runs as. It is NOT funded, and cannot be: the in-memory
# billing adapter denominates every balance in one currency, billing.DemoCurrency
# ("USD"), and its seed loader drops any EXCHANGE_BILLING_SEED entry in another
# currency. Registration then gives this agent a zero USD account.
#
# That is enough for what this script proves. The resources it walks — socrates
# for discovery, thales for the canary fetch — are reached on terms whose charge
# is zero, and a zero charge skips the currency and balance gates. Point it at a
# PRICED term and Authorize refuses with "currency mismatch".
#
# Its kid == agent_id so the Broker self-act gate (verified keyID == req.agent_id)
# admits it.
DEMO_AGENT_ID = "agent-demo-eur"
DEMO_AGENT_KEY_PATH = (
    REPO_ROOT / "tests" / "e2e" / "harness" / "fixtures" / "agent_demo_eur_key.json"
)


def _port(service: str, container_port: int) -> str:
    out = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "port", service, str(container_port)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    # "0.0.0.0:57003" -> "127.0.0.1:57003"
    return out.replace("0.0.0.0", "127.0.0.1")


def _pg_dsn() -> str:
    hostport = _port("postgres", 5432)
    return f"postgres://ramp:ramp@{hostport}/ramp"


def _register_tenant(dsn: str, tenant_id: str, domain: str, scheme: str) -> None:
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT tenant_id FROM ramp.tenants WHERE domain = %s", (domain,))
        row = cur.fetchone()
        if row is not None:
            return
        if scheme == "AWS_CLOUDFRONT_RSA":
            cur.execute(
                """
                INSERT INTO ramp.tenants (
                    tenant_id, domain, ed25519_key_ref,
                    reporting_policy, signing_scheme, rsa_key_ref, cloudfront_key_pair_id
                ) VALUES (%s, %s, %s, '{}', 'AWS_CLOUDFRONT_RSA', %s, %s)
                """,
                (tenant_id, domain, ED25519_KEY_REF, RSA_KEY_REF, RSA_KEY_REF),
            )
        else:
            cur.execute(
                """
                INSERT INTO ramp.tenants (
                    tenant_id, domain, ed25519_key_ref,
                    reporting_policy, signing_scheme
                ) VALUES (%s, %s, %s, '{}', 'ED25519')
                """,
                (tenant_id, domain, ED25519_KEY_REF),
            )
        conn.commit()


def _register_contributor_and_exchange(dsn: str) -> None:
    pub = load_public_key_bytes(CONTRIBUTOR_KEY)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES (%s, %s, 'AGENT')
            ON CONFLICT (agent_id) DO UPDATE SET public_key = EXCLUDED.public_key
            """,
            (CONTRIBUTOR_ID, pub),
        )
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES ('agent-e2e', %s, 'AGENT')
            ON CONFLICT (agent_id) DO UPDATE SET public_key = EXCLUDED.public_key
            """,
            (load_public_key_bytes(AGENT_E2E_KEY_PATH),),
        )
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES (%s, %s, 'AGENT')
            ON CONFLICT (agent_id) DO UPDATE SET public_key = EXCLUDED.public_key
            """,
            (DEMO_AGENT_ID, load_public_key_bytes(DEMO_AGENT_KEY_PATH)),
        )
        # Broker outbound-relay identity: the Broker signs the relayed
        # ExecuteTransaction with this kid, so the Exchange's resolveCaller must
        # find it classified as BROKER (else "caller keyID ... not registered").
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES (%s, %s, 'BROKER')
            ON CONFLICT (agent_id) DO UPDATE SET
                public_key = EXCLUDED.public_key,
                requester_type = EXCLUDED.requester_type
            """,
            (_BROKER_RELAY_KID, _broker_relay_pubkey_bytes()),
        )
        # The registry row and the recipient every push names must be the same
        # exchange, or the demo routes to one and addresses the other. Both come
        # from the constant, so they cannot be kept equal by hand and then not
        # be.
        cur.execute("SELECT 1 FROM broker.exchanges WHERE domain = %s", (EXCHANGE_A_DOMAIN,))
        if cur.fetchone() is None:
            cur.execute(
                """
                INSERT INTO broker.exchanges (
                    exchange_id, domain, endpoint, trust_level,
                    supported_profiles, priority, healthy
                ) VALUES ('ex-demo', %s, %s,
                          'VERIFIED', '["ramp-news-v1"]'::jsonb, 10, TRUE)
                """,
                (EXCHANGE_A_DOMAIN, EXCHANGE_A_INTERNAL_URL),
            )
        conn.commit()


def _enable_broker_relay(dsn: str, domain: str) -> None:
    """Opt a demo tenant into broker-relayed ExecuteTransaction (defaults FALSE)."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE ramp.tenants SET allow_broker_relay = TRUE WHERE domain = %s",
            (domain,),
        )
        conn.commit()


def _ingest(exchange_url: str, tenant_id: str, feed: str) -> None:
    """Push one feed. ``exchange_url`` is a host-mapped 127.0.0.1 port, which
    names no exchange, so ``--exchange`` overrides the recipient the binary
    would otherwise derive from it."""
    proc = run_ingest(
        argv_prefix=["go", "run", "./src/exchange/cmd/ramp-ingest"],
        exchange_url=exchange_url,
        exchange=EXCHANGE_A_DOMAIN,
        tenant_id=tenant_id,
        key_path=CONTRIBUTOR_KEY,
        feed=Path(feed),
        cwd=REPO_ROOT,
    )
    tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
    print(f"  ingest {feed} -> rc={proc.returncode} | {tail}")
    if not ingest_succeeded(proc):
        print(proc.stderr)
        msg = f"ingest failed for {feed}"
        raise SystemExit(msg)


def main() -> None:
    dsn = _pg_dsn()
    exchange_url = f"http://{_port('exchange', 8081)}"
    broker_url = f"http://{_port('broker', 8082)}"
    # harness.broker_client.resolve only consumes compose_stack.broker; the edge
    # fetch below keeps demo_proof's own port logic (container 8787, not 80).
    stack = StackURLs(
        exchange=exchange_url,
        # The multi-exchange topology and the identity service are not part of
        # this script's flow; they are named explicitly rather than defaulted so
        # a future field addition surfaces here instead of silently binding.
        exchange_b="",
        exchange_c="",
        broker=broker_url,
        edge="",
        aws_edge="",
        fastly_edge="",
        lambda_edge="",
        lambda_edge_no_wba="",
        identity="",
        zitadel="",
    )

    print("== item 2: register demo tenants + contributor + exchange ==")
    for tenant_id, domain, scheme, _feed, _svc, _p in E2E_PUBLISHERS:
        _register_tenant(dsn, tenant_id, domain, scheme)
        _enable_broker_relay(dsn, domain)
        print(f"  tenant {tenant_id} ({domain}, {scheme})")
    _register_contributor_and_exchange(dsn)

    print("== item 2: ingest all three demo feeds via cmd/ramp-ingest ==")
    for tenant_id, _domain, _scheme, feed, _svc, _p in E2E_PUBLISHERS:
        _ingest(exchange_url, tenant_id, feed)

    print("== item 3: DiscoverResources for socrates ==")
    socrates = "http://demo.ramp-protocol.org/articles/philosophers/socrates.txt"
    resp = resolve(
        stack,
        {
            "agent_id": DEMO_AGENT_ID,
            "uri": socrates,
            "intended_use": "ai-input",
        },
        key_path=DEMO_AGENT_KEY_PATH,
    )
    print(f"  resolve status={resp.status_code}")
    print(f"  body={resp.text}")
    payload = resp.json()
    if not licensed_of(payload):
        msg = "socrates resolve did not return a licensed offer"
        raise SystemExit(msg)

    print("== item 4: signed-URL canary fetch through the Cloudflare edge ==")
    canary = "http://demo.ramp-protocol.org/articles/philosophers/thales-of-miletus.txt"
    resp = resolve(
        stack,
        {
            "agent_id": DEMO_AGENT_ID,
            "uri": canary,
            "intended_use": "ai-input",
        },
        key_path=DEMO_AGENT_KEY_PATH,
    )
    payload = resp.json()
    signed = retrieval_endpoint_of(payload)
    print(f"  resolve status={resp.status_code} licensed={licensed_of(payload)}")
    print(f"  retrievalEndpoint={signed}")
    if not signed:
        print(f"  body={resp.text}")
        msg = "canary resolve returned no retrievalEndpoint"
        raise SystemExit(msg)

    edge_hostport = _port("edge", 8787)
    # Replace the signed URL's host:port with the host-mapped edge, but stamp the
    # original (port-less) Host so the edge reconstructs the signed authority.
    fetch_url = signed.replace("http://demo.ramp-protocol.org", f"http://{edge_hostport}")
    content = httpx.get(
        fetch_url,
        headers={"Host": "demo.ramp-protocol.org"},
        follow_redirects=True,
        timeout=15.0,
    )
    print(f"  edge fetch status={content.status_code}")
    marker = "RAMP-DEMO-CANARY-8FK3J2-0418"
    if marker not in content.text:
        print(content.text[:500])
        msg = "canary marker NOT found in edge-delivered body"
        raise SystemExit(msg)
    print(f"  CANARY FOUND: {marker}")
    print(f"  greek phrase present: {'καῦμα διὰ ῥάμπης' in content.text}")
    print("\nALL PROOF ITEMS 2-5 PASSED")


if __name__ == "__main__":
    main()
