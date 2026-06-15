"""Seeding helpers for the E2E stack.

Seeds the minimum state the happy-path and obligation tests need. Catalog
rows are pushed via the signed ``ramp.v1.CatalogService/PushResources``
RPC — the same path a production third-party contributor uses — not via
raw SQL. The legacy catalog-reload HTTP shortcut has been permanently
removed from the Exchange; see the regression tripwires under
``src/exchange/cmd/server/`` and
``src/exchange/internal/transport/`` for policy.

Setup state that in production would arrive through separate onboarding
paths is still written via direct SQL:

* Exchange: tenant row (``ramp.tenants``), buyer agent row
  (``ramp.agents`` keyed by ``agent_id='agent-e2e'``), and the catalog
  contributor pubkey (``ramp.agents`` keyed by
  ``agent_id='catalog-contributor-e2e'`` — piggy-backs on the agents
  table until the registry is split by role).
* Broker: exchange row pointing at the Exchange's in-compose URL.

Catalog rows themselves are handed off to :func:`catalog_push.push_catalog`
which signs a ``PushResources`` RPC with the contributor's Ed25519 key.
The edge worker advertises the contributor in its
``/.well-known/ramp.json#catalog_contributors`` (via
``CATALOG_CONTRIBUTORS_JSON`` env) so the Exchange's Gate 2 passes.

When run inside the compose network (``RAMP_E2E_IN_NETWORK=1``) we use
service DNS names; otherwise we use the host-exposed ports.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import psycopg

from .catalog_push import (
    CatalogEntry,
    generate_contributor_key,
    load_public_key_bytes,
    push_catalog,
)

EXCHANGE_INTERNAL_URL = "http://exchange:8081"
EDGE_INTERNAL_URL = "http://edge:8787"
EDGE_INTERNAL_HOST = "edge:8787"
# Pytest runs inside the compose network (as the `runner` service) so it can
# use the same edge:8787 DNS name the Broker probe uses.
EDGE_PUBLIC_URL = "http://edge:8787"
EDGE_PUBLIC_HOST = "edge:8787"
AWS_EDGE_PUBLIC_URL = "http://aws-edge:8788"
AWS_EDGE_PUBLIC_HOST = "aws-edge:8788"
FASTLY_EDGE_PUBLIC_URL = "http://fastly-edge:7676"
FASTLY_EDGE_PUBLIC_HOST = "fastly-edge:7676"
EXCHANGE_DOMAIN = "exchange.e2e.local"
# Default signing key refs — must match those that the Exchange populates at
# startup (see src/exchange/cmd/server/main.go).
ED25519_KEY_REF = "exchange-primary"
RSA_KEY_REF = "cf-rsa-primary"
CLOUDFRONT_KEY_PAIR_ID = "cf-rsa-primary"

# Contributor identity used to sign the PushResources RPC. See
# catalog_push.py for the keyfile format + Gate 1/Gate 2 details.
CATALOG_CONTRIBUTOR_ID = "catalog-contributor-e2e"


def _contributor_key_path() -> Path:
    """Return the keyfile path appropriate to the run environment.

    The keypair is a committed test fixture under
    ``tests/e2e/harness/fixtures/catalog_contributor_key.json`` — the
    matching pubkey is also pinned in ``deploy/broker/keys.json`` with
    kid ``catalog-contributor-e2e`` so the Exchange's static httpsig
    resolver finds it. A ``RAMP_CATALOG_KEY_PATH`` override lets CI
    pin a different location (e.g. for a rotated key); when set, the
    file there MUST match the pubkey in ``deploy/broker/keys.json``.
    """
    override = os.environ.get("RAMP_CATALOG_KEY_PATH")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / "fixtures" / "catalog_contributor_key.json"


CONTRIBUTOR_KEY_PATH = _contributor_key_path()

# Signing identities the obligation + full-stack tests act as. Each kid is
# ALSO pinned in deploy/broker/keys.json (transport httpsig, so the
# Exchange/Broker static resolvers verify the signature) AND registered in
# ramp.agents below (service-layer authz: resolveCaller looks the *signing*
# kid up, authorizeForAgent requires kid == requester.id). agent-e2e carries
# the EXCHANGE_BILLING_SEED balance; agent-nobilling-e2e is deliberately
# uncredited so obligation-00 failure-5 reaches the billing gate.
_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
_SIGNING_AGENT_KEY_FILES = {
    "agent-e2e": _FIXTURES_DIR / "agent_e2e_key.json",
    "agent-nobilling-e2e": _FIXTURES_DIR / "agent_nobilling_e2e_key.json",
}

# Broker outbound-relay identity (kid prefixed "broker."). The Broker signs
# relayed Exchange RPCs with this key (BROKER_RELAY_KEY_FILE), so the
# Exchange's resolveCaller must find the kid classified as BROKER and
# authorizeForAgent honours it on tenants with allow_broker_relay=true. The
# pubkey is kept here as a constant because the runner image ships
# tests/e2e/harness but not deploy/; keep deploy/broker/broker-key.json,
# deploy/broker/keys.json, and this value in sync on rotation.
_BROKER_RELAY_KID = "broker.broker-local.v1"
_BROKER_RELAY_PUBKEY_B64 = "gCX76Qe6aRTjVWd2WIFaLtfTzBjA9EFFHUg3pz5AE9s"

# Host-side Postgres exposed by docker-compose on the Postgres' default port
# inside the compose network. For the test harness we use the port the
# host maps via `docker compose port`.
DEFAULT_PG_CONNECT_TIMEOUT_SEC = 20


@dataclass(frozen=True)
class SeededFixture:
    """IDs and URLs produced by :func:`seed_stack`.

    Carries fixtures for all three edge runtimes so the E2E exercises:
      * Cloudflare ed25519 path (``resource_uri`` — Miniflare)
      * Fastly Compute ed25519 path (``fastly_resource_uri`` — Viceroy)
      * AWS CloudFront RSA path (``aws_resource_uri`` — local verifier shim)
    """

    tenant_id: str
    resource_id: str
    resource_uri: str
    agent_id: str
    exchange_id: str
    aws_tenant_id: str
    aws_resource_id: str
    aws_resource_uri: str
    fastly_resource_id: str
    fastly_resource_uri: str


def _resolve_pg_dsn(compose_file: str) -> str:
    """Resolve the Postgres DSN based on whether we run inside compose or on the host."""
    if os.environ.get("RAMP_E2E_IN_NETWORK") == "1":
        return "postgres://ramp:ramp@postgres:5432/ramp"
    from ._compose import resolve_host_port

    port = resolve_host_port(Path(compose_file), "postgres", 5432)
    return f"postgres://ramp:ramp@127.0.0.1:{port}/ramp"


def _wait_pg(dsn: str, timeout_seconds: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=3) as conn:
                conn.execute("SELECT 1")
                return
        except psycopg.Error as exc:
            last_err = exc
        time.sleep(0.5)
    msg = f"postgres not reachable at {dsn}: {last_err}"
    raise TimeoutError(msg)


def _agent_public_key(agent_id: str) -> bytes:
    """Real Ed25519 pubkey for a known signing identity, else a zero placeholder.

    The Exchange's ``resolveCaller`` looks the *signing* keyID up in
    ``ramp.agents`` and ``authorizeForAgent`` requires keyID == requester.id,
    so any agent that signs ExecuteTransaction MUST carry its real pubkey
    (kid == agent_id). Identities that never sign (pure transaction_log FK
    targets) keep the zero placeholder.
    """
    key_file = _SIGNING_AGENT_KEY_FILES.get(agent_id)
    if key_file is None:
        return b"\x00" * 32
    return load_public_key_bytes(key_file)


def _upsert_agent(dsn: str, *, agent_id: str, requester_type: str = "AGENT") -> None:
    """Register an agent in ramp.agents (FK target + service-layer authz).

    The pubkey is UPSERTed (not DO NOTHING) so a real key always replaces an
    earlier zero placeholder on a reused stack (RAMP_E2E_REUSE_STACK keeps the
    Postgres volume between runs).
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES (%s, %s, %s)
            ON CONFLICT (agent_id) DO UPDATE SET
                public_key = EXCLUDED.public_key,
                requester_type = EXCLUDED.requester_type
            """,
            (agent_id, _agent_public_key(agent_id), requester_type),
        )
        conn.commit()


def _upsert_tenant_ed25519(dsn: str, *, tenant_id: str, domain: str) -> None:
    """Idempotent tenant insert for the ed25519-signed-URL scheme.

    ``ramp.tenants`` has UNIQUE constraints on BOTH ``tenant_id`` and
    ``domain``. Tests that share a domain under different tenant_ids
    would collide on the domain key before the tenant_id ON CONFLICT
    clause fires. We check-before-insert to keep the helper idempotent
    against either collision — the first caller wins the domain, later
    callers with the same domain-different-tenant_id become no-ops.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM ramp.tenants WHERE domain = %s", (domain,))
        if cur.fetchone() is not None:
            return
        cur.execute(
            """
            INSERT INTO ramp.tenants (
                tenant_id, domain, hmac_secret_ref, ed25519_key_ref,
                reporting_policy, signing_scheme
            ) VALUES (%s, %s, 'none', %s, '{}', 'ED25519')
            ON CONFLICT (tenant_id) DO UPDATE SET
                domain = EXCLUDED.domain,
                signing_scheme = EXCLUDED.signing_scheme,
                ed25519_key_ref = EXCLUDED.ed25519_key_ref
            """,
            (tenant_id, domain, ED25519_KEY_REF),
        )
        conn.commit()


def _upsert_tenant_cf_rsa(dsn: str, *, tenant_id: str, domain: str) -> None:
    """Idempotent tenant insert for the AWS CloudFront RSA scheme."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.tenants (
                tenant_id, domain, hmac_secret_ref, ed25519_key_ref,
                reporting_policy, signing_scheme,
                rsa_key_ref, cloudfront_key_pair_id
            ) VALUES (%s, %s, 'none', %s, '{}', 'AWS_CLOUDFRONT_RSA', %s, %s)
            ON CONFLICT (tenant_id) DO UPDATE SET
                domain = EXCLUDED.domain,
                signing_scheme = EXCLUDED.signing_scheme,
                rsa_key_ref = EXCLUDED.rsa_key_ref,
                cloudfront_key_pair_id = EXCLUDED.cloudfront_key_pair_id
            """,
            (tenant_id, domain, ED25519_KEY_REF, RSA_KEY_REF, CLOUDFRONT_KEY_PAIR_ID),
        )
        conn.commit()


def _upsert_catalog_contributor(dsn: str, *, pubkey_bytes: bytes) -> None:
    """Pre-register the catalog contributor's Ed25519 pubkey for Gate 1.

    The Exchange's agent registry (``src/exchange/internal/agentreg/``) looks
    keys up from ``ramp.agents`` and only falls back to the lazy
    ``ramp.json`` fetch when ``LookupPublicKey`` returns
    ``ErrUnknown``. Pre-inserting the row lets the harness skip standing
    up a second static HTTP server without weakening Gate 1 —
    ``httpsig.Verify`` still covers the request end-to-end.

    This reuses ``ramp.agents`` for a contributor identity; see the module
    docstring for the piggy-back rationale.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES (%s, %s, 'AGENT')
            ON CONFLICT (agent_id) DO UPDATE SET
                public_key = EXCLUDED.public_key
            """,
            (CATALOG_CONTRIBUTOR_ID, pubkey_bytes),
        )
        conn.commit()


def _upsert_broker_relay(dsn: str) -> None:
    """Register the Broker's outbound-relay identity as a BROKER caller.

    The full-stack test drives MCP → Broker → Exchange; the Broker signs the
    relayed ExecuteTransaction with its relay key (kid ``broker.broker-local.v1``),
    so the Exchange's ``resolveCaller`` must find that kid classified as BROKER.
    ``authorizeForAgent`` then honours the relay on tenants opted in via
    :func:`_set_allow_broker_relay`.
    """
    pad = "=" * (-len(_BROKER_RELAY_PUBKEY_B64) % 4)
    pub = base64.urlsafe_b64decode(_BROKER_RELAY_PUBKEY_B64 + pad)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES (%s, %s, 'BROKER')
            ON CONFLICT (agent_id) DO UPDATE SET
                public_key = EXCLUDED.public_key,
                requester_type = EXCLUDED.requester_type
            """,
            (_BROKER_RELAY_KID, pub),
        )
        conn.commit()


def _set_allow_broker_relay(dsn: str, *, tenant_id: str) -> None:
    """Opt a tenant into broker-relayed transactions (column defaults to FALSE)."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE ramp.tenants SET allow_broker_relay = TRUE WHERE tenant_id = %s",
            (tenant_id,),
        )
        conn.commit()


def _upsert_exchange(dsn: str, *, exchange_id: str, domain: str) -> None:
    """Idempotent exchange insert.

    Like ``ramp.tenants``, ``broker.exchanges`` has UNIQUE constraints
    on BOTH ``exchange_id`` and ``domain``. Multiple tests pointing at
    the same Exchange domain (``exchange.e2e.local``) under different
    ``exchange_id`` values would hit the domain-uniqueness constraint
    before the ``exchange_id`` ON CONFLICT clause could fire. We
    check-before-insert so the first caller wins the domain and later
    callers become no-ops.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM broker.exchanges WHERE domain = %s", (domain,))
        if cur.fetchone() is not None:
            return
        cur.execute(
            """
            INSERT INTO broker.exchanges (
                exchange_id, domain, endpoint, trust_level,
                supported_profiles, priority, healthy
            ) VALUES (%s, %s, %s, 'VERIFIED', %s::jsonb, 10, TRUE)
            ON CONFLICT (exchange_id) DO UPDATE SET
                domain = EXCLUDED.domain,
                endpoint = EXCLUDED.endpoint,
                trust_level = EXCLUDED.trust_level,
                updated_at = NOW()
            """,
            (
                exchange_id,
                domain,
                EXCHANGE_INTERNAL_URL,
                json.dumps(["ramp-news-v1"]),
            ),
        )
        conn.commit()


def _wait_exchange_ready(exchange_host_url: str, timeout_seconds: float = 20.0) -> None:
    """Wait for Exchange healthz and catalog readiness."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{exchange_host_url}/healthz", timeout=2.0)
            if r.status_code == httpx.codes.OK:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    msg = f"exchange not healthy at {exchange_host_url}"
    raise TimeoutError(msg)


def seed_stack(compose_file: str, exchange_host_url: str) -> SeededFixture:
    """Seed the E2E stack and return the IDs the test will use."""
    dsn = _resolve_pg_dsn(compose_file)
    _wait_pg(dsn)
    _wait_exchange_ready(exchange_host_url)

    tenant_id = "tenant-e2e"
    agent_id = "agent-e2e"
    resource_id = "res-e2e-1"
    exchange_id = "ex-e2e"
    resource_uri = f"{EDGE_PUBLIC_URL}/premium/article-42.html"

    aws_tenant_id = "tenant-aws-e2e"
    aws_resource_id = "res-aws-e2e-1"
    aws_resource_uri = f"{AWS_EDGE_PUBLIC_URL}/premium/article-42.html"

    # Fastly shares the ed25519 tenant — same signing scheme — but its own
    # catalog entry, publisher host, and ramp.json.
    fastly_resource_id = "res-fastly-e2e-1"
    fastly_resource_uri = f"{FASTLY_EDGE_PUBLIC_URL}/premium/article-42.html"

    _upsert_tenant_ed25519(dsn, tenant_id=tenant_id, domain="e2e.local")
    _upsert_tenant_cf_rsa(dsn, tenant_id=aws_tenant_id, domain="aws.e2e.local")
    _upsert_agent(dsn, agent_id=agent_id)
    # Credit-less agent for obligation-00 failure-5: registered + keyed, but
    # deliberately absent from EXCHANGE_BILLING_SEED so the billing gate
    # refuses it with a billing-family reason (not an auth error).
    _upsert_agent(dsn, agent_id="agent-nobilling-e2e")
    # Broker-relay caller + per-tenant opt-in for the MCP → Broker → Exchange
    # full-stack path (test_full_stack). Both transacting tenants opt in.
    _upsert_broker_relay(dsn)
    _set_allow_broker_relay(dsn, tenant_id=tenant_id)
    _set_allow_broker_relay(dsn, tenant_id=aws_tenant_id)

    # Pre-register the catalog contributor pubkey so Gate 1 resolves without
    # a ramp.json fetch, then push every catalog entry via the signed
    # PushResources RPC — exercising both Gate 1 (httpsig) and Gate 2
    # (contributor-in-catalog_contributors) the same way production does.
    generate_contributor_key(CONTRIBUTOR_KEY_PATH)
    _upsert_catalog_contributor(dsn, pubkey_bytes=load_public_key_bytes(CONTRIBUTOR_KEY_PATH))
    push_catalog(
        exchange_url=exchange_host_url,
        tenant_id=tenant_id,
        entries=[
            CatalogEntry(
                domain=EDGE_PUBLIC_HOST,
                path="/premium/article-42.html",
                content_id=resource_id,
            ),
            CatalogEntry(
                domain=FASTLY_EDGE_PUBLIC_HOST,
                path="/premium/article-42.html",
                content_id=fastly_resource_id,
            ),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    push_catalog(
        exchange_url=exchange_host_url,
        tenant_id=aws_tenant_id,
        entries=[
            CatalogEntry(
                domain=AWS_EDGE_PUBLIC_HOST,
                path="/premium/article-42.html",
                content_id=aws_resource_id,
            ),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )

    # Broker matches exchanges by the `domain` advertised in the publisher's
    # ramp.json (see EXCHANGES_JSON in docker-compose.e2e.yml). Both edges
    # advertise the same Exchange domain so one registry row suffices.
    _upsert_exchange(dsn, exchange_id=exchange_id, domain=EXCHANGE_DOMAIN)

    return SeededFixture(
        tenant_id=tenant_id,
        resource_id=resource_id,
        resource_uri=resource_uri,
        agent_id=agent_id,
        exchange_id=exchange_id,
        aws_tenant_id=aws_tenant_id,
        aws_resource_id=aws_resource_id,
        aws_resource_uri=aws_resource_uri,
        fastly_resource_id=fastly_resource_id,
        fastly_resource_uri=fastly_resource_uri,
    )
