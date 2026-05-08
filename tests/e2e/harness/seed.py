"""Seeding helpers for the E2E stack.

Directly talks to the live Exchange + Broker databases and service HTTP APIs
to insert the minimum state the happy-path test needs:

* Exchange: tenant + one catalog entry whose URI points at the edge worker.
* Exchange billing: credits the agent balance used by the test.
* Broker: one marketplace row pointing at the Exchange's in-compose URL.

When run inside the compose network (RAMP_E2E_IN_NETWORK=1) we use service
DNS names; otherwise we use the host-exposed ports.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass

import httpx
import psycopg

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
MARKETPLACE_DOMAIN = "exchange.e2e.local"
# Default signing key refs — must match those that the Exchange populates at
# startup (see src/exchange/cmd/server/main.go).
ED25519_KEY_REF = "exchange-primary"
RSA_KEY_REF = "cf-rsa-primary"
CLOUDFRONT_KEY_PAIR_ID = "cf-rsa-primary"

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
    marketplace_id: str
    aws_tenant_id: str
    aws_resource_id: str
    aws_resource_uri: str
    fastly_resource_id: str
    fastly_resource_uri: str


def _resolve_pg_dsn(compose_file: str) -> str:
    """Resolve the Postgres DSN based on whether we run inside compose or on the host."""
    if os.environ.get("RAMP_E2E_IN_NETWORK") == "1":
        return "postgres://ramp:ramp@postgres:5432/ramp"
    import subprocess

    result = subprocess.run(
        ["docker", "compose", "-f", compose_file, "port", "postgres", "5432"],
        capture_output=True,
        text=True,
        check=True,
    )
    mapping = result.stdout.strip()
    _, _, port_str = mapping.rpartition(":")
    port = int(port_str)
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


def _upsert_agent(dsn: str, *, agent_id: str) -> None:
    """Idempotent agent insert — Exchange's transaction_log FK requires this."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type)
            VALUES (%s, %s, 'AGENT')
            ON CONFLICT (agent_id) DO NOTHING
            """,
            # Demo agent: a zero-filled pubkey is fine — the Exchange doesn't
            # yet verify agent signatures in the scrappy-demo path.
            (agent_id, b"\x00" * 32),
        )
        conn.commit()


def _upsert_tenant_ed25519(dsn: str, *, tenant_id: str, domain: str) -> None:
    """Idempotent tenant insert for the ed25519-signed-URL scheme."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
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


def _upsert_catalog(dsn: str, *, resource_id: str, tenant_id: str, uri: str) -> None:
    """Idempotent catalog insert via direct SQL — matches the PushResources RPC shape."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.catalog (
                resource_id, tenant_id, uri, uri_prefix,
                pricing, licensing_rules, delivery_method
            ) VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, 'DIRECT')
            ON CONFLICT (resource_id) DO UPDATE SET
                uri = EXCLUDED.uri,
                uri_prefix = EXCLUDED.uri_prefix,
                updated_at = NOW()
            """,
            (
                resource_id,
                tenant_id,
                uri,
                uri,
                json.dumps({"unit_cost": 0.01, "currency": "USD", "unit": "access"}),
                json.dumps({}),
            ),
        )
        conn.commit()


def _upsert_marketplace(dsn: str, *, marketplace_id: str, domain: str) -> None:
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO broker.marketplaces (
                marketplace_id, domain, endpoint, trust_level,
                supported_profiles, priority, healthy
            ) VALUES (%s, %s, %s, 'VERIFIED', %s::jsonb, 10, TRUE)
            ON CONFLICT (marketplace_id) DO UPDATE SET
                domain = EXCLUDED.domain,
                endpoint = EXCLUDED.endpoint,
                trust_level = EXCLUDED.trust_level,
                updated_at = NOW()
            """,
            (
                marketplace_id,
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
    marketplace_id = "mp-e2e"
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
    _upsert_catalog(dsn, resource_id=resource_id, tenant_id=tenant_id, uri=resource_uri)
    _upsert_catalog(dsn, resource_id=aws_resource_id, tenant_id=aws_tenant_id, uri=aws_resource_uri)
    _upsert_catalog(
        dsn,
        resource_id=fastly_resource_id,
        tenant_id=tenant_id,
        uri=fastly_resource_uri,
    )
    # Broker matches exchanges by the `domain` advertised in the publisher's
    # ramp.json (see EXCHANGES_JSON in docker-compose.e2e.yml). Both edges
    # advertise the same Exchange domain so one registry row suffices.
    _upsert_marketplace(dsn, marketplace_id=marketplace_id, domain=MARKETPLACE_DOMAIN)

    # Exchange loads the catalog into a radix trie at startup; rebuild it.
    reload_exchange_catalog(compose_file, exchange_host_url)

    return SeededFixture(
        tenant_id=tenant_id,
        resource_id=resource_id,
        resource_uri=resource_uri,
        agent_id=agent_id,
        marketplace_id=marketplace_id,
        aws_tenant_id=aws_tenant_id,
        aws_resource_id=aws_resource_id,
        aws_resource_uri=aws_resource_uri,
        fastly_resource_id=fastly_resource_id,
        fastly_resource_uri=fastly_resource_uri,
    )


def reload_exchange_catalog(_compose_file: str, exchange_host_url: str) -> None:
    """Trigger the Exchange's in-process radix-trie rebuild.

    After seeding ramp.catalog rows via SQL, the Exchange still has the trie
    it built at startup. POST /admin/catalog/reload rebuilds it from the DB.
    """
    resp = httpx.post(f"{exchange_host_url}/admin/catalog/reload", timeout=10.0)
    if resp.status_code not in (httpx.codes.OK, httpx.codes.NO_CONTENT):
        msg = f"catalog reload failed: {resp.status_code} {resp.text[:256]}"
        raise RuntimeError(msg)
