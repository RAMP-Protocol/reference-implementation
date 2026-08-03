"""Seeding helpers for the E2E stack — Phase-2b demo-catalog edition.

The e2e catalog is THE three demo publisher feeds
(``deploy/fixtures/demo/{philosophy,music,sfx}.jsonl``), ingested through the
REAL production binary ``cmd/ramp-ingest`` (ParseJSONL → mapRecord →
licenseterm.Normalize/Validate → signed ``CatalogService/PushResources`` RPC).
There is NO Python re-implementation of mapper.go and NO ``push_catalog`` of
demo content — the binary's single signed RPC is the only catalog write.

The binary ships in the runner image at ``/usr/local/bin/ramp-ingest``
(built by the Go builder stage of ``tests/e2e/Dockerfile``); the seed shells
out to it once per feed, under the owning demo-domain tenant.

Setup state that in production would arrive through separate onboarding paths
is still written via direct SQL (the production onboarding RPCs are out of e2e
scope): tenant rows (``ramp.tenants``), buyer/agent rows (``ramp.agents``), the
broker exchange row (``broker.exchanges``), and the per-tenant broker-relay
opt-in.

NO catalog-writer signing key is pre-seeded into ``ramp.agents`` (Core
Invariant). Each demo feed is ingested under its publisher's OWN self-publish
key (caller_id == domain); the Exchange learns that key ONLY by fetching the
publisher's edge Web Bot Auth directory
(``/.well-known/http-message-signatures-directory``) keys[] (Gate-1 self-signup).
The 3rd-party ``catalog-contributor-e2e`` identity is likewise learned only via
its own well-known host (the ``catalog-contributor`` compose service).

The three demo domains resolve in-network to their edges via docker-compose
network aliases (demo.→Cloudflare, music.→Fastly, sfx.→AWS), each edge serving
its publisher's ``/.well-known/ramp.json`` (listing ``catalog-contributor-e2e``
for Gate 2 and ``exchange.e2e.local`` for the Broker probe) AND verifying +
serving the signed content on port 80. So BOTH the Exchange Gate-2 manifest
fetch and the agent's signed-URL content fetch resolve natively to the right
edge — tests fetch demo-domain URIs directly, no Host override.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import httpx
import psycopg
from ramp_sdk.b64 import b64url_decode

from .catalog_push import (
    load_public_key_bytes,
)
from .demo_catalog import (
    _FIXTURES_DIR,
    CANARY_MARKER,  # noqa: F401  (re-exported for the ~40 `from .seed import` call sites)
    CATALOG_CONTRIBUTOR_ID,
    CONTRIBUTOR_KEY_PATH,  # noqa: F401  (re-exported)
    DEMO_CF_PUBLISHER_HOST,  # noqa: F401  (re-exported)
    DEMO_MUSIC_DOMAIN,
    DEMO_PHILOSOPHY_DOMAIN,
    DEMO_SFX_DOMAIN,
    DemoResource,  # noqa: F401  (re-exported)
    EDGE_PUBLIC_URL,  # noqa: F401  (re-exported)
    EUR_AGENT_ID,
    EUR_AGENT_KEY_PATH,
    NOBILLING_AGENT_ID,
    NOBILLING_AGENT_KEY_PATH,
    SeededFixture,
    USD_AGENT_ID,
    USD_AGENT_KEY_PATH,
    _build_fixture,
)

EXCHANGE_INTERNAL_URL = "http://exchange:8081"
EXCHANGE_DOMAIN = "exchange:8081"

# ───── Multi-exchange topology: 3 REAL exchanges, each with its own
# catalog DB + identity. exchange-a keeps the cluster default DB `ramp` (shared
# with the broker schema); exchange-b/c get separate databases `ramp_b`/`ramp_c`.
# Each exchange's EXCHANGE_DOMAIN is stamped onto Offer.exchange, and its
# EXCHANGE_PUBLIC_ORIGIN MUST equal the endpoint registered in broker.exchanges
# (the post-resolve SSRF equality gate). The music publisher (fastly-edge) is
# fronted by exchange-b; the sfx publisher (aws-edge) by exchange-c.
EXCHANGE_B_DOMAIN = "exchange-b:8081"
EXCHANGE_B_INTERNAL_URL = "http://exchange-b:8081"
EXCHANGE_C_DOMAIN = "exchange-c:8081"
EXCHANGE_C_INTERNAL_URL = "http://exchange-c:8081"

# Default signing key refs — must match those the Exchange populates at startup
# (see src/exchange/cmd/server/main.go).
ED25519_KEY_REF = "exchange-primary"
RSA_KEY_REF = "cf-rsa-primary"
CLOUDFRONT_KEY_PAIR_ID = "cf-rsa-primary"

DEFAULT_PG_CONNECT_TIMEOUT_SEC = 20

# Per-domain SELF-PUBLISH signing keys: caller_id == publisher domain. The
# demo ingest signs each feed with its publisher's own key (caller_id == domain;
# keyid == thumbprint), so Gate-1 self-signup fetches the publisher's edge WBA
# directory (keys[]) and Gate-2 passes on the caller==domain branch — no DB
# pre-seed. Generated idempotently
# by scripts/gen-e2e-keys.sh; the SAME private fixture's pubkey is served by the edge.
SELFPUB_PHILOSOPHY_KEY_PATH = _FIXTURES_DIR / "selfpub_philosophy_key.json"
SELFPUB_MUSIC_KEY_PATH = _FIXTURES_DIR / "selfpub_music_key.json"
SELFPUB_SFX_KEY_PATH = _FIXTURES_DIR / "selfpub_sfx_key.json"

# Per-edge demo feeds + their owning tenant/scheme. The Exchange derives the owning
# tenant from each ResourceEntry's domain via the UNIQUE ramp.tenants.domain
# mapping, so the binary's --tenant MUST be the domain's tenant.
#
# (tenant_id, domain, signing_scheme, repo-relative feed path, self-publish key)
DEMO_PUBLISHERS: tuple[tuple[str, str, str, str, Path], ...] = (
    (
        "tenant-demo-philosophy",
        DEMO_PHILOSOPHY_DOMAIN,
        "ED25519",
        "deploy/fixtures/demo/philosophy.jsonl",
        SELFPUB_PHILOSOPHY_KEY_PATH,
    ),
    (
        "tenant-demo-music",
        DEMO_MUSIC_DOMAIN,
        "ED25519",
        "deploy/fixtures/demo/music.jsonl",
        SELFPUB_MUSIC_KEY_PATH,
    ),
    (
        "tenant-demo-sfx",
        DEMO_SFX_DOMAIN,
        "AWS_CLOUDFRONT_RSA",
        "deploy/fixtures/demo/sfx.jsonl",
        SELFPUB_SFX_KEY_PATH,
    ),
)

# Edge public hosts used by the relay-flow e2e tests (ported from the v1.1
# harness during the merge reconciliation).
EDGE_PUBLIC_HOST = "edge:8787"
AWS_EDGE_PUBLIC_HOST = "aws-edge:8788"
FASTLY_EDGE_PUBLIC_HOST = "fastly-edge:7676"


def _set_allow_broker_relay(dsn: str, *, tenant_id: str) -> None:
    """Opt a tenant into broker-relayed transactions (column defaults to FALSE)."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE ramp.tenants SET allow_broker_relay = TRUE WHERE tenant_id = %s",
            (tenant_id,),
        )
        conn.commit()


# Broker outbound-relay identity (kid prefixed "broker."). The Broker signs
# relayed Exchange RPCs with this key (BROKER_RELAY_KEY_FILE), so the Exchange's
# resolveCaller must find the kid classified as BROKER; authorizeForAgent then
# honours it on tenants with allow_broker_relay=true. The pubkey is READ from
# the generated broker-relay fixture (the same file the broker container mounts)
# so seed registration and the broker's actual signing key can never drift.
_BROKER_RELAY_KID = "broker.broker-local.v1"
_BROKER_RELAY_KEY_FILE = _FIXTURES_DIR / "broker_relay_key.json"


def _broker_relay_pubkey_bytes() -> bytes:
    """Raw 32-byte Ed25519 pubkey of the broker-relay identity, from the fixture."""
    doc = json.loads(_BROKER_RELAY_KEY_FILE.read_text())
    return b64url_decode(doc["public_key"])


# ───── DSN + readiness ──────────────────────────────────────────────────────


def _resolve_pg_dsn(compose_file: str) -> str:
    """Resolve the Postgres DSN based on whether we run inside compose or on the host."""
    return _resolve_pg_dsn_for_db(compose_file, "ramp")


def _resolve_pg_dsn_for_db(compose_file: str, db_name: str) -> str:
    """Resolve the Postgres DSN for a SPECIFIC database on the same cluster.

    All three exchange catalog DBs (``ramp``, ``ramp_b``, ``ramp_c``) live on the
    one Postgres cluster; only the database name in the DSN differs. The broker
    schema lives in ``ramp`` (BROKER_DSN), so the broker.exchanges registry is
    written there while each exchange's tenants/agents go into its own DB.
    """
    if os.environ.get("RAMP_E2E_IN_NETWORK") == "1":
        return f"postgres://ramp:ramp@postgres:5432/{db_name}"
    from ._compose import resolve_host_port

    port = resolve_host_port(Path(compose_file), "postgres", 5432)
    return f"postgres://ramp:ramp@127.0.0.1:{port}/{db_name}"


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


def _wait_exchange_ready(exchange_host_url: str, timeout_seconds: float = 20.0) -> None:
    """Wait for Exchange healthz."""
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


# ───── Tenant / agent / exchange registration (direct SQL — onboarding RPCs
# are out of e2e scope) ─────────────────────────────────────────────────────


def _register_tenant(dsn: str, *, tenant_id: str, domain: str, scheme: str) -> None:
    """Idempotent tenant insert for either signing scheme.

    ``ramp.tenants`` has UNIQUE constraints on BOTH tenant_id and domain; we
    check-before-insert so the first caller wins the domain and reruns no-op.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM ramp.tenants WHERE domain = %s", (domain,))
        if cur.fetchone() is not None:
            cur.execute(
                "UPDATE ramp.tenants SET allow_broker_relay = TRUE WHERE domain = %s",
                (domain,),
            )
            conn.commit()
            return
        if scheme == "AWS_CLOUDFRONT_RSA":
            cur.execute(
                """
                INSERT INTO ramp.tenants (
                    tenant_id, domain, hmac_secret_ref, ed25519_key_ref,
                    reporting_policy, signing_scheme, rsa_key_ref,
                    cloudfront_key_pair_id, allow_broker_relay
                ) VALUES (%s, %s, 'none', %s, '{}', 'AWS_CLOUDFRONT_RSA', %s, %s, TRUE)
                """,
                (tenant_id, domain, ED25519_KEY_REF, RSA_KEY_REF, CLOUDFRONT_KEY_PAIR_ID),
            )
        else:
            cur.execute(
                """
                INSERT INTO ramp.tenants (
                    tenant_id, domain, hmac_secret_ref, ed25519_key_ref,
                    reporting_policy, signing_scheme, allow_broker_relay
                ) VALUES (%s, %s, 'none', %s, '{}', 'ED25519', TRUE)
                """,
                (tenant_id, domain, ED25519_KEY_REF),
            )
        conn.commit()


def _upsert_agent(
    dsn: str, *, agent_id: str, pubkey: bytes | None = None, requester_type: str = "AGENT"
) -> None:
    """Register an agent in ramp.agents (FK target + caller authz).

    ``pubkey`` is optional: when omitted it is derived from the agent's signing
    keyfile via :func:`_agent_public_key` (the relay-flow tests register agents
    without passing a key), else a zero placeholder for pure FK targets.

    Buyer agents (requester_type AGENT) get ``billing_ref`` set equal to their
    ``agent_id``. Production mints a random handle at Register (ADR-021 D1), but
    the demo path never calls Register (onboarding RPC is out of e2e scope), and
    the paid charge path denies an agent whose row carries no billing_ref
    (BILLING_REF_INACTIVE). Reusing the agent_id as the handle keeps the
    agent_id-keyed EXCHANGE_BILLING_SEED balances working without re-keying. A
    matching active SoR account is seeded by :func:`_register_sor_accounts`.
    Brokers keep a NULL billing_ref — they relay, they never buy.
    """
    if pubkey is None:
        pubkey = _agent_public_key(agent_id)
    billing_ref = agent_id if requester_type == "AGENT" else None
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ramp.agents (agent_id, public_key, requester_type, billing_ref)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (agent_id) DO UPDATE SET
                public_key = EXCLUDED.public_key,
                requester_type = EXCLUDED.requester_type,
                billing_ref = EXCLUDED.billing_ref
            """,
            (agent_id, pubkey, requester_type, billing_ref),
        )
        conn.commit()


def _register_sor_accounts(sor_dsn: str, agent_ids: tuple[str, ...]) -> None:
    """Seed active System-of-Record accounts for the demo buyers.

    The paid charge path reads the buyer's billing_ref off its ramp.agents row
    (set to the agent_id by :func:`_upsert_agent`) and then asks the SoR whether
    that account is active (IsActive → checkAccountActive). The SoR runs in its
    OWN database (EXCHANGE_SOR_DSN: ramp_sor / ramp_sor_b / ramp_sor_c), which
    starts empty — so an account the SoR does not know is denied
    BILLING_REF_INACTIVE before Authorize. Registering an active account
    (billing_ref == subdomain == agent_id) lets the paid path reach billing;
    funding is separate (EXCHANGE_BILLING_SEED), so an active-but-unfunded buyer
    is correctly denied INSUFFICIENT_BALANCE, not BILLING_REF_INACTIVE.
    """
    with psycopg.connect(sor_dsn) as conn, conn.cursor() as cur:
        for agent_id in agent_ids:
            cur.execute(
                """
                INSERT INTO sor.agent_accounts (billing_ref, subdomain, active)
                VALUES (%s, %s, TRUE)
                ON CONFLICT (billing_ref) DO UPDATE SET active = TRUE
                """,
                (agent_id, agent_id),
            )
        conn.commit()


def _upsert_exchange(dsn: str, *, exchange_id: str, domain: str, endpoint: str) -> None:
    """Idempotent broker.exchanges insert (check-before-insert on domain).

    ``endpoint`` is the exchange's EXCHANGE_PUBLIC_ORIGIN — the broker's relay
    SSRF-equality gate (exchange_relay.go) matches the well-known-resolved
    endpoint against THIS registered value, so per the multi-exchange topology
    each row carries its own exchange's origin (exchange-a/b/c).
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
                domain = EXCLUDED.domain, endpoint = EXCLUDED.endpoint,
                trust_level = EXCLUDED.trust_level, updated_at = NOW()
            """,
            (exchange_id, domain, endpoint, json.dumps(["ramp-news-v1"])),
        )
        conn.commit()


def _register_tenants_and_buyers(dsn: str) -> None:
    """Register every demo tenant + buyer + the broker-relay agent in ONE catalog DB.

    Multi-exchange topology: execute's caller-authz resolves the requester
    via ``agents.ByID`` against the EXCHANGE's OWN catalog DB, so the full setup
    (all 3 demo tenants + the 3 buyers + the broker-relay agent) is replicated into
    EACH exchange DB (``ramp``, ``ramp_b``, ``ramp_c``). Registering all 3 tenants
    in every DB is harmless — each exchange only ingests its own publisher's feed,
    so the catalog rows stay isolated even though the tenant rows are replicated.

    Deliberately does NOT pre-seed any catalog-writer signing key into
    ``ramp.agents`` (Core Invariant). The demo publishers' self-publish
    keys and the 3rd-party contributor key are learned by the Exchange ONLY via
    the well-known fetch at catalog-push time (Gate-1 self-signup).
    """
    for tenant_id, domain, scheme, _feed, _key in DEMO_PUBLISHERS:
        _register_tenant(dsn, tenant_id=tenant_id, domain=domain, scheme=scheme)
        # the agent originates ExecuteTransaction via the Broker relay
        # (agent sig1 + broker sig2); authorizeForAgent honours the relay only on
        # tenants opted in here.
        _set_allow_broker_relay(dsn, tenant_id=tenant_id)

    # Buyers + the credit-less buyer (real pubkeys; kid == agent_id). Buyers are
    # registered directly because their onboarding RPC is out of e2e scope — this
    # is distinct from the catalog-WRITER keys, which the well-known-trust rule forbids pre-seeding.
    _upsert_agent(dsn, agent_id=USD_AGENT_ID, pubkey=load_public_key_bytes(USD_AGENT_KEY_PATH))
    _upsert_agent(dsn, agent_id=EUR_AGENT_ID, pubkey=load_public_key_bytes(EUR_AGENT_KEY_PATH))
    _upsert_agent(
        dsn, agent_id=NOBILLING_AGENT_ID, pubkey=load_public_key_bytes(NOBILLING_AGENT_KEY_PATH)
    )
    # Broker outbound-relay identity (classified BROKER).
    _upsert_agent(
        dsn,
        agent_id=_BROKER_RELAY_KID,
        pubkey=_broker_relay_pubkey_bytes(),
        requester_type="BROKER",
    )


def _register_exchange_registry(broker_dsn: str) -> None:
    """Write the 3 broker.exchanges routing rows into the BROKER DB (ramp).

    One row per exchange; each endpoint equals that exchange's
    EXCHANGE_PUBLIC_ORIGIN so the broker's relay SSRF-equality gate passes.
    """
    _upsert_exchange(
        broker_dsn, exchange_id="ex-demo", domain=EXCHANGE_DOMAIN, endpoint=EXCHANGE_INTERNAL_URL
    )
    _upsert_exchange(
        broker_dsn,
        exchange_id="ex-demo-b",
        domain=EXCHANGE_B_DOMAIN,
        endpoint=EXCHANGE_B_INTERNAL_URL,
    )
    _upsert_exchange(
        broker_dsn,
        exchange_id="ex-demo-c",
        domain=EXCHANGE_C_DOMAIN,
        endpoint=EXCHANGE_C_INTERNAL_URL,
    )


# ───── Ingest via the REAL production binary ────────────────────────────────


def _ingest_binary_path() -> str:
    """Locate the ramp-ingest binary.

    In the runner image the Go builder stage installs it at
    ``/usr/local/bin/ramp-ingest``; a ``RAMP_INGEST_BIN`` override
    lets a host run point at a locally-built or ``go run`` shim.
    """
    return os.environ.get("RAMP_INGEST_BIN", "/usr/local/bin/ramp-ingest")


def _repo_root(compose_file: str) -> Path:
    return Path(compose_file).resolve().parent


def _ingest_feed(
    *, exchange_url: str, tenant_id: str, feed_abspath: Path, binary: str, key_path: Path
) -> None:
    """Shell out to the production ramp-ingest binary for one feed.

    The binary signs (RFC 9421) and POSTs a single ``PushResources`` RPC — the
    only catalog write. ``key_path`` is the publisher's SELF-PUBLISH key (kid ==
    domain); the binary's caller_id is that kid, so Gate-1 self-signup resolves
    it from the publisher's edge well-known and Gate-2 passes caller==domain — no
    DB pre-seed. A non-zero rejected count or non-zero exit fails the seed.
    """
    proc = subprocess.run(
        [
            binary,
            "--exchange-url",
            exchange_url,
            "--tenant",
            tenant_id,
            "--key",
            str(key_path),
            str(feed_abspath),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    if proc.returncode != 0 or "rejected=0" not in proc.stderr:
        msg = (
            f"ramp-ingest failed for {feed_abspath} (tenant={tenant_id}): "
            f"rc={proc.returncode}\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}"
        )
        raise RuntimeError(msg)


def _ingest_all_feeds(compose_file: str, exchange_url_by_domain: dict[str, str]) -> None:
    """Ingest each demo feed into its OWNING exchange's catalog DB.

    ``exchange_url_by_domain`` maps each publisher domain to the URL of the
    exchange that owns it (host-mapped on a host run, docker-DNS in-network). The
    music catalog lands in exchange-b's DB and the sfx catalog in exchange-c's DB
    — the catalog isolation the separate-DB topology guarantees.
    """
    binary = _ingest_binary_path()
    root = _repo_root(compose_file)
    for tenant_id, domain, _scheme, feed_rel, key_path in DEMO_PUBLISHERS:
        feed_abspath = root / feed_rel
        _ingest_feed(
            exchange_url=exchange_url_by_domain[domain],
            tenant_id=tenant_id,
            feed_abspath=feed_abspath,
            binary=binary,
            key_path=key_path,
        )


# ───── Public seed entrypoint ───────────────────────────────────────────────


def seed_stack(
    compose_file: str,
    exchange_host_url: str,
    *,
    exchange_b_host_url: str | None = None,
    exchange_c_host_url: str | None = None,
) -> SeededFixture:
    """Seed the 3-exchange E2E stack with the demo catalogs.

    Multi-exchange topology: tenants + buyers + the broker-relay agent are
    registered into EACH exchange's OWN catalog DB (ramp / ramp_b / ramp_c) — the
    execute caller-authz resolves the requester via agents.ByID against the
    exchange's own DB, so all 3 DBs need the buyer/relay rows. The broker.exchanges
    registry (3 rows, one per exchange) is written ONCE into the broker DB (ramp).
    Each demo feed is ingested into its owning exchange's DB.

    ``exchange_b_host_url`` / ``exchange_c_host_url`` default to the docker-DNS
    in-network URLs (the runner path); a host run passes the host-mapped URLs.

    Idempotent: tenant/agent/exchange registration is upsert/check-before-insert,
    and re-ingesting a feed re-pushes the same entries (the catalog is keyed by
    tenant+URI, so a repeat push is a no-op overwrite).
    """
    ex_b_url = exchange_b_host_url or EXCHANGE_B_INTERNAL_URL
    ex_c_url = exchange_c_host_url or EXCHANGE_C_INTERNAL_URL

    broker_dsn = _resolve_pg_dsn(compose_file)  # the broker schema lives in `ramp`
    dsn_a = broker_dsn
    dsn_b = _resolve_pg_dsn_for_db(compose_file, "ramp_b")
    dsn_c = _resolve_pg_dsn_for_db(compose_file, "ramp_c")

    for dsn in (dsn_a, dsn_b, dsn_c):
        _wait_pg(dsn)
    _wait_exchange_ready(exchange_host_url)
    _wait_exchange_ready(ex_b_url)
    _wait_exchange_ready(ex_c_url)

    # Tenants + buyers + broker-relay into EACH exchange's catalog DB.
    for dsn in (dsn_a, dsn_b, dsn_c):
        _register_tenants_and_buyers(dsn)
    # Active SoR accounts for the buyers in EACH exchange's OWN SoR database
    # (ramp_sor / ramp_sor_b / ramp_sor_c), keyed by billing_ref == agent_id.
    # Without these the now-live SoR active check (checkAccountActive) denies
    # every paid transaction BILLING_REF_INACTIVE before Authorize.
    buyer_ids = (USD_AGENT_ID, EUR_AGENT_ID, NOBILLING_AGENT_ID)
    for sor_db in ("ramp_sor", "ramp_sor_b", "ramp_sor_c"):
        sor_dsn = _resolve_pg_dsn_for_db(compose_file, sor_db)
        _wait_pg(sor_dsn)
        _register_sor_accounts(sor_dsn, buyer_ids)
    # Broker → Exchange routing rows (3) in the broker DB.
    _register_exchange_registry(broker_dsn)

    _ingest_all_feeds(
        compose_file,
        {
            DEMO_PHILOSOPHY_DOMAIN: exchange_host_url,
            DEMO_MUSIC_DOMAIN: ex_b_url,
            DEMO_SFX_DOMAIN: ex_c_url,
        },
    )
    return _build_fixture()


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
    pub = b64url_decode(_BROKER_RELAY_PUBKEY_B64)
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


_SIGNING_AGENT_KEY_FILES = {
    "agent-e2e": _FIXTURES_DIR / "agent_e2e_key.json",
    "agent-nobilling-e2e": _FIXTURES_DIR / "agent_nobilling_e2e_key.json",
}

_BROKER_RELAY_PUBKEY_B64 = "gCX76Qe6aRTjVWd2WIFaLtfTzBjA9EFFHUg3pz5AE9s"
