"""Pure-data demo-catalog constants + fixture builders (no DB, no I/O).

This leaf module holds the demo-domain constants, buyer identities, and the
``DemoResource`` / ``SeededFixture`` dataclasses together with their pure
builders. It performs NO database access and NO network/subprocess I/O, so it
imports nothing from the seeding layer — the dependency is one-directional
(``seed`` → ``demo_catalog``) and cycle-free.

``seed.py`` re-exports every public name defined here, so the ~40 test modules
that ``from .seed import X`` continue to resolve unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# ───── Demo publisher domains (port-less; alias to their edges on port 80) ──
DEMO_PHILOSOPHY_DOMAIN = "demo.ramp-protocol.org"
DEMO_MUSIC_DOMAIN = "music.demo.ramp-protocol.org"
DEMO_SFX_DOMAIN = "sfx.demo.ramp-protocol.org"

# Back-compat aliases kept so the few remaining edge-agnostic call sites import
# cleanly; the demo catalog is served by path through the SAME publisher origin
# so the edge that fronts each domain is selected by the domain alias, not by a
# distinct host:port. These point at the philosophy (Cloudflare) publisher demo
# domain on its natural port 80.
EDGE_PUBLIC_URL = f"http://{DEMO_PHILOSOPHY_DOMAIN}"
DEMO_CF_PUBLISHER_HOST = DEMO_PHILOSOPHY_DOMAIN

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# 3rd-party contributor identity (kid == catalog-contributor-e2e). Served via the
# `catalog-contributor` well-known host (NOT pre-seeded in ramp.agents); the
# Exchange learns its key by fetching that host. Used by the new trust test's
# 3rd-party leg and by the existing full-path/ingest probes that push to a
# publisher listing it. See catalog_push.py for the keyfile format + gate details.
CATALOG_CONTRIBUTOR_ID = "catalog-contributor-e2e"
CONTRIBUTOR_KEY_PATH = _FIXTURES_DIR / "catalog_contributor_key.json"

# ───── Buyer identities (kid == agent_id; pinned in deploy/broker/keys.json so
# the Broker self-act gate + Exchange caller-authz admit them). The in-memory
# billing adapter authorizes a term ONLY when the buyer's balance currency
# matches the term currency (the currency check
# precedes the charge, so even a FREE/rate-0 term is denied on a mismatch). So
# EUR demo terms use the EUR buyer; USD demo terms use the USD buyer.
USD_AGENT_ID = "agent-e2e"  # EXCHANGE_BILLING_SEED: $100 USD
USD_AGENT_KEY_PATH = _FIXTURES_DIR / "agent_e2e_key.json"
EUR_AGENT_ID = "agent-demo-eur"  # EXCHANGE_BILLING_SEED: €1000 EUR
EUR_AGENT_KEY_PATH = _FIXTURES_DIR / "agent_demo_eur_key.json"

# Credit-less buyer: registered + keyed but absent from EXCHANGE_BILLING_SEED so
# the billing gate refuses it (obligation 00 failure-5).
NOBILLING_AGENT_ID = "agent-nobilling-e2e"
NOBILLING_AGENT_KEY_PATH = _FIXTURES_DIR / "agent_nobilling_e2e_key.json"

# Canary marker embedded in thales-of-miletus.txt (deploy/fixtures/demo/CATALOG.md).
CANARY_MARKER = "RAMP-DEMO-CANARY-8FK3J2-0418"


# ───── Demo resource catalog (from deploy/fixtures/demo/CATALOG.md). Each is a
# port-less demo-domain URI the tests fetch directly (the domain aliases to its
# edge). The owning tenant + the buyer whose currency matches the term are
# carried alongside so test scenarios can pick a resource by term-shape.


@dataclass(frozen=True)
class DemoResource:
    """One demo-catalog resource the rewritten e2e suites assert against.

    ``uri`` is the port-less demo-domain URI (resolves to ``edge_service`` via
    the network alias). ``buyer_agent_id`` / ``buyer_key_path`` is the buyer
    whose balance currency matches the term currency.
    """

    uri: str
    tenant_id: str
    domain: str
    edge_service: str  # "edge" | "fastly-edge" | "aws-edge"
    currency: str
    buyer_agent_id: str
    buyer_key_path: Path


def _demo_uri(domain: str, path: str) -> str:
    return f"http://{domain}{path}"


def _eur(uri_domain: str, path: str, tenant: str, edge: str) -> DemoResource:
    return DemoResource(
        uri=_demo_uri(uri_domain, path),
        tenant_id=tenant,
        domain=uri_domain,
        edge_service=edge,
        currency="EUR",
        buyer_agent_id=EUR_AGENT_ID,
        buyer_key_path=EUR_AGENT_KEY_PATH,
    )


def _usd(uri_domain: str, path: str, tenant: str, edge: str) -> DemoResource:
    return DemoResource(
        uri=_demo_uri(uri_domain, path),
        tenant_id=tenant,
        domain=uri_domain,
        edge_service=edge,
        currency="USD",
        buyer_agent_id=USD_AGENT_ID,
        buyer_key_path=USD_AGENT_KEY_PATH,
    )


@dataclass(frozen=True)
class SeededFixture:
    """Demo-catalog resources + buyers the rewritten e2e suites consume.

    Every resource is produced by ingesting the demo feeds through the real
    ``ramp-ingest`` binary — none is ``push_catalog``-ed. The buyer on
    each resource matches the term currency.
    """

    # Buyers.
    eur_agent_id: str
    eur_agent_key_path: Path
    usd_agent_id: str
    usd_agent_key_path: Path
    nobilling_agent_id: str
    nobilling_agent_key_path: Path

    # FREE term (socrates: FREE EUR, academic/EU) on the Cloudflare edge.
    free: DemoResource
    # Priced PER_UNIT term (wooden-door-creak: 0.25 USD/accesses, commercial,
    # EU/US/GB) on the AWS edge.
    priced_per_unit: DemoResource
    priced_per_unit_rate: float
    # Geo/user-type restricted multi-term resource (plato: academic-FREE +
    # commercial-PER_UNIT, EUR, geo[EU]) on the Cloudflare edge.
    restricted: DemoResource
    restricted_commercial_rate: float
    # Another multi-term resource (zeno-of-citium: academic-FREE EUR +
    # commercial-PER_UNIT USD) on the Cloudflare edge. Its commercial term is
    # USD so the commercial path uses the USD buyer.
    multi_term: DemoResource
    multi_term_commercial_rate: float
    multi_term_commercial_buyer_id: str
    multi_term_commercial_buyer_key_path: Path
    # Retrieval canary (thales-of-miletus: FLAT 9.99 EUR, geo[EU]) on the
    # Cloudflare edge. Body carries RAMP-DEMO-CANARY-8FK3J2-0418.
    canary: DemoResource
    canary_marker: str
    # One resource per edge runtime (the FREE/affordable resource the
    # signed-URL fetch tests follow to each edge).
    cloudflare: DemoResource
    fastly: DemoResource
    aws: DemoResource


def _build_fixture() -> SeededFixture:
    """Assemble the demo-resource fixture (pure data, no I/O)."""
    socrates = _eur(
        DEMO_PHILOSOPHY_DOMAIN,
        "/articles/philosophers/socrates.txt",
        "tenant-demo-philosophy",
        "edge",
    )
    wooden_door = _usd(
        DEMO_SFX_DOMAIN, "/sfx/wooden-door-creak.json", "tenant-demo-sfx", "aws-edge"
    )
    plato = _eur(
        DEMO_PHILOSOPHY_DOMAIN, "/articles/philosophers/plato.txt", "tenant-demo-philosophy", "edge"
    )
    zeno = _eur(
        DEMO_PHILOSOPHY_DOMAIN,
        "/articles/philosophers/zeno-of-citium.txt",
        "tenant-demo-philosophy",
        "edge",
    )
    thales = _eur(
        DEMO_PHILOSOPHY_DOMAIN,
        "/articles/philosophers/thales-of-miletus.txt",
        "tenant-demo-philosophy",
        "edge",
    )
    # paper-satellites: FLAT 3.50 USD, geo[US], no user-type restriction — a
    # clean non-subscription Fastly-edge resource a USD buyer fetches. (The
    # demo's truly-unrestricted music resources are all subscription/
    # reference_only, which yield no offer on a plain resolve.)
    paper_satellites = _usd(
        DEMO_MUSIC_DOMAIN, "/lyrics/paper-satellites.txt", "tenant-demo-music", "fastly-edge"
    )
    # rain-on-tin-roof: FREE USD, individual, EU/US/GB — the AWS-edge FREE
    # resource a USD individual buyer can fetch.
    rain = _usd(DEMO_SFX_DOMAIN, "/sfx/rain-on-tin-roof.json", "tenant-demo-sfx", "aws-edge")
    return SeededFixture(
        eur_agent_id=EUR_AGENT_ID,
        eur_agent_key_path=EUR_AGENT_KEY_PATH,
        usd_agent_id=USD_AGENT_ID,
        usd_agent_key_path=USD_AGENT_KEY_PATH,
        nobilling_agent_id=NOBILLING_AGENT_ID,
        nobilling_agent_key_path=NOBILLING_AGENT_KEY_PATH,
        free=socrates,
        priced_per_unit=wooden_door,
        priced_per_unit_rate=0.25,
        restricted=plato,
        restricted_commercial_rate=0.03,
        multi_term=zeno,
        multi_term_commercial_rate=0.04,
        multi_term_commercial_buyer_id=USD_AGENT_ID,
        multi_term_commercial_buyer_key_path=USD_AGENT_KEY_PATH,
        canary=thales,
        canary_marker=CANARY_MARKER,
        cloudflare=socrates,
        fastly=paper_satellites,
        aws=rain,
    )
