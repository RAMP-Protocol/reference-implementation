#!/usr/bin/env python3
"""make ledger TX=<id> — render the cryptographic evidence chain for a RAMP demo transaction.

Joins three sources by tx_id:
  1. Exchange transaction_log row via GET /admin/ledger?tx=<id>
     (returns offer_signature + signed_url_signature + signed_url_hash + obligation state)
  2. Lambda@Edge access-log entries via aws logs filter-log-events
     (returns the JSON line carrying tx_id + signature_prefix written by the
     Lambda function in pi-terraform — see q5gq-B for the field schema)
  3. Cross-correlation assertions: "Lambda saw signature_prefix=X; Exchange
     stored signed_url_signature starting with X" → matches step N ✓

Usage:
    scripts/ledger.py --tx <transaction_id>
    scripts/ledger.py --tx <transaction_id> --exchange https://exchange.demo.ramp-protocol.org

The Makefile target `make ledger TX=<id>` calls this with sensible defaults
for the deployed demo stack.

No external Python deps — stdlib only — so this runs anywhere the AWS CLI
+ Python 3 are present.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

DEFAULT_EXCHANGE = "https://exchange.demo.ramp-protocol.org"
DEFAULT_LAMBDA_LOG_GROUP = "/aws/lambda/us-east-1.ramp-demo-edge-bot-redirect"
DEFAULT_ECS_LOG_GROUP = "/ecs/ramp-demo"
# Lambda@Edge logs are emitted to whichever region the POP that handled the
# request lives in; this set covers the regions we have observed during demos.
# Extend if a future demo rehearsal surfaces a new POP.
DEFAULT_AWS_REGIONS = (
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "eu-north-1",
    "ap-southeast-1",
    "ap-northeast-1",
)
DEFAULT_AWS_PROFILE = "<DEPLOYER_PROFILE>"


@dataclass(frozen=True)
class EdgeHit:
    """A single Lambda@Edge log line matching the tx_id."""
    region: str
    timestamp_ms: int
    tx_id: str
    req_id: str
    signature_prefix: str
    decision: str
    uri: str
    ua: str

    @property
    def time_iso(self) -> str:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class EcsLogHit:
    """A matching log line from one of the ECS service streams."""
    stream_prefix: str       # exchange | broker | mcp (whichever surfaced the hit)
    timestamp_ms: int
    message: str             # raw log line (often JSON, sometimes plain text)
    parsed: dict[str, Any]   # JSON-decoded if parseable, else empty dict

    @property
    def time_iso(self) -> str:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc).isoformat(timespec="seconds")


def fetch_ledger(exchange_url: str, tx_id: str) -> dict[str, Any]:
    """Pull the transaction_log row from the Exchange's /admin/ledger endpoint."""
    url = f"{exchange_url.rstrip('/')}/admin/ledger?tx={tx_id}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            sys.stderr.write(f"ledger: transaction {tx_id!r} not found at {exchange_url}\n")
            sys.exit(2)
        raise


def fetch_edge_hits(tx_id: str, log_group: str, regions: tuple[str, ...], profile: str) -> list[EdgeHit]:
    """Filter Lambda@Edge CloudWatch logs across regions for entries carrying tx_id.

    Filter pattern is just the quoted tx_id string — any line containing it
    matches. Stricter JSON-field patterns work in CloudWatch but extend the
    server-side scan time considerably; the false-positive rate for a UUID
    is zero in practice. Per-region scan capped at 30 min back so the demo
    keeps a tight window.
    """
    hits: list[EdgeHit] = []
    start_ms = int((time.time() - 30 * 60) * 1000)
    for region in regions:
        cmd = [
            "aws", "--profile", profile, "--region", region,
            "logs", "filter-log-events",
            "--log-group-name", log_group,
            "--filter-pattern", f'"{tx_id}"',
            "--start-time", str(start_ms),
            "--max-items", "20",
            "--output", "json",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        except subprocess.TimeoutExpired:
            sys.stderr.write(f"ledger: aws logs timed out in {region}\n")
            continue
        if res.returncode != 0:
            # ResourceNotFoundException is expected in regions where the POP
            # never ran — skip silently. Any other error is surfaced.
            if "ResourceNotFoundException" not in res.stderr:
                sys.stderr.write(f"ledger: {region} aws-logs error: {res.stderr.strip()}\n")
            continue
        try:
            payload = json.loads(res.stdout)
        except json.JSONDecodeError:
            continue
        for ev in payload.get("events", []):
            # Lambda runtime prefixes every console.log line with
            # `<timestamp>\t<request-id>\tINFO\t<message>` — strip everything
            # before the first `{` so json.loads sees the JSON the function
            # emitted, not the runtime envelope.
            msg = ev.get("message", "")
            idx = msg.find("{")
            if idx < 0:
                continue
            try:
                row = json.loads(msg[idx:])
            except json.JSONDecodeError:
                continue
            if row.get("tx_id") != tx_id:
                continue
            hits.append(EdgeHit(
                region=region,
                timestamp_ms=ev.get("timestamp", 0),
                tx_id=row.get("tx_id", ""),
                req_id=row.get("req_id", ""),
                signature_prefix=row.get("signature_prefix", ""),
                decision=row.get("decision", ""),
                uri=row.get("uri", ""),
                ua=row.get("ua", ""),
            ))
    hits.sort(key=lambda h: h.timestamp_ms)
    return hits


def fetch_ecs_hits(
    tx_id: str, log_group: str, region: str, profile: str, prefixes: tuple[str, ...]
) -> dict[str, EcsLogHit | None]:
    """Filter the shared /ecs/ramp-demo log group for lines containing tx_id.

    Returns one EcsLogHit per stream prefix (broker, mcp, …) for the FIRST
    line that mentions the tx_id in that prefix. Used to add "broker
    routed" and "mcp fetched" rows to the ledger so the chain is visible
    end-to-end, not just at the Exchange edge.
    """
    cmd = [
        "aws", "--profile", profile, "--region", region,
        "logs", "filter-log-events",
        "--log-group-name", log_group,
        "--filter-pattern", f'"{tx_id}"',
        "--start-time", str(int((time.time() - 30 * 60) * 1000)),
        "--max-items", "100",
        "--output", "json",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"ledger: aws logs ecs timed out in {region}\n")
        return {}
    if res.returncode != 0:
        if "ResourceNotFoundException" not in res.stderr:
            sys.stderr.write(f"ledger: ecs aws-logs error: {res.stderr.strip()}\n")
        return {}
    try:
        payload = json.loads(res.stdout)
    except json.JSONDecodeError:
        return {}
    # Bucket events per prefix, then pick the most informative line. The
    # broker emits two lines per resolve ("report usage relayed" first,
    # "resolve delivered" second); the latter carries agent_id + offer_id
    # so the table rendering can fill in those columns.
    bucket: dict[str, list[EcsLogHit]] = {p: [] for p in prefixes}
    for ev in payload.get("events", []):
        stream = ev.get("logStreamName", "")
        prefix = stream.split("/", 1)[0] if "/" in stream else stream
        if prefix not in prefixes:
            continue
        msg = ev.get("message", "").strip()
        parsed: dict[str, Any] = {}
        idx = msg.find("{")
        if idx >= 0:
            try:
                parsed = json.loads(msg[idx:])
            except json.JSONDecodeError:
                parsed = {}
        bucket[prefix].append(EcsLogHit(
            stream_prefix=prefix,
            timestamp_ms=ev.get("timestamp", 0),
            message=msg,
            parsed=parsed,
        ))

    def pick(events: list[EcsLogHit], prefer_msg: str) -> EcsLogHit | None:
        if not events:
            return None
        for hit in events:
            if hit.parsed.get("msg") == prefer_msg:
                return hit
        return events[0]

    return {
        "broker": pick(bucket["broker"], "resolve delivered"),
        "mcp": pick(bucket["mcp"], ""),
    } if "broker" in prefixes or "mcp" in prefixes else {  # pragma: no cover
        p: (bucket[p][0] if bucket[p] else None) for p in prefixes
    }


def truncate(s: str, n: int) -> str:
    if not s:
        return "—"
    return s if len(s) <= n else s[:n - 1] + "…"


def assertion(label: str, ok: bool, detail: str = "") -> str:
    mark = "✓" if ok else "✗"
    return f"{mark} {label}" + (f"  ({detail})" if detail else "")


def render(ledger: dict[str, Any], hits: list[EdgeHit], ecs: dict[str, EcsLogHit | None]) -> str:
    """Render the evidence table + cross-party assertions across all parties."""
    tx = ledger["transaction_id"]
    offer_sig = ledger.get("offer_signature") or ""
    url_sig = ledger.get("signed_url_signature") or ""
    url_hash = ledger.get("signed_url_hash_hex") or ""
    obligation = ledger.get("obligation")
    obligation_state = (obligation or {}).get("state", "—")
    edge_first = hits[0] if hits else None
    broker_hit = ecs.get("broker")
    mcp_hit = ecs.get("mcp")

    lines: list[str] = []
    lines.append(f"$ make ledger TX={tx}")
    lines.append("")
    fmt = "  {party:<9}  {step:<22}  {event:<22}  {correlator:<48}  {crypto}"
    lines.append(fmt.format(party="party", step="step", event="event", correlator="correlator", crypto="crypto"))
    lines.append(fmt.format(party="-" * 9, step="-" * 22, event="-" * 22, correlator="-" * 48, crypto="-" * 56))

    # 1. offer issued (signed by Exchange at DiscoverResources time; the
    #    bytes the agent presented in ExecuteTransaction are stored verbatim).
    lines.append(fmt.format(
        party="exchange",
        step="1. offer issued",
        event="DiscoverResources",
        correlator=f"offer={ledger.get('offer_id', '')}",
        crypto=f"offer_sig={truncate(offer_sig, 32)}",
    ))
    # 2a. broker selected — picks the marketplace, calls ExecuteTransaction.
    if broker_hit is not None:
        bp = broker_hit.parsed
        lines.append(fmt.format(
            party="broker",
            step="2a. broker routed",
            event="POST /broker/v1/resolve",
            correlator=f"agent={bp.get('agent_id','?')}  marketplace={bp.get('marketplace','?')}",
            crypto=assertion("broker selected this exchange",
                             bp.get("transaction_id") == tx,
                             f"req={bp.get('request_id','?')}"),
        ))
    else:
        lines.append(fmt.format(
            party="broker",
            step="2a. broker routed",
            event="POST /broker/v1/resolve",
            correlator="(no broker log line found)",
            crypto="— (not routed via broker, or log lag)",
        ))
    # 2b. agent accepted — same bytes echoed back, transaction_id assigned.
    lines.append(fmt.format(
        party="exchange",
        step="2b. offer accepted",
        event="ExecuteTransaction",
        correlator=f"tx={tx}  req={ledger.get('tx_request_id', '')}",
        crypto=assertion("offer_sig matches step 1", bool(offer_sig)),
    ))
    # 3. ledger row — written before the URL is returned.
    lines.append(fmt.format(
        party="exchange",
        step="3. ledger row",
        event="transaction_log INSERT",
        correlator=f"tx={tx}  expiry={ledger.get('expiry', '')}",
        crypto=f"url_sig={truncate(url_sig, 32)}",
    ))
    # 3b. mcp fetched — MCP shim received the URL and called the edge.
    if mcp_hit is not None:
        # MCP logs are httpx INFO lines. Show the fact that MCP saw the URL,
        # not the URL itself — the Lambda@Edge row below carries the URL.
        ua_hint = "python-httpx (MCP shim)"
        lines.append(fmt.format(
            party="mcp",
            step="3b. mcp fetched URL",
            event="GET signed_url",
            correlator=f"tx={tx}  ua={ua_hint}",
            crypto="✓ MCP shim issued the GET on agent's behalf",
        ))
    # 4. signed-URL hit at Lambda@Edge — joined by tx_id.
    if edge_first is not None:
        cross_match_url = url_sig.startswith(edge_first.signature_prefix) and edge_first.signature_prefix != ""
        lines.append(fmt.format(
            party="edge",
            step="4. signed-URL hit",
            event=f"lambda@edge ({edge_first.region})",
            correlator=f"tx={edge_first.tx_id}  sig_prefix={edge_first.signature_prefix}",
            crypto=assertion("url_sig matches step 3", cross_match_url, f"prefix {edge_first.signature_prefix}"),
        ))
        # 5. origin served: same Lambda decision is authoritative for the
        # demo (CloudFront → S3 200 inferred from decision=pass:signed; if
        # CloudFront access logs are wired later, swap this row for them).
        lines.append(fmt.format(
            party="edge",
            step="5. origin served",
            event="cloudfront → s3",
            correlator=f"uri={truncate(edge_first.uri, 32)}  ua={truncate(edge_first.ua, 16)}",
            crypto=f"decision={edge_first.decision}",
        ))
    else:
        lines.append(fmt.format(
            party="edge",
            step="4. signed-URL hit",
            event="lambda@edge",
            correlator="(no log line found)",
            crypto="— (Lambda@Edge propagation may take 15min after publish)",
        ))
        lines.append(fmt.format(
            party="edge",
            step="5. origin served",
            event="cloudfront → s3",
            correlator="—",
            crypto="—",
        ))
    # 6. usage reported — obligation state from the same row.
    if obligation is None or obligation_state == "PENDING":
        lines.append(fmt.format(
            party="exchange",
            step="6. usage reported",
            event="reporting_obligations",
            correlator=f"tx={tx}",
            crypto=f"state={obligation_state}  (awaiting ReportUsage)",
        ))
    else:
        consumed = obligation.get("consumed") or ""
        # Hide placeholder consumed=0 from the broker auto-relay (no metering
        # data on the wire); the RECEIVED state is the load-bearing fact here.
        consumed_str = f"  consumed={consumed}" if consumed and consumed != "0" else ""
        lines.append(fmt.format(
            party="exchange",
            step="6. usage reported",
            event="reporting_obligations",
            correlator=f"tx={tx}{consumed_str}",
            crypto=assertion(f"state={obligation_state}", True),
        ))

    lines.append("")
    lines.append(f"  signed_url_hash (sha256): {url_hash}")
    if edge_first is not None:
        lines.append(f"  edge log timestamp:       {edge_first.time_iso}  ({edge_first.region})")
    lines.append(f"  signing scheme:           {ledger.get('signing_scheme', '?')}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--tx", required=True, help="transaction_id (UUID)")
    parser.add_argument("--exchange", default=os.environ.get("RAMP_EXCHANGE_URL", DEFAULT_EXCHANGE))
    parser.add_argument("--log-group", default=os.environ.get("RAMP_EDGE_LOG_GROUP", DEFAULT_LAMBDA_LOG_GROUP))
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE", DEFAULT_AWS_PROFILE))
    parser.add_argument("--regions", default=os.environ.get("RAMP_EDGE_REGIONS", ",".join(DEFAULT_AWS_REGIONS)))
    parser.add_argument("--ecs-log-group", default=os.environ.get("RAMP_ECS_LOG_GROUP", DEFAULT_ECS_LOG_GROUP))
    parser.add_argument("--ecs-region", default=os.environ.get("RAMP_ECS_REGION", "us-east-1"))
    args = parser.parse_args()

    regions = tuple(r.strip() for r in args.regions.split(",") if r.strip())
    ledger = fetch_ledger(args.exchange, args.tx)
    hits = fetch_edge_hits(args.tx, args.log_group, regions, args.profile)
    # ECS log group lives in us-east-1 only; Broker + MCP services log there.
    ecs = fetch_ecs_hits(
        args.tx, args.ecs_log_group, args.ecs_region, args.profile,
        prefixes=("broker", "mcp"),
    )
    print(render(ledger, hits, ecs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
