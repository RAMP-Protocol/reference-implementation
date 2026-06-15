#!/usr/bin/env python3
"""Free-index ledger mode — the 2-row counterpart to the paid 6-row chain.

A WBA free-index serve has no transaction: no offer, no signed URL, no
ReportUsage. The evidence is the bot's signed request + the edge's recorded
serve, joined by req_id (not tx_id). This module renders that 2-row chain and a
side-by-side comparison with the paid chain — the collapse that is the demo.

Imported by ledger.py; reuses its fetch/format helpers. Stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FreeHit:
    """A Lambda@Edge `pass:free-index` log line, joined by req_id."""

    region: str
    timestamp_ms: int
    req_id: str
    purpose: str
    bot_kid: str
    signature_agent: str
    sig_prefix: str
    license_id: str
    content_hash: str
    uri: str
    rendition: str

    @property
    def time_iso(self) -> str:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc).isoformat(
            timespec="seconds"
        )


def _row_to_hit(region: str, timestamp_ms: int, row: dict[str, Any]) -> FreeHit:
    return FreeHit(
        region=region,
        timestamp_ms=timestamp_ms,
        req_id=row.get("req_id", ""),
        purpose=row.get("purpose", ""),
        bot_kid=row.get("bot_kid", ""),
        signature_agent=row.get("signature_agent", ""),
        sig_prefix=row.get("sig_prefix", ""),
        license_id=row.get("license_id", ""),
        content_hash=row.get("content_hash", ""),
        uri=row.get("uri", ""),
        rendition=row.get("rendition", ""),
    )


def fetch_free_hits_from_fixture(path: str, req_id: str) -> list[FreeHit]:
    """Read free-index hits from a local newline-delimited log fixture (offline)."""
    hits: list[FreeHit] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            idx = line.find("{")
            if idx < 0:
                continue
            try:
                row = json.loads(line[idx:])
            except json.JSONDecodeError:
                continue
            if row.get("decision") != "pass:free-index" or row.get("req_id") != req_id:
                continue
            hits.append(_row_to_hit("fixture", 0, row))
    return hits


def fetch_free_hits(
    req_id: str, log_group: str, regions: tuple[str, ...], profile: str
) -> list[FreeHit]:
    """Filter Lambda@Edge logs across regions for the pass:free-index line by req_id."""
    hits: list[FreeHit] = []
    start_ms = int((time.time() - 30 * 60) * 1000)
    for region in regions:
        cmd = [
            "aws", "--profile", profile, "--region", region,
            "logs", "filter-log-events",
            "--log-group-name", log_group,
            "--filter-pattern", f'"{req_id}"',
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
            if "ResourceNotFoundException" not in res.stderr:
                sys.stderr.write(f"ledger: {region} aws-logs error: {res.stderr.strip()}\n")
            continue
        try:
            payload = json.loads(res.stdout)
        except json.JSONDecodeError:
            continue
        for ev in payload.get("events", []):
            msg = ev.get("message", "")
            idx = msg.find("{")
            if idx < 0:
                continue
            try:
                row = json.loads(msg[idx:])
            except json.JSONDecodeError:
                continue
            if row.get("decision") != "pass:free-index" or row.get("req_id") != req_id:
                continue
            hits.append(_row_to_hit(region, ev.get("timestamp", 0), row))
    hits.sort(key=lambda h: h.timestamp_ms)
    return hits


def load_bot_directory(src: str | None) -> dict[str, dict[str, Any]]:
    """Load the bot's JWK directory (URL or file) → {kid: jwk}. Empty on failure."""
    if not src:
        return {}
    try:
        if src.startswith("http://") or src.startswith("https://"):
            with urllib.request.urlopen(src, timeout=10) as resp:  # noqa: S310 - operator-supplied
                doc = json.loads(resp.read())
        else:
            with open(src, encoding="utf-8") as fh:
                doc = json.load(fh)
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        sys.stderr.write(f"ledger: could not load bot directory {src!r}: {e}\n")
        return {}
    return {k.get("kid", ""): k for k in doc.get("keys", [])}


def render_free(hits: list[FreeHit], bot_dir: dict[str, dict[str, Any]], assertion) -> str:
    """Render the 2-row free-index chain + the bot-identity cross-assertion."""
    lines: list[str] = []
    if not hits:
        return "  (no pass:free-index log line found for that req_id)"
    hit = hits[0]
    lines.append(f"$ ledger.py --free --req {hit.req_id}")
    lines.append("")
    fmt = "  {party:<7}  {step:<26}  {detail:<48}  {crypto}"
    lines.append(fmt.format(party="party", step="step", detail="detail", crypto="crypto"))
    lines.append(fmt.format(party="-" * 7, step="-" * 26, detail="-" * 48, crypto="-" * 40))

    # 1. bot signed intent — purpose covered by the signature (D3).
    lines.append(fmt.format(
        party="bot",
        step="1. signed intent",
        detail=f"X-Intended-Use={hit.purpose}  (covers @authority @path x-intended-use)",
        crypto=f"sig_prefix={hit.sig_prefix}",
    ))
    # 2. edge served + recorded — one request, signed access record (D8).
    key_known = hit.bot_kid in bot_dir if bot_dir else None
    if key_known is None:
        crypto = f"kid={hit.bot_kid} (pass --bot-jwks to re-verify identity)"
    else:
        crypto = assertion(
            f"bot key kid={hit.bot_kid} in published directory",
            key_known,
            "signed this intent" if key_known else "kid NOT in directory",
        )
    lines.append(fmt.format(
        party="edge",
        step="2. served + recorded",
        detail=f"decision=pass:free-index  license={hit.license_id}",
        crypto=crypto,
    ))

    lines.append("")
    served = hit.rendition or hit.uri
    lines.append(f"  served:        {served}  (one request, no Exchange round-trip)")
    if hit.content_hash:
        lines.append(f"  content_hash:  {hit.content_hash}")
    if hit.region != "fixture":
        lines.append(f"  edge log:      {hit.time_iso}  ({hit.region})")
    lines.append("  evidence:      the signed request IS the record (ADR-015 D8)")
    return "\n".join(lines)


# Canonical paid-chain step labels (the 6-row full RAMP cycle), for the compare
# view. The detailed per-field paid render stays in ledger.render().
_PAID_STEPS = [
    ("exchange", "1. offer issued"),
    ("broker", "2a. broker routed"),
    ("exchange", "2b. offer accepted"),
    ("exchange", "3. ledger row"),
    ("edge", "4. signed-URL hit"),
    ("edge", "5. origin served"),
    ("exchange", "6. usage reported"),
]


def render_compare(free_hits: list[FreeHit], tx_id: str) -> str:
    """Side-by-side: the paid 6-row cycle beside the free 2-row chain (the money shot)."""
    free_rows: list[tuple[str, str]] = []
    if free_hits:
        h = free_hits[0]
        free_rows = [
            ("bot", f"1. signed intent  purpose={h.purpose}"),
            ("edge", "2. served + recorded  pass:free-index"),
        ]
    else:
        free_rows = [("bot", "1. signed intent"), ("edge", "2. served + recorded")]

    left = [f"{p:<9} {s}" for p, s in _PAID_STEPS]
    right = [f"{p:<6} {s}" for p, s in free_rows]
    width = max(len(x) for x in left) + 3

    out: list[str] = []
    out.append(f"  {'PAID — grounding (ai-input)':<{width}}FREE-INDEX (ai-index)")
    out.append(f"  {('TX=' + tx_id):<{width}}REQ join, no transaction")
    out.append(f"  {'-' * (width - 2):<{width}}{'-' * 38}")
    for i in range(max(len(left), len(right))):
        lcol = left[i] if i < len(left) else ""
        rcol = right[i] if i < len(right) else ""
        out.append(f"  {lcol:<{width}}{rcol}")
    out.append("")
    out.append(f"  {'6-step full RAMP cycle':<{width}}2 rows, edge-only, still cryptographically attributable")
    return "\n".join(out)
