#!/usr/bin/env python3
"""Demo Web Bot Auth crawler — signs a GET under the RFC 9421 web-bot-auth profile.

The cryptographic mechanism is real and standards-compliant; only the crawler
*identity* is ours (a demo bot, not GPTBot). It signs the same signature base the
edge verifier (src/edge/src/wba.ts) reconstructs, declaring a purpose that is
covered by the signature (ADR-015 D2/D3). A signed `ai-index` request over a free
path is served the markdown rendition in one edge request and recorded.

Usage:
    scripts/wba-crawl.py <url> [--purpose ai-index] [--keyid bot-1]
                         [--key <pem>] [--agent <directory-url>]
                         [--emit-directory <path>] [--json] [--no-send]

Mirrors scripts/mint-signed-url.py: stdlib + `cryptography`, prints what a joiner
needs (req_id, sig_prefix) on stdout. Keys live under /tmp and are never committed.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlencode

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

DEFAULT_KEY_PATH = Path("/tmp/ramp-demo-keys/wba-ed25519-private.pem")
DEFAULT_PURPOSE = "ai-index"
DEFAULT_KEYID = "bot-1"
COVERED = ("@authority", "@path", "ramp-purpose")


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def load_or_generate_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{path} is not an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return key


def public_jwk(pub: Ed25519PublicKey, kid: str) -> dict[str, str]:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64url_nopad(raw), "alg": "EdDSA", "use": "sig"}


def signature_base(authority: str, path: str, purpose: str, params: str) -> str:
    # MUST match src/edge/src/wba.ts buildSignatureBase, component-for-component.
    values = {
        "@authority": authority.lower(),
        "@path": path,
        "ramp-purpose": purpose,
    }
    lines = [f'"{c}": {values[c]}' for c in COVERED]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines)


def build_signed_headers(
    key: Ed25519PrivateKey, authority: str, path: str, purpose: str, keyid: str, agent: str
) -> tuple[dict[str, str], str]:
    created = int(time.time())
    component_list = " ".join(f'"{c}"' for c in COVERED)
    params = (
        f"({component_list});created={created};keyid=\"{keyid}\";alg=\"ed25519\";tag=\"web-bot-auth\""
    )
    base = signature_base(authority, path, purpose, params)
    sig = key.sign(base.encode())
    sig_b64 = base64.b64encode(sig).decode()  # RFC 9421 sf-binary (standard base64)
    headers = {
        "RAMP-Purpose": purpose,
        "Signature-Input": f"sig1={params}",
        "Signature": f"sig1=:{sig_b64}:",
        "Signature-Agent": agent,
    }
    return headers, sig_b64[:16]


def send(url: str, headers: dict[str, str]) -> tuple[int, int]:
    req = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - demo client, fixed scheme
            body = resp.read()
            return resp.status, len(body)
    except urllib.error.HTTPError as e:
        return e.code, 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("url", help="target URL (the free-content path to index)")
    p.add_argument("--purpose", default=DEFAULT_PURPOSE, help="AIPREF purpose token")
    p.add_argument("--keyid", default=DEFAULT_KEYID)
    p.add_argument("--key", type=Path, default=DEFAULT_KEY_PATH)
    p.add_argument("--agent", default="", help="Signature-Agent directory URL")
    p.add_argument("--emit-directory", type=Path, help="write the JWK directory JSON here")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument("--no-send", action="store_true", help="compute + print only; no HTTP request")
    args = p.parse_args()

    key = load_or_generate_key(args.key)
    jwk = public_jwk(key.public_key(), args.keyid)
    directory = {"keys": [jwk]}
    if args.emit_directory:
        args.emit_directory.parent.mkdir(parents=True, exist_ok=True)
        args.emit_directory.write_text(json.dumps(directory, indent=2))

    # Append a joinable req_id so the edge decision log (and ledger.py --req) can
    # correlate this exact request.
    req_id = str(uuid.uuid4())
    parsed = urlparse(args.url)
    sep = "&" if parsed.query else "?"
    url = f"{args.url}{sep}{urlencode({'req_id': req_id})}"

    # RFC 9421 @path covers the path only — NOT the query. The edge verifies
    # @path against request.uri (CloudFront) / url.pathname (Hono), both
    # query-free, so the req_id rides the URL on the wire but stays out of the
    # signature base.
    headers, sig_prefix = build_signed_headers(
        key, parsed.netloc, parsed.path, args.purpose, args.keyid, args.agent
    )

    status = None
    bytes_sent = 0
    if not args.no_send:
        status, bytes_sent = send(url, headers)

    if args.json:
        print(
            json.dumps(
                {
                    "req_id": req_id,
                    "sig_prefix": sig_prefix,
                    "purpose": args.purpose,
                    "keyid": args.keyid,
                    "url": url,
                    "authority": parsed.netloc,
                    "path": parsed.path,
                    "headers": headers,
                    "jwk": jwk,
                    "status": status,
                    "bytes": bytes_sent,
                },
                indent=2,
            )
        )
    else:
        print(f"req_id={req_id}")
        print(f"sig_prefix={sig_prefix}")
        print(f"purpose={args.purpose} keyid={args.keyid}")
        if status is not None:
            served = "one-request serve" if status == 200 else "not served"
            print(f"GET {url} -> {status} ({bytes_sent} bytes) [{served}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
