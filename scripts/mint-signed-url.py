#!/usr/bin/env python3
"""Mint a CloudFront canned-policy signed URL for a ramp-demo resource.

Usage:
    scripts/mint-signed-url.py <uri> [--ttl=<seconds>] [--key=<pem>]

Reads the RSA private key from /tmp/ramp-demo-keys/rsa-private.pem by default
(where scripts/rotate-keys.sh generate puts it) and uses the CloudFront
key-pair ID from the `pi-terraform` aws-ramp-demo-cloudfront output.

Prints the signed URL on stdout; nothing else.
"""
from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DEFAULT_KEY_PATH = Path("/tmp/ramp-demo-keys/rsa-private.pem")
DEFAULT_KEY_PAIR_ID = "<CLOUDFRONT_KEY_PAIR_ID>"
DEFAULT_TTL_SECONDS = 3600


def mint(uri: str, key_path: Path, key_pair_id: str, ttl_seconds: int) -> str:
    expires = int(time.time()) + ttl_seconds
    policy = (
        '{"Statement":[{"Resource":"' + uri
        + '","Condition":{"DateLessThan":{"AWS:EpochTime":' + str(expires) + "}}}]}"
    )
    key = load_pem_private_key(key_path.read_bytes(), password=None)
    sig = key.sign(policy.encode(), padding.PKCS1v15(), hashes.SHA1())  # noqa: S303 - CF canned policy is SHA1
    sig_cf = base64.b64encode(sig).decode().translate(str.maketrans({"+": "-", "=": "_", "/": "~"}))
    return f"{uri}?Expires={expires}&Signature={sig_cf}&Key-Pair-Id={key_pair_id}"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("uri")
    p.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS, help="seconds until Expires (default: 3600)")
    p.add_argument("--key", type=Path, default=DEFAULT_KEY_PATH)
    p.add_argument("--key-pair-id", default=DEFAULT_KEY_PAIR_ID)
    args = p.parse_args()
    print(mint(args.uri, args.key, args.key_pair_id, args.ttl))
    return 0


if __name__ == "__main__":
    sys.exit(main())
