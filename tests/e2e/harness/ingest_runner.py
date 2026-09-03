"""Running the production catalog-ingest binary, and reading its verdict.

The flag set and the success condition were written twice — once in the seed
path, once in the demo proof — and this branch had to add ``--exchange`` to both.
That is the cost of the copy, paid every time the binary's contract moves.

The binary signs (RFC 9421) and sends the feed as ``PushResources`` RPCs — one
per submission of at most the wire bound on ``entries``; every feed this harness
ingests fits in one — and that is the only catalog write here. The exit code is
the whole verdict: the Exchange stores or refuses a submission whole, the binary
exits non-zero on the first refusal, and its stderr summary
(``push: accepted=N warnings=M``) counts what was stored rather than carrying a
second signal a caller has to read.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# One ingest is a handful of RPCs at most over a signed connection; five minutes
# is the wall a hung stack hits rather than a duration any real run approaches.
_TIMEOUT_SECONDS = 300


def run_ingest(
    *,
    argv_prefix: list[str],
    exchange_url: str,
    exchange: str,
    tenant_id: str,
    key_path: Path,
    feed: Path,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Ingest one feed and return the finished process.

    ``argv_prefix`` is how the binary is reached — a built binary's path, or
    ``go run ./src/exchange/cmd/ramp-ingest`` — and is the only thing the two
    callers differ in.

    ``exchange`` is who the push is addressed to. It overrides the recipient the
    binary would otherwise take from ``exchange_url``'s host, which the harness
    needs because a host run reaches the exchange through a mapped 127.0.0.1
    port that names no exchange at all. A deployment dialling the exchange's own
    origin can pass the same value it dials.
    """
    return subprocess.run(  # noqa: S603 — argv list, no shell, all values harness-local
        [
            *argv_prefix,
            "--exchange-url",
            exchange_url,
            "--exchange",
            exchange,
            "--tenant",
            tenant_id,
            "--key",
            str(key_path),
            str(feed),
        ],
        cwd=None if cwd is None else str(cwd),
        capture_output=True,
        text=True,
        check=False,
        timeout=_TIMEOUT_SECONDS,
    )


def ingest_succeeded(proc: subprocess.CompletedProcess[str]) -> bool:
    """Whether every submission was stored.

    The binary exits non-zero on the first submission that did not store,
    whether the Exchange refused it or never answered at all, so a zero exit is
    the only result that means the whole feed landed.
    """
    return proc.returncode == 0


__all__ = ["ingest_succeeded", "run_ingest"]
