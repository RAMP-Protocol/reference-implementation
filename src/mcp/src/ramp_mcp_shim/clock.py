"""Clock port for the MCP shim — realises ADR-008 D1 (Python side).

Production policy code MUST consult time through the :class:`Clock`
Protocol rather than calling ``datetime.now`` / ``datetime.utcnow`` /
``time.time`` / ``time.monotonic`` directly. The ruff configuration
under ``src/mcp/pyproject.toml`` bans those primitives inside
``src/mcp/src/ramp_mcp_shim/`` — this module and a small allowlist of
leaves (the production root that constructs the system clock,
observability shims, log formatters) are the only places allowed to
reference the wall clock.

Tests construct :class:`DeterministicClock` and advance it explicitly
so behaviour-gating windows (e.g. RFC 9421 signature ``created``
freshness) are exercised without sleeping.
"""

from __future__ import annotations

import threading
import time as _time_module
from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    """Narrow time port consumed by every behaviour-gating call site.

    Implementations MUST return UTC ``datetime`` instances from :meth:`now`
    and a monotonically non-decreasing float from :meth:`monotonic`. The
    monotonic clock is used for bounded retry / backoff windows where
    wall-clock skew would corrupt the loop.
    """

    def now(self) -> datetime:
        """Return the current instant in UTC."""

    def monotonic(self) -> float:
        """Return a monotonic float reading suitable for elapsed-time math."""


class SystemClock:
    """Production implementation backed by the standard library wall clock.

    This is one of the few sites permitted to call ``datetime.now`` and
    ``time.monotonic`` directly — the ruff allowlist exempts this module.
    """

    def now(self) -> datetime:
        """Return the current UTC instant."""
        return datetime.now(tz=UTC)  # noqa: DTZ005, RUF100 — sole production allowlist

    def monotonic(self) -> float:
        """Delegate to ``time.monotonic``."""
        return _time_module.monotonic()


class DeterministicClock:
    """Test-side implementation. The instant is fixed at construction and
    only advances when the test calls :meth:`advance` or :meth:`set_now`.

    Concurrent reads are safe; concurrent advance from multiple threads is
    serialised by the embedded lock.
    """

    def __init__(self, start: datetime, monotonic_start: float = 0.0) -> None:
        if start.tzinfo is None:
            msg = "DeterministicClock start must be timezone-aware"
            raise ValueError(msg)
        self._lock = threading.Lock()
        self._now = start.astimezone(UTC)
        self._mono = float(monotonic_start)

    def now(self) -> datetime:
        """Return the clock's current UTC instant."""
        with self._lock:
            return self._now

    def monotonic(self) -> float:
        """Return the deterministic monotonic counter."""
        with self._lock:
            return self._mono

    def advance(self, delta: timedelta) -> None:
        """Move the clock forward by ``delta``.

        Negative deltas are clamped to zero so accidental rewinds cannot
        silently break window invariants.
        """
        seconds = max(0.0, delta.total_seconds())
        with self._lock:
            self._now = self._now + timedelta(seconds=seconds)
            self._mono = self._mono + seconds

    def set_now(self, instant: datetime) -> None:
        """Pin the clock to ``instant`` (UTC)."""
        if instant.tzinfo is None:
            msg = "set_now requires timezone-aware datetime"
            raise ValueError(msg)
        with self._lock:
            self._now = instant.astimezone(UTC)


def system_clock() -> Clock:
    """Return the canonical production clock.

    Wiring code that needs a :class:`Clock` for the production path uses
    this factory rather than constructing :class:`SystemClock` inline so
    every wiring site reads the same way and the lint allowlist stays
    narrow to this one module.
    """
    return SystemClock()
