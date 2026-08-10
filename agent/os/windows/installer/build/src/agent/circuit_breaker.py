"""
agent/agent/circuit_breaker.py — Per-section circuit breaker.

States:
  CLOSED   — section is healthy, runs normally
  OPEN     — too many failures, section is skipped until cooldown expires
  HALF     — cooldown expired, next run is a probe; success → CLOSED, fail → OPEN

Config (all have defaults):
  fail_threshold   int   failures before opening   (default: 3)
  success_to_close int   consecutive successes needed to close from HALF (default: 1)
  cooldown_sec     int   how long to wait in OPEN before going HALF (default: 60)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Literal

log = logging.getLogger("agent.circuit_breaker")

State = Literal["CLOSED", "OPEN", "HALF"]


@dataclass
class _Breaker:
    name: str
    fail_threshold: int   = 3
    cooldown_sec: int     = 60
    success_to_close: int = 1

    state: State          = "CLOSED"
    failures: int         = 0
    successes: int        = 0
    opened_at: float      = 0.0
    last_result: str      = "—"

    def record_success(self) -> None:
        if self.state == "HALF":
            self.successes += 1
            if self.successes >= self.success_to_close:
                log.info("[%s] circuit CLOSED after recovery", self.name)
                self._reset()
        elif self.state == "CLOSED":
            self.failures = 0
        self.last_result = "ok"

    def record_failure(self, reason: str = "") -> None:
        self.failures += 1
        self.last_result = reason[:80] if reason else "error"
        if self.state == "CLOSED" and self.failures >= self.fail_threshold:
            log.warning(
                "[%s] circuit OPEN after %d failures — skipping for %ds",
                self.name, self.failures, self.cooldown_sec,
            )
            self.state     = "OPEN"
            self.opened_at = time.time()
        elif self.state == "HALF":
            log.debug("[%s] probe failed — back to OPEN", self.name)
            self.state     = "OPEN"
            self.opened_at = time.time()
            self.successes = 0

    def allow(self) -> bool:
        """Return True if this section should run now."""
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.opened_at >= self.cooldown_sec:
                log.debug("[%s] circuit HALF — probing", self.name)
                self.state    = "HALF"
                self.successes = 0
                return True
            return False
        # HALF: allow one probe
        return True

    def _reset(self) -> None:
        self.state    = "CLOSED"
        self.failures = 0
        self.successes = 0
        self.opened_at = 0.0

    @property
    def is_healthy(self) -> bool:
        return self.state == "CLOSED"


class CircuitBreakerRegistry:
    """Thread-safe registry of per-section circuit breakers."""

    def __init__(
        self,
        fail_threshold: int = 3,
        cooldown_sec: int   = 60,
    ):
        self._default_fail  = fail_threshold
        self._default_cool  = cooldown_sec
        self._breakers: dict[str, _Breaker] = {}
        import threading
        self._lock = threading.Lock()

    def _get(self, section: str) -> _Breaker:
        if section not in self._breakers:
            self._breakers[section] = _Breaker(
                name=section,
                fail_threshold=self._default_fail,
                cooldown_sec=self._default_cool,
            )
        return self._breakers[section]

    def allow(self, section: str) -> bool:
        with self._lock:
            return self._get(section).allow()

    def success(self, section: str) -> None:
        with self._lock:
            self._get(section).record_success()

    def failure(self, section: str, reason: str = "") -> None:
        with self._lock:
            self._get(section).record_failure(reason)

    def snapshot(self) -> dict:
        """Return a status snapshot (for the health section)."""
        with self._lock:
            return {
                name: {
                    "state":       b.state,
                    "failures":    b.failures,
                    "last_result": b.last_result,
                }
                for name, b in self._breakers.items()
            }
