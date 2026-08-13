"""Lifecycle-safe pywintrace adapter with bounded memory and health reporting."""
from __future__ import annotations

from collections import deque
import logging
import threading
import uuid

log = logging.getLogger("agent.windows.etw")


class EventBuffer:
    def __init__(self, capacity: int = 4096) -> None:
        self._events: deque[dict] = deque(maxlen=max(1, int(capacity)))
        self._lock = threading.Lock()
        self.received = 0
        self.dropped = 0

    def append(self, event: dict) -> None:
        with self._lock:
            if len(self._events) == self._events.maxlen:
                self.dropped += 1
            self._events.append(event)
            self.received += 1

    def drain(self, limit: int = 256) -> list[dict]:
        result: list[dict] = []
        with self._lock:
            for _ in range(min(max(0, int(limit)), len(self._events))):
                result.append(self._events.popleft())
        return result

    def stats(self) -> dict:
        with self._lock:
            return {
                "received": self.received,
                "dropped": self.dropped,
                "buffered": len(self._events),
                "capacity": self._events.maxlen,
            }


class PyWinTraceSession:
    """One provider per session; start/stop are idempotent and non-fatal."""

    def __init__(
        self,
        *,
        provider_name: str,
        provider_guid: str,
        parser,
        any_keywords: int | None = None,
        event_ids: tuple[int, ...] | None = None,
        capacity: int = 4096,
        backend=None,
        session_prefix: str = "AttackLens",
    ) -> None:
        self.provider_name = provider_name
        self.provider_guid = provider_guid
        self.any_keywords = any_keywords
        self.event_ids = tuple(event_ids or ())
        self.parser = parser
        self.buffer = EventBuffer(capacity)
        self._backend = backend
        self._trace = None
        self._lock = threading.Lock()
        self._running = False
        self._available = None
        self._last_error: str | None = None
        self._session_prefix = session_prefix

    def _callback(self, raw) -> None:
        try:
            parsed = self.parser(raw)
            if parsed is not None:
                self.buffer.append(parsed)
        except Exception as exc:
            # Callback failures must never tear down the native consumer.
            self._last_error = f"callback: {type(exc).__name__}: {exc}"

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return True
            try:
                backend = self._backend
                if backend is None:
                    import etw as backend  # pywintrace package
                provider = backend.ProviderInfo(
                    self.provider_name,
                    backend.GUID(self.provider_guid),
                    any_keywords=self.any_keywords,
                )
                trace = backend.ETW(
                    session_name=f"{self._session_prefix}-{uuid.uuid4().hex}",
                    providers=[provider],
                    event_callback=self._callback,
                    event_id_filters=list(self.event_ids),
                    ignore_exists_error=False,
                )
                trace.start()
                self._trace = trace
                self._running = True
                self._available = True
                self._last_error = None
                return True
            except Exception as exc:
                self._trace = None
                self._running = False
                self._available = False
                self._last_error = f"{type(exc).__name__}: {exc}"
                log.warning(
                    "ETW provider unavailable provider=%s error=%s",
                    self.provider_name,
                    self._last_error,
                )
                return False

    def stop(self) -> None:
        with self._lock:
            trace = self._trace
            self._trace = None
            self._running = False
        if trace is not None:
            try:
                trace.stop()
            except Exception as exc:
                self._last_error = f"stop: {type(exc).__name__}: {exc}"
                log.warning(
                    "ETW provider stop failed provider=%s error=%s",
                    self.provider_name,
                    self._last_error,
                )

    def drain(self, limit: int = 256) -> list[dict]:
        return self.buffer.drain(limit)

    def health_snapshot(self) -> dict:
        result = self.buffer.stats()
        result.update({
            "provider": self.provider_name,
            "available": self._available,
            "running": self._running,
            "last_error": self._last_error,
        })
        return result
