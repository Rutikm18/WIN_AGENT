"""EvtSubscribe wrapper with bounded buffering and per-event bookmarks."""
from __future__ import annotations

from collections import deque
import logging
from pathlib import Path
import threading
import time

log = logging.getLogger("agent.windows.evtlog.subscription")


class ChannelSubscription:
    def __init__(
        self,
        *,
        channel: str,
        event_ids: tuple[int, ...],
        bookmark_path: Path,
        parser,
        capacity: int = 4096,
        backend=None,
        lookback_ms: int = 86_400_000,
    ) -> None:
        self.channel = channel
        self.event_ids = event_ids
        self.bookmark_path = Path(bookmark_path)
        self.parser = parser
        self.capacity = max(1, int(capacity))
        self._backend = backend
        self.lookback_ms = max(0, int(lookback_ms))
        self._handle = None
        self._bookmark_handle = None
        self._callback_ref = self._callback
        self._events: deque[tuple[dict, str]] = deque()
        self._lock = threading.Lock()
        self._running = False
        self._available = None
        self._paused = False
        self._received = 0
        self._parse_errors = 0
        self._overflow_events = 0
        self._last_error: str | None = None
        self._last_event_at: int | None = None

    def _api(self):
        if self._backend is not None:
            return self._backend
        import win32evtlog
        return win32evtlog

    def start(self) -> bool:
        self.stop()
        api = self._api()
        bookmark_xml = None
        try:
            if self.bookmark_path.exists():
                bookmark_xml = self.bookmark_path.read_text(encoding="utf-8")
            bookmark = api.EvtCreateBookmark(bookmark_xml) if bookmark_xml else None
            ids = " or ".join(f"EventID={event_id}" for event_id in self.event_ids)
            query = f"*[System[({ids})]]"
            flags = (
                api.EvtSubscribeStartAfterBookmark
                if bookmark_xml else api.EvtSubscribeToFutureEvents
            )
            # Use keyword arguments here.  pywin32's positional wrapper does
            # not follow the native Win32 parameter order and, critically,
            # can bind the bookmark as the wrong optional argument.  Fresh
            # subscriptions appeared to work because that value was None,
            # while resume failed with ERROR_INVALID_PARAMETER (87).
            handle = api.EvtSubscribe(
                ChannelPath=self.channel,
                Flags=flags,
                SignalEvent=None,
                Callback=self._callback_ref,
                Context=self.channel,
                Query=query,
                Bookmark=bookmark,
            )
            self._bookmark_handle = bookmark
            self._handle = handle
            self._running = True
            self._available = True
            self._paused = False
            self._last_error = None
            return True
        except Exception as exc:
            self._available = False
            self._running = False
            self._last_error = f"{type(exc).__name__}: {exc}"
            self._close(api, self._bookmark_handle)
            self._bookmark_handle = None
            return False

    def stop(self) -> None:
        handle, bookmark = self._handle, self._bookmark_handle
        self._handle = self._bookmark_handle = None
        self._running = False
        if handle is None and bookmark is None:
            return
        try:
            api = self._api()
        except Exception:
            return
        self._close(api, handle)
        self._close(api, bookmark)

    @staticmethod
    def _close(api, handle) -> None:
        if handle is not None:
            try:
                close = getattr(handle, "Close", None) or getattr(handle, "close", None)
                if close is not None:
                    close()
                else:
                    # Test doubles and alternate backends may expose the
                    # native-style helper even though pywin32 itself does not.
                    api.EvtClose(handle)
            except Exception:
                pass

    def _callback(self, action, context, event_handle):
        del context
        api = self._api()
        if action == api.EvtSubscribeActionError:
            self._last_error = f"subscription_error: {event_handle}"
            return 0
        if action != api.EvtSubscribeActionDeliver:
            return 0
        with self._lock:
            if self._paused:
                self._overflow_events += 1
                return 0
            if len(self._events) >= self.capacity:
                # Stop accepting later events. Restarting from the last durable
                # bookmark replays every ignored record after the queue drains.
                self._paused = True
                self._overflow_events += 1
                return 0
        try:
            xml = api.EvtRender(event_handle, api.EvtRenderEventXml)
            record = self.parser(xml, self.channel)
            if record is None:
                self._parse_errors += 1
                return 0
            bookmark = api.EvtCreateBookmark(None)
            try:
                api.EvtUpdateBookmark(bookmark, event_handle)
                bookmark_xml = api.EvtRender(bookmark, api.EvtRenderBookmark)
            finally:
                self._close(api, bookmark)
            with self._lock:
                if self._paused or len(self._events) >= self.capacity:
                    self._paused = True
                    self._overflow_events += 1
                else:
                    self._events.append((record, bookmark_xml))
                    self._received += 1
                    self._last_event_at = int(time.time())
        except Exception as exc:
            self._parse_errors += 1
            self._last_error = f"callback: {type(exc).__name__}: {exc}"
        return 0

    def drain(self, limit: int) -> list[tuple[dict, str]]:
        result: list[tuple[dict, str]] = []
        with self._lock:
            for _ in range(min(max(0, int(limit)), len(self._events))):
                result.append(self._events.popleft())
        return result

    def restart_from_committed(self) -> bool:
        with self._lock:
            self._events.clear()
            self._paused = False
        return self.start()

    @property
    def paused(self) -> bool:
        with self._lock:
            return self._paused

    def health_snapshot(self) -> dict:
        with self._lock:
            return {
                "available": self._available,
                "running": self._running,
                "paused": self._paused,
                "buffered": len(self._events),
                "capacity": self.capacity,
                "received": self._received,
                "overflow_events": self._overflow_events,
                "parse_errors": self._parse_errors,
                "last_event_at": self._last_event_at,
                "last_error": self._last_error,
            }
