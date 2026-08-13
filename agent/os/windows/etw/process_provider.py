"""Microsoft-Windows-Kernel-Process start/stop ETW consumer."""
from __future__ import annotations

from datetime import datetime
import ntpath
import re

from .session import PyWinTraceSession

PROVIDER_NAME = "Microsoft-Windows-Kernel-Process"
PROVIDER_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
PROCESS_KEYWORD = 0x10

_FORMAT_CHARS = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_INTEGRITY = {
    0x1000: "low",
    0x2000: "medium",
    0x3000: "high",
    0x4000: "system",
    0x5000: "protected",
}


def _integer(value) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _timestamp(value) -> int | None:
    if not value:
        return None
    try:
        cleaned = _FORMAT_CHARS.sub("", str(value)).replace("Z", "+00:00")
        return int(datetime.fromisoformat(cleaned).timestamp())
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _integrity_level(value) -> str | None:
    try:
        rid = int(str(value).rsplit("-", 1)[-1])
    except (TypeError, ValueError):
        return None
    return _INTEGRITY.get(rid, "unknown")


def parse_process_event(raw) -> dict | None:
    if not isinstance(raw, (tuple, list)) or len(raw) != 2:
        return None
    event_id, data = raw
    if not isinstance(data, dict) or int(event_id) not in (1, 2):
        return None
    started = int(event_id) == 1
    image_path = str(data.get("ImageName") or "") or None
    name = ntpath.basename(image_path or "") or None
    return {
        "event": "start" if started else "stop",
        "pid": _integer(data.get("ProcessID")),
        "ppid": _integer(data.get("ParentProcessID")) if started else None,
        "name": name,
        "image_path": image_path,
        "started_at": _timestamp(data.get("CreateTime")),
        "event_at": _timestamp(data.get("CreateTime") if started else data.get("ExitTime")),
        "integrity_level": _integrity_level(data.get("MandatoryLabel")),
        "elevated": (_integer(data.get("ProcessTokenIsElevated")) == 1) if started else None,
        "sequence": _integer(data.get("ProcessSequenceNumber")),
        "session_id": _integer(data.get("SessionID")),
        "exit_code": _integer(data.get("ExitCode")) if not started else None,
    }


class ProcessEtwProvider:
    def __init__(self, *, capacity: int = 4096, backend=None) -> None:
        self._session = PyWinTraceSession(
            provider_name=PROVIDER_NAME,
            provider_guid=PROVIDER_GUID,
            parser=parse_process_event,
            any_keywords=PROCESS_KEYWORD,
            event_ids=(1, 2),
            capacity=capacity,
            backend=backend,
            session_prefix="AttackLens-Process",
        )

    def start(self) -> bool:
        return self._session.start()

    def stop(self) -> None:
        self._session.stop()

    def drain(self, limit: int = 256) -> list[dict]:
        return self._session.drain(limit)

    def health_snapshot(self) -> dict:
        return self._session.health_snapshot()
