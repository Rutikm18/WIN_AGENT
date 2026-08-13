"""Microsoft-Windows-DNS-Client query/response ETW consumer."""
from __future__ import annotations

from .process_provider import _integer
from .session import PyWinTraceSession

PROVIDER_NAME = "Microsoft-Windows-DNS-Client"
PROVIDER_GUID = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"
DNS_EVENT_IDS = (3006, 3008, 3009, 3010)
_EVENT_NAMES = {
    3006: "query",
    3008: "complete",
    3009: "network_query",
    3010: "sent",
}


def _filetime(value) -> int | None:
    integer = _integer(value)
    if integer is None:
        return None
    timestamp = (integer - 116444736000000000) // 10_000_000
    return timestamp if timestamp >= 0 else None


def parse_dns_event(raw) -> dict | None:
    if not isinstance(raw, (tuple, list)) or len(raw) != 2:
        return None
    event_id, data = raw
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        return None
    if event_id not in DNS_EVENT_IDS or not isinstance(data, dict):
        return None
    header = data.get("EventHeader") if isinstance(data.get("EventHeader"), dict) else {}
    pid = _integer(data.get("ClientPID"))
    if pid is None:
        pid = _integer(header.get("ProcessId"))
    return {
        "event": _EVENT_NAMES[event_id],
        "event_id": event_id,
        "timestamp": _filetime(header.get("TimeStamp")),
        "query_name": str(data.get("QueryName") or "") or None,
        "query_type": _integer(data.get("QueryType")),
        "status": _integer(data.get("QueryStatus")),
        "results": str(data.get("QueryResults") or "") or None,
        "pid": pid,
        "dns_server": str(
            data.get("DnsServerIpAddress") or data.get("DNSServerAddress") or ""
        ) or None,
        "interface": str(data.get("AdapterName") or "") or None,
        "interface_index": _integer(data.get("InterfaceIndex")),
    }


class DnsEtwProvider:
    def __init__(self, *, capacity: int = 4096, backend=None) -> None:
        self._session = PyWinTraceSession(
            provider_name=PROVIDER_NAME,
            provider_guid=PROVIDER_GUID,
            parser=parse_dns_event,
            event_ids=DNS_EVENT_IDS,
            capacity=capacity,
            backend=backend,
            session_prefix="AttackLens-DNS",
        )

    def start(self) -> bool:
        return self._session.start()

    def stop(self) -> None:
        self._session.stop()

    def drain(self, limit: int = 256) -> list[dict]:
        return self._session.drain(limit)

    def health_snapshot(self) -> dict:
        return self._session.health_snapshot()
