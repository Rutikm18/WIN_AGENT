"""
agent/os/windows/collectors/eventlog.py — Windows Security Event Log monitor.

section name: "eventlog"
interval:     300 s (collected every 5 min; events cover the past 24 hours)

There is no macOS equivalent of this section — the Windows Security Event Log
is the canonical audit trail for authentication, process creation, service
installation, and scheduled task manipulation.  These events map directly to
MITRE ATT&CK techniques and are the highest-signal data for detecting lateral
movement, persistence, and privilege escalation.

Security events collected
─────────────────────────
  Logon / Credential
    4624  Successful logon                (T1078 — valid accounts)
    4625  Failed logon                    (T1110 — brute force indicator)
    4648  Logon with explicit credentials (T1134 — access token manipulation)
    4672  Special privileges at logon     (admin/sensitive privilege use)

  Process (requires "Audit Process Creation" GPO to be enabled)
    4688  Process created with full cmdline (T1059 — command and scripting)

  Service / Persistence
    4697  Service installed by SCM        (T1543.003 — Windows Service)
    7045  New service installed (System)  (duplicate of 4697 from kernel path)

  Scheduled Tasks
    4698  Task created                    (T1053.005 — scheduled task)
    4699  Task deleted
    4700  Task enabled
    4701  Task disabled
    4702  Task updated

  User Account
    4720  Account created                 (T1136 — create account)
    4726  Account deleted
    4738  Account changed / group modified

Each record follows the canonical schema:
  {
    "event_id":  int,
    "timestamp": int (unix epoch),
    "computer":  str,
    "channel":   "Security" | "System",
    "category":  "logon" | "process" | "service" | "task" | "account" | "other",
    "subject":   str | None,   # who triggered the event (e.g. TargetUserName)
    "detail":    dict,         # event-specific key fields (no raw binary blobs)
  }

Privileges required
───────────────────
  Reading the Security event log requires SeSecurityPrivilege or membership in
  the Event Log Readers group.  The agent runs as NT AUTHORITY\\SYSTEM so this
  is always satisfied.  The System channel is world-readable.

Dependencies
────────────
  pywin32 (win32evtlog) — if absent, returns an empty list with a log warning.
  xml.etree.ElementTree — stdlib.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.eventlog")

# Windows Event XML namespace
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# How far back to look (milliseconds — used in XPath timediff)
_LOOKBACK_MS = 24 * 3600 * 1000   # 24 hours
_MAX_EVENTS  = 500                 # cap per cycle; cursors continue next cycle


# ── Event definitions ─────────────────────────────────────────────────────────

_SECURITY_IDS = (
    1102,                             # audit log cleared
    4624, 4625, 4648, 4672,          # logon / credential
    4688,                             # process creation
    4697, 4698, 4699, 4700, 4701, 4702,  # service + task persistence
    4720, 4726, 4728, 4732, 4738, 4756,  # account / privileged group
    4768, 4769, 4771, 4776,           # Kerberos / credential validation
)

_SYSTEM_IDS = (7045,)                 # new service installed (kernel path)
_APPLICATION_IDS = (1000, 1001)       # process crash / error reporting
_POWERSHELL_IDS = (4103, 4104, 4105, 4106)
_DEFENDER_IDS = (1006, 1007, 1116, 1117, 5001, 5004, 5007, 5010, 5012)
_SYSMON_IDS = (1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25, 26)
_TERMINAL_SERVICES_IDS = (21, 22, 23, 24, 25)
_WMI_ACTIVITY_IDS = (5857, 5858, 5859, 5860, 5861)

_CHANNELS: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("Security", _SECURITY_IDS),
    ("System", _SYSTEM_IDS),
    ("Application", _APPLICATION_IDS),
    ("Microsoft-Windows-Sysmon/Operational", _SYSMON_IDS),
    ("Microsoft-Windows-PowerShell/Operational", _POWERSHELL_IDS),
    ("Microsoft-Windows-Windows Defender/Operational", _DEFENDER_IDS),
    (
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        _TERMINAL_SERVICES_IDS,
    ),
    ("Microsoft-Windows-WMI-Activity/Operational", _WMI_ACTIVITY_IDS),
)

# These channels are supplied by optional products and are not present on a
# clean Windows installation. Their absence is a capability state, not a
# collector failure. Recheck periodically so installing the provider while the
# agent is running is detected automatically.
_OPTIONAL_CHANNELS = frozenset({
    "Microsoft-Windows-Sysmon/Operational",
})
_OPTIONAL_RECHECK_SEC = 3600

_CATEGORY_MAP: dict[int, str] = {
    1102: "tamper",
    4624: "logon",   4625: "logon",   4648: "logon",   4672: "logon",
    4688: "process",
    4697: "service", 7045: "service",
    4698: "task",    4699: "task",    4700: "task",    4701: "task",    4702: "task",
    4720: "account", 4726: "account", 4728: "account",
    4732: "account", 4738: "account", 4756: "account",
    4768: "credential", 4769: "credential",
    4771: "credential", 4776: "credential",
    1000: "application", 1001: "application",
    1: "process", 3: "network", 7: "image_load", 8: "injection",
    10: "process_access", 11: "file", 12: "registry", 13: "registry",
    14: "registry", 15: "file", 17: "pipe", 18: "pipe", 22: "dns",
    23: "file", 25: "process_tamper", 26: "file",
    21: "rdp", 24: "rdp",
    5857: "wmi", 5858: "wmi", 5859: "wmi", 5860: "wmi", 5861: "wmi",
    4103: "powershell", 4104: "powershell",
    4105: "powershell", 4106: "powershell",
    1006: "defender", 1007: "defender", 1116: "defender",
    1117: "defender", 5001: "defender", 5004: "defender",
    5007: "defender", 5010: "defender", 5012: "defender",
}

# Fields to extract from EventData per event ID (others go into detail as-is)
_SUBJECT_FIELD: dict[int, str] = {
    4624: "TargetUserName",  4625: "TargetUserName",  4648: "TargetUserName",
    4672: "SubjectUserName", 4688: "SubjectUserName",
    4697: "SubjectUserName", 7045: "AccountName",
    4698: "SubjectUserName", 4699: "SubjectUserName",
    4700: "SubjectUserName", 4701: "SubjectUserName", 4702: "SubjectUserName",
    4720: "TargetUserName",  4726: "TargetUserName",  4738: "TargetUserName",
}

# Only include these EventData fields in the output (exclude binary/noisy fields)
_ALLOWED_FIELDS: dict[int, set[str]] = {
    1102: {"SubjectUserName", "SubjectDomainName", "SubjectLogonId"},
    4624: {"TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "ProcessName"},
    4625: {"TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "FailureReason"},
    4648: {"TargetUserName", "TargetDomainName", "ProcessName", "IpAddress"},
    4672: {"SubjectUserName", "SubjectDomainName", "PrivilegeList"},
    4688: {"SubjectUserName", "NewProcessId", "NewProcessName", "CommandLine", "ParentProcessName"},
    4697: {"SubjectUserName", "ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType"},
    7045: {"AccountName", "ServiceName", "ServiceFileName", "ServiceType", "StartType"},
    4698: {"SubjectUserName", "TaskName", "TaskContent"},
    4699: {"SubjectUserName", "TaskName"},
    4700: {"SubjectUserName", "TaskName"},
    4701: {"SubjectUserName", "TaskName"},
    4702: {"SubjectUserName", "TaskName"},
    4720: {"SubjectUserName", "TargetUserName"},
    4726: {"SubjectUserName", "TargetUserName"},
    4738: {"SubjectUserName", "TargetUserName", "PasswordLastSet"},
    4728: {"SubjectUserName", "MemberName", "MemberSid", "TargetUserName"},
    4732: {"SubjectUserName", "MemberName", "MemberSid", "TargetUserName"},
    4756: {"SubjectUserName", "MemberName", "MemberSid", "TargetUserName"},
    4768: {"TargetUserName", "TargetDomainName", "IpAddress", "Status", "TicketEncryptionType"},
    4769: {"TargetUserName", "ServiceName", "IpAddress", "Status", "TicketEncryptionType"},
    4771: {"TargetUserName", "IpAddress", "Status", "PreAuthType"},
    4776: {"TargetUserName", "Workstation", "Status", "PackageName"},
    1000: {"ApplicationName", "ApplicationVersion", "FaultingModuleName", "ExceptionCode"},
    1001: {"EventName", "AppName", "AppPath", "ReportId"},
    1: {
        "UtcTime", "ProcessGuid", "ProcessId", "Image", "CommandLine",
        "CurrentDirectory", "User", "IntegrityLevel", "Hashes",
        "ParentProcessGuid", "ParentProcessId", "ParentImage",
        "ParentCommandLine", "ParentUser",
    },
    3: {
        "UtcTime", "ProcessGuid", "ProcessId", "Image", "User",
        "Protocol", "Initiated", "SourceIp", "SourcePort", "DestinationIp",
        "DestinationHostname", "DestinationPort",
    },
    7: {"UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"},
    8: {"UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "StartAddress", "StartModule", "StartFunction"},
    10: {"UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "GrantedAccess", "CallTrace"},
    11: {"UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "User"},
    12: {"EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "User"},
    13: {"EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "User"},
    14: {"EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "NewName", "User"},
    15: {"UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "Hashes", "Contents", "User"},
    17: {"UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image", "User"},
    18: {"UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image", "User"},
    22: {"UtcTime", "ProcessGuid", "ProcessId", "QueryName", "QueryStatus", "QueryResults", "Image", "User"},
    23: {"UtcTime", "ProcessGuid", "ProcessId", "User", "Image", "TargetFilename", "Hashes"},
    25: {"UtcTime", "ProcessGuid", "ProcessId", "Image", "Type", "User"},
    26: {"UtcTime", "ProcessGuid", "ProcessId", "User", "Image", "TargetFilename", "Hashes"},
    21: {"User", "SessionID", "Address"},
    24: {"User", "SessionID", "Address"},
    5857: {"ProviderName", "Code", "HostProcess", "ProcessID"},
    5858: {"Operation", "ResultCode", "ClientMachine", "User", "ClientProcessId"},
    5859: {"NamespaceName", "Query", "User", "processid"},
    5860: {"NamespaceName", "Query", "User", "processid"},
    5861: {"NamespaceName", "ESS", "CONSUMER", "PossibleCause", "User"},
    4103: {"ContextInfo", "Payload"},
    4104: {"MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"},
    4105: {"ScriptBlockId", "Path"},
    4106: {"ScriptBlockId", "Path"},
    1006: {"Product Name", "Detection ID", "Detection Time"},
    1007: {"Product Name", "Detection ID", "Action Name"},
    1116: {"Product Name", "Threat Name", "Severity Name", "Path", "Detection ID"},
    1117: {"Product Name", "Threat Name", "Action Name", "Error Description"},
    5001: {"Product Name"},
    5004: {"Product Name", "Feature Name", "New Value"},
    5007: {"Product Name", "Old Value", "New Value"},
    5010: {"Product Name"},
    5012: {"Product Name"},
}


# ── Collector ─────────────────────────────────────────────────────────────────

class EventLogCollector(WinBaseCollector):
    """
    Reads Windows Security and System event logs for security-relevant events.

    Returns up to MAX_EVENTS records from the last 24 hours, newest first.
    The section name "eventlog" is Windows-only — the manager stores it like
    any other section; AttackLens analyzers can pattern-match on event_id and detail.
    """
    name    = "eventlog"
    timeout = 30

    def __init__(self, state_dir: str | None = None) -> None:
        base = Path(state_dir) if state_dir else Path(
            os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        ) / "AttackLens" / "data"
        self._state_path = base / "eventlog-cursors.json"
        self._lock = threading.Lock()
        self._cursors = self._load_cursors()
        self._pending_cursors: dict[str, int] = {}
        self._pending_resets: set[str] = set()
        self._cursor_resets: dict[str, int] = {}
        self._errors: dict[str, dict[str, Any]] = {}
        self._channel_status: dict[str, dict[str, Any]] = {}
        self._optional_retry_after: dict[str, int] = {}
        self._last_success_at: dict[str, int] = {}
        self._parse_errors = 0

    def collect(self) -> list:
        try:
            import win32evtlog
        except ImportError:
            log.warning("pywin32 not installed — eventlog collector disabled")
            return []

        events: list[dict] = []
        pending: dict[str, int] = {}
        pending_resets: set[str] = set()
        per_channel_limit = max(1, _MAX_EVENTS // len(_CHANNELS))
        for channel, event_ids in _CHANNELS:
            if self._optional_retry_after.get(channel, 0) > int(time.time()):
                continue
            cursor = int(self._cursors.get(channel, 0))
            records, latest_id, error = _query_channel_incremental(
                win32evtlog,
                channel,
                event_ids,
                after_record_id=cursor,
                limit=per_channel_limit,
            )
            if error:
                self._record_error(channel, error[0], error[1])
                continue
            if not records and cursor > 0:
                current_latest, latest_error = _channel_latest_record_id(
                    win32evtlog, channel
                )
                if latest_error:
                    self._record_error(
                        channel, latest_error[0], latest_error[1]
                    )
                    continue
                if 0 <= current_latest < cursor:
                    log.warning(
                        "eventlog channel=%s was cleared or recreated; "
                        "resetting cursor old=%d current=%d",
                        channel,
                        cursor,
                        current_latest,
                    )
                    records, latest_id, error = _query_channel_incremental(
                        win32evtlog,
                        channel,
                        event_ids,
                        after_record_id=0,
                        limit=per_channel_limit,
                    )
                    if error:
                        self._record_error(channel, error[0], error[1])
                        continue
                    pending_resets.add(channel)
                    self._cursor_resets[channel] = (
                        int(self._cursor_resets.get(channel, 0)) + 1
                    )
            self._record_success(channel)
            events.extend(records)
            if channel in pending_resets:
                pending[channel] = max(0, latest_id)
            elif latest_id > cursor:
                pending[channel] = latest_id

        # Cursor changes are committed only after durable outbox enqueue.
        with self._lock:
            self._pending_cursors = pending
            self._pending_resets = pending_resets
        events.sort(
            key=lambda event: (
                event.get("timestamp") or 0,
                event.get("record_id") or 0,
            )
        )
        return events

    def commit(self) -> None:
        """Persist prepared cursors after durable enqueue succeeds."""
        with self._lock:
            if not self._pending_cursors:
                return
            updated = dict(self._cursors)
            for channel, record_id in self._pending_cursors.items():
                if channel in self._pending_resets:
                    updated[channel] = int(record_id)
                else:
                    updated[channel] = max(
                        int(updated.get(channel, 0)), int(record_id)
                    )
            self._write_cursors(updated)
            self._cursors = updated
            self._pending_cursors = {}
            self._pending_resets = set()

    def rollback(self) -> None:
        """Forget prepared cursor updates so the next cycle re-reads records."""
        with self._lock:
            self._pending_cursors = {}
            self._pending_resets = set()

    def health_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "cursors": dict(self._cursors),
                "pending_cursors": dict(self._pending_cursors),
                "pending_resets": sorted(self._pending_resets),
                "cursor_resets": dict(self._cursor_resets),
                "channel_errors": dict(self._errors),
                "channel_status": dict(self._channel_status),
                "last_success_at": dict(self._last_success_at),
                "parse_errors": self._parse_errors,
            }

    def _load_cursors(self) -> dict[str, int]:
        if not self._state_path.exists():
            return {}
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("cursor state root must be an object")
            return {
                str(channel): max(0, int(record_id))
                for channel, record_id in raw.items()
            }
        except Exception as exc:
            quarantine = self._state_path.with_suffix(
                f".corrupt-{int(time.time())}.json"
            )
            try:
                os.replace(self._state_path, quarantine)
            except OSError:
                pass
            log.error(
                "eventlog cursor state was corrupt and was quarantined: %s",
                type(exc).__name__,
            )
            return {}

    def _write_cursors(self, cursors: dict[str, int]) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self._state_path.with_suffix(".tmp")
        try:
            with temp.open("w", encoding="utf-8") as handle:
                json.dump(cursors, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self._state_path)
        except Exception:
            temp.unlink(missing_ok=True)
            raise

    def _record_error(self, channel: str, code: str, detail: str) -> None:
        now = int(time.time())
        if code == "channel_unavailable" and channel in _OPTIONAL_CHANNELS:
            previous = self._channel_status.get(channel, {})
            retry_at = now + _OPTIONAL_RECHECK_SEC
            self._errors.pop(channel, None)
            self._optional_retry_after[channel] = retry_at
            self._channel_status[channel] = {
                "status": "not_installed",
                "code": code,
                "last_checked_at": now,
                "retry_at": retry_at,
                "detail": detail[:256],
            }
            if previous.get("status") != "not_installed":
                log.info(
                    "optional eventlog channel=%s is not installed; "
                    "next capability check in %d seconds",
                    channel,
                    _OPTIONAL_RECHECK_SEC,
                )
            return

        previous = self._errors.get(channel, {})
        count = int(previous.get("count", 0)) + 1
        self._errors[channel] = {
            "code": code,
            "count": count,
            "last_at": now,
            "detail": detail[:256],
        }
        self._channel_status[channel] = {
            "status": "error",
            "code": code,
            "last_checked_at": now,
        }
        level = logging.WARNING if count in {1, 3, 10} else logging.DEBUG
        log.log(
            level,
            "eventlog channel=%s unavailable code=%s failures=%d detail=%s",
            channel,
            code,
            count,
            detail,
        )

    def _record_success(self, channel: str) -> None:
        now = int(time.time())
        previous = self._channel_status.get(channel, {})
        self._errors.pop(channel, None)
        self._optional_retry_after.pop(channel, None)
        self._last_success_at[channel] = now
        self._channel_status[channel] = {
            "status": "available",
            "last_success_at": now,
        }
        if previous.get("status") == "not_installed":
            log.info("optional eventlog channel=%s is now available", channel)


# ── Query helpers ─────────────────────────────────────────────────────────────

def _query_channel(win32evtlog: Any, channel: str, event_ids: tuple[int, ...]) -> list[dict]:
    """Run an XPath query against a Windows event channel and return parsed records."""
    if not event_ids:
        return []

    # Build XPath: filter by event IDs + time window in a single query
    id_filter = " or ".join(f"EventID={eid}" for eid in event_ids)
    xpath = (
        f"*[System[({id_filter}) and "
        f"TimeCreated[timediff(@SystemTime) <= {_LOOKBACK_MS}]]]"
    )

    records: list[dict] = []
    try:
        flags = (
            win32evtlog.EvtQueryChannelPath |
            win32evtlog.EvtQueryReverseDirection   # newest first
        )
        handle = win32evtlog.EvtQuery(channel, flags, xpath)

        while len(records) < _MAX_EVENTS:
            batch = win32evtlog.EvtNext(handle, 50, -1, 0)
            if not batch:
                break
            for evt_h in batch:
                try:
                    xml_str = win32evtlog.EvtRender(
                        evt_h, win32evtlog.EvtRenderEventXml
                    )
                    rec = _parse_event_xml(xml_str, channel)
                    if rec:
                        records.append(rec)
                except Exception as exc:
                    log.debug("EvtRender error: %s", exc)

    except Exception as exc:
        # AccessDenied on Security channel if agent isn't SYSTEM — logged once
        log.debug("EvtQuery(%s) failed: %s", channel, exc)

    return records


def _query_channel_incremental(
    win32evtlog: Any,
    channel: str,
    event_ids: tuple[int, ...],
    *,
    after_record_id: int = 0,
    limit: int = _MAX_EVENTS,
) -> tuple[list[dict], int, tuple[str, str] | None]:
    """Read oldest-first records after a committed EventRecordID cursor."""
    if not event_ids:
        return [], after_record_id, None

    id_filter = " or ".join(f"EventID={event_id}" for event_id in event_ids)
    if after_record_id > 0:
        xpath = (
            f"*[System[({id_filter}) and "
            f"EventRecordID > {int(after_record_id)}]]"
        )
    else:
        xpath = (
            f"*[System[({id_filter}) and "
            f"TimeCreated[timediff(@SystemTime) <= {_LOOKBACK_MS}]]]"
        )

    records: list[dict] = []
    latest_id = int(after_record_id)
    query_handle = None
    try:
        flags = (
            win32evtlog.EvtQueryChannelPath
            | win32evtlog.EvtQueryForwardDirection
        )
        query_handle = win32evtlog.EvtQuery(channel, flags, xpath)
        while len(records) < limit:
            batch = win32evtlog.EvtNext(
                query_handle, min(50, limit - len(records)), -1, 0
            )
            if not batch:
                break
            for event_handle in batch:
                try:
                    xml_str = win32evtlog.EvtRender(
                        event_handle, win32evtlog.EvtRenderEventXml
                    )
                    record = _parse_event_xml(xml_str, channel)
                    if record:
                        records.append(record)
                        latest_id = max(
                            latest_id, int(record.get("record_id") or 0)
                        )
                except Exception as exc:
                    log.debug("EvtRender(%s) error: %s", channel, exc)
                finally:
                    _close_event_handle(win32evtlog, event_handle)
        return records, latest_id, None
    except Exception as exc:
        code = _classify_eventlog_error(exc)
        return [], after_record_id, (code, str(exc))
    finally:
        _close_event_handle(win32evtlog, query_handle)


def _channel_latest_record_id(
    win32evtlog: Any,
    channel: str,
) -> tuple[int, tuple[str, str] | None]:
    """Return the channel's newest record ID to detect log clear/recreation."""
    query_handle = None
    event_handle = None
    try:
        flags = (
            win32evtlog.EvtQueryChannelPath
            | win32evtlog.EvtQueryReverseDirection
        )
        query_handle = win32evtlog.EvtQuery(channel, flags, "*")
        batch = win32evtlog.EvtNext(query_handle, 1, -1, 0)
        if not batch:
            return 0, None
        event_handle = batch[0]
        xml_str = win32evtlog.EvtRender(
            event_handle, win32evtlog.EvtRenderEventXml
        )
        root = ET.fromstring(xml_str)
        record_id_el = root.find(
            f"{{{_NS}}}System/{{{_NS}}}EventRecordID"
        )
        return (
            int(record_id_el.text or 0) if record_id_el is not None else 0,
            None,
        )
    except Exception as exc:
        return 0, (_classify_eventlog_error(exc), str(exc))
    finally:
        _close_event_handle(win32evtlog, event_handle)
        _close_event_handle(win32evtlog, query_handle)


def _close_event_handle(win32evtlog: Any, handle: Any) -> None:
    if handle is None:
        return
    try:
        win32evtlog.EvtClose(handle)
    except Exception:
        pass


def _classify_eventlog_error(exc: Exception) -> str:
    code = getattr(exc, "winerror", None)
    if code is None and getattr(exc, "args", None):
        try:
            code = int(exc.args[0])
        except (TypeError, ValueError):
            code = None
    return {
        5: "access_denied",
        1722: "eventlog_service_unavailable",
        15007: "channel_unavailable",
        15011: "query_result_stale",
    }.get(code, f"winerror_{code}" if code is not None else type(exc).__name__)


def _parse_event_xml(xml_str: str, channel: str) -> dict | None:
    """
    Parse Windows Event XML into a flat, canonical dict.

    The XML schema is documented at:
    https://docs.microsoft.com/en-us/windows/win32/wes/eventschema-schema
    """
    try:
        root   = ET.fromstring(xml_str)
        sys_el = root.find(f"{{{_NS}}}System")
        if sys_el is None:
            return None

        # ── Core system fields ────────────────────────────────────────────────
        event_id_el = sys_el.find(f"{{{_NS}}}EventID")
        event_id    = int(event_id_el.text or 0) if event_id_el is not None else 0

        record_id_el = sys_el.find(f"{{{_NS}}}EventRecordID")
        record_id = (
            int(record_id_el.text or 0) if record_id_el is not None else 0
        )

        provider_el = sys_el.find(f"{{{_NS}}}Provider")
        provider = provider_el.get("Name") if provider_el is not None else None

        tc_el    = sys_el.find(f"{{{_NS}}}TimeCreated")
        time_str = tc_el.get("SystemTime") if tc_el is not None else None
        ts       = _parse_timestamp(time_str)

        computer_el = sys_el.find(f"{{{_NS}}}Computer")
        computer    = (computer_el.text or "").strip() if computer_el is not None else None

        # ── EventData → dict (string fields only) ────────────────────────────
        data_el = root.find(f"{{{_NS}}}EventData")
        raw_data: dict[str, str | None] = {}
        if data_el is not None:
            for d in data_el.findall(f"{{{_NS}}}Data"):
                name = d.get("Name")
                if name:
                    raw_data[name] = (d.text or "").strip() or None

        # Filter to allowed fields for this event ID
        allowed = _ALLOWED_FIELDS.get(event_id, set())
        detail = {k: v for k, v in raw_data.items() if k in allowed}
        if not detail and raw_data:
            # Preserve bounded fields for version-specific provider schemas
            # while refusing obvious secret-bearing names.
            sensitive = re.compile(r"password|secret|token|credential", re.I)
            for key in sorted(raw_data):
                if len(detail) >= 24 or sensitive.search(key):
                    continue
                value = raw_data[key]
                detail[key] = value[:2048] if isinstance(value, str) else value

        # ── Redact sensitive values ───────────────────────────────────────────
        # TaskContent can contain credential material in task XML
        if "TaskContent" in detail and detail["TaskContent"]:
            detail["TaskContent"] = "<redacted-xml>"

        # CommandLine may contain passwords passed on the command line
        if "CommandLine" in detail and detail["CommandLine"]:
            detail["CommandLine"] = detail["CommandLine"][:512]   # cap length

        subject_field = _SUBJECT_FIELD.get(event_id)
        subject       = detail.get(subject_field) if subject_field else None

        record = {
            "event_id":  event_id,
            "record_id": record_id,
            "timestamp": ts,
            "computer":  computer,
            "channel":   channel,
            "provider":  provider,
            "category":  _event_category(event_id, provider, channel),
            "subject":   subject,
            "detail":    detail,
        }
        entity = _canonical_entity(event_id, provider, detail)
        if entity:
            record["entity"] = entity
        return record

    except ET.ParseError as exc:
        log.debug("event XML parse error: %s", exc)
        return None
    except Exception as exc:
        log.debug("event parse error: %s", exc)
        return None


def _event_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _event_category(
    event_id: int,
    provider: str | None,
    channel: str,
) -> str:
    provider_name = (provider or "").lower()
    channel_name = channel.lower()
    if "sysmon" in provider_name or "sysmon" in channel_name:
        return {
            1: "process", 3: "network", 7: "image_load", 8: "injection",
            10: "process_access", 11: "file", 12: "registry",
            13: "registry", 14: "registry", 15: "file", 17: "pipe",
            18: "pipe", 22: "dns", 23: "file", 25: "process_tamper",
            26: "file",
        }.get(event_id, "sysmon")
    if "terminalservices" in channel_name:
        return "rdp"
    if "wmi-activity" in channel_name:
        return "wmi"
    return _CATEGORY_MAP.get(event_id, "other")


def _canonical_entity(
    event_id: int,
    provider: str | None,
    detail: dict[str, Any],
) -> dict[str, Any] | None:
    """Normalize equivalent audit sources into source-independent entities."""
    provider_name = (provider or "").lower()
    is_sysmon = "sysmon" in provider_name
    if event_id == 4688:
        return {
            "kind": "process",
            "pid": _event_int(detail.get("NewProcessId")),
            "image": detail.get("NewProcessName"),
            "command_line": detail.get("CommandLine"),
            "parent_image": detail.get("ParentProcessName"),
            "user": detail.get("SubjectUserName"),
        }
    if is_sysmon and event_id == 1:
        return {
            "kind": "process",
            "pid": _event_int(detail.get("ProcessId")),
            "process_guid": detail.get("ProcessGuid"),
            "image": detail.get("Image"),
            "command_line": detail.get("CommandLine"),
            "parent_pid": _event_int(detail.get("ParentProcessId")),
            "parent_image": detail.get("ParentImage"),
            "parent_command_line": detail.get("ParentCommandLine"),
            "integrity_level": detail.get("IntegrityLevel"),
            "user": detail.get("User"),
            "hashes": detail.get("Hashes"),
        }
    if is_sysmon and event_id == 3:
        return {
            "kind": "network",
            "pid": _event_int(detail.get("ProcessId")),
            "image": detail.get("Image"),
            "protocol": detail.get("Protocol"),
            "source_ip": detail.get("SourceIp"),
            "source_port": _event_int(detail.get("SourcePort")),
            "destination_ip": detail.get("DestinationIp"),
            "destination_host": detail.get("DestinationHostname"),
            "destination_port": _event_int(detail.get("DestinationPort")),
            "initiated": detail.get("Initiated"),
        }
    if is_sysmon and event_id == 22:
        return {
            "kind": "dns",
            "pid": _event_int(detail.get("ProcessId")),
            "image": detail.get("Image"),
            "query": detail.get("QueryName"),
            "status": detail.get("QueryStatus"),
            "answers": detail.get("QueryResults"),
        }
    return None


def _parse_timestamp(time_str: str | None) -> int | None:
    """Parse a Windows SystemTime string ('2026-04-20T12:34:56.789Z') to Unix epoch."""
    if not time_str:
        return None
    try:
        # Truncate nanoseconds that Python's fromisoformat can't handle
        ts = time_str.rstrip("Z")
        if "." in ts:
            head, frac = ts.split(".", 1)
            ts = f"{head}.{frac[:6]}"   # keep at most microseconds
        dt = datetime.fromisoformat(ts + "+00:00")
        return int(dt.timestamp())
    except Exception:
        return None
