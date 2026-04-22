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

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.eventlog")

# Windows Event XML namespace
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# How far back to look (milliseconds — used in XPath timediff)
_LOOKBACK_MS = 24 * 3600 * 1000   # 24 hours
_MAX_EVENTS  = 500                 # cap to avoid huge payloads


# ── Event definitions ─────────────────────────────────────────────────────────

_SECURITY_IDS = (
    4624, 4625, 4648, 4672,          # logon / credential
    4688,                             # process creation
    4697, 4698, 4699, 4700, 4701, 4702,  # service + task persistence
    4720, 4726, 4738,                 # account management
)

_SYSTEM_IDS = (7045,)                # new service installed (kernel path)

_CATEGORY_MAP: dict[int, str] = {
    4624: "logon",   4625: "logon",   4648: "logon",   4672: "logon",
    4688: "process",
    4697: "service", 7045: "service",
    4698: "task",    4699: "task",    4700: "task",    4701: "task",    4702: "task",
    4720: "account", 4726: "account", 4738: "account",
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
    4624: {"TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "ProcessName"},
    4625: {"TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "FailureReason"},
    4648: {"TargetUserName", "TargetDomainName", "ProcessName", "IpAddress"},
    4672: {"SubjectUserName", "SubjectDomainName", "PrivilegeList"},
    4688: {"SubjectUserName", "NewProcessName", "CommandLine", "ParentProcessName"},
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
}


# ── Collector ─────────────────────────────────────────────────────────────────

class EventLogCollector(WinBaseCollector):
    """
    Reads Windows Security and System event logs for security-relevant events.

    Returns up to MAX_EVENTS records from the last 24 hours, newest first.
    The section name "eventlog" is Windows-only — the manager stores it like
    any other section; Jarvis analyzers can pattern-match on event_id and detail.
    """
    name    = "eventlog"
    timeout = 30

    def collect(self) -> list:
        try:
            import win32evtlog
        except ImportError:
            log.warning("pywin32 not installed — eventlog collector disabled")
            return []

        events: list[dict] = []
        events.extend(_query_channel(win32evtlog, "Security", _SECURITY_IDS))
        events.extend(_query_channel(win32evtlog, "System",   _SYSTEM_IDS))

        # Newest first, cap at MAX_EVENTS
        events.sort(key=lambda e: e.get("timestamp") or 0, reverse=True)
        return events[:_MAX_EVENTS]


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
        detail  = {k: v for k, v in raw_data.items() if k in allowed}

        # ── Redact sensitive values ───────────────────────────────────────────
        # TaskContent can contain credential material in task XML
        if "TaskContent" in detail and detail["TaskContent"]:
            detail["TaskContent"] = "<redacted-xml>"

        # CommandLine may contain passwords passed on the command line
        if "CommandLine" in detail and detail["CommandLine"]:
            detail["CommandLine"] = detail["CommandLine"][:512]   # cap length

        subject_field = _SUBJECT_FIELD.get(event_id)
        subject       = detail.get(subject_field) if subject_field else None

        return {
            "event_id":  event_id,
            "timestamp": ts,
            "computer":  computer,
            "channel":   channel,
            "category":  _CATEGORY_MAP.get(event_id, "other"),
            "subject":   subject,
            "detail":    detail,
        }

    except ET.ParseError as exc:
        log.debug("event XML parse error: %s", exc)
        return None
    except Exception as exc:
        log.debug("event parse error: %s", exc)
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
