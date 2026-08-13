"""Registration helper for the AttackLensAgent Windows Event Log source."""
from __future__ import annotations

import os
from typing import Any, Callable


SOURCE_NAME = "AttackLensAgent"


def register_event_source(
    *,
    source_name: str = SOURCE_NAME,
    add_source_fn: Callable[..., Any] | None = None,
    message_dll: str | None = None,
) -> dict[str, Any]:
    """Idempotently register an Application-log source with a message table."""
    try:
        if add_source_fn is None:
            if os.name != "nt":
                return {"registered": False, "supported": False, "reason": "not_windows"}
            import win32evtlog
            import win32evtlogutil

            add_source_fn = win32evtlogutil.AddSourceToRegistry
            message_dll = message_dll or win32evtlog.__file__
        add_source_fn(source_name, msgDLL=message_dll, eventLogType="Application")
        return {
            "registered": True,
            "supported": True,
            "source": source_name,
            "message_dll": message_dll,
        }
    except Exception as exc:
        return {
            "registered": False,
            "supported": os.name == "nt" or add_source_fn is not None,
            "source": source_name,
            "error": f"{type(exc).__name__}: {exc}",
        }
