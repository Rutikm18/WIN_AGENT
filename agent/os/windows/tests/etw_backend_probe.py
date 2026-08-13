"""Short, read-only pywintrace compatibility probe; run elevated on Windows."""
from __future__ import annotations

import json
import argparse
from pathlib import Path
import socket
import subprocess
import time
import uuid

import etw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    parser.add_argument("--provider", choices=("process", "dns"), default="process")
    args = parser.parse_args()
    events: list[dict] = []
    if args.provider == "process":
        providers = [etw.ProviderInfo(
            "Microsoft-Windows-Kernel-Process",
            etw.GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"),
            any_keywords=0x10,
        )]
    else:
        providers = [etw.ProviderInfo(
            "Microsoft-Windows-DNS-Client",
            etw.GUID("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"),
        )]
    trace = etw.ETW(
        session_name=f"AttackLens-ETW-Probe-{uuid.uuid4().hex}",
        providers=providers,
        event_callback=lambda event: events.append(event),
        event_id_filters=[1, 2] if args.provider == "process" else [3006, 3008, 3009, 3010],
    )
    trace.start()
    try:
        subprocess.run(
            ["cmd.exe", "/c", "exit", "0"],
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        socket.getaddrinfo(f"probe-{uuid.uuid4().hex}.invalid", 443)
    except OSError:
        pass
    finally:
        time.sleep(3)
        trace.stop()

    summary = {
        "count": len(events),
        "event_types": [
            [type(part).__name__ for part in event]
            if isinstance(event, (tuple, list)) else type(event).__name__
            for event in events[:10]
        ],
        "samples": (
            [event for event in events if event[0] in (1, 2)][:3]
            if args.provider == "process" else events[:5]
        ),
    }
    rendered = json.dumps(summary, default=str)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    return 0 if events else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        import sys
        import traceback
        rendered = json.dumps({
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        })
        try:
            output_index = sys.argv.index("--output") + 1
            Path(sys.argv[output_index]).write_text(rendered, encoding="utf-8")
        except Exception:
            print(rendered)
        raise SystemExit(1)
