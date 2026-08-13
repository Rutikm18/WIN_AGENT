"""Elevated source integration probe for process + DNS ETW collectors."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from agent.os.windows.collectors.volatile import ConnectionsCollector, ProcessesCollector
from agent.os.windows.normalizer import normalize
from shared.schema import validate_section


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    processes = ProcessesCollector()
    connections = ConnectionsCollector()
    started = time.monotonic()
    process_ok = processes.start_stream()
    dns_ok = connections.start_stream()
    subprocess.run(
        ["cmd.exe", "/c", "exit", "0"], check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        socket.getaddrinfo(f"attacklens-{uuid.uuid4().hex}.invalid", 443)
    except OSError:
        pass
    time.sleep(3)
    process_rows = normalize("processes", processes.collect())
    connection_rows = normalize("connections", connections.collect())
    stop_started = time.monotonic()
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda collector: collector.stop_stream(), (processes, connections)))
    summary = {
        "process_started": process_ok,
        "dns_started": dns_ok,
        "elapsed_sec": round(time.monotonic() - started, 3),
        "stop_elapsed_sec": round(time.monotonic() - stop_started, 3),
        "process_schema_errors": validate_section("processes", process_rows),
        "connection_schema_errors": validate_section("connections", connection_rows),
        "process_etw_rows": sum(
            row.get("_win", {}).get("source") == "etw" for row in process_rows
            if isinstance(row.get("_win"), dict)
        ),
        "dns_etw_rows": sum(
            row.get("proto") == "dns" for row in connection_rows
        ),
        "process_health": processes.health_snapshot(),
        "connection_health": connections.health_snapshot(),
    }
    Path(args.output).write_text(json.dumps(summary), encoding="utf-8")
    return 0 if (
        process_ok and dns_ok and not summary["process_schema_errors"]
        and not summary["connection_schema_errors"]
        and summary["process_etw_rows"] > 0 and summary["dns_etw_rows"] > 0
    ) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
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
