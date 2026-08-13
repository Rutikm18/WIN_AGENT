"""Elevated live EvtSubscribe and bookmark-resume verification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from agent.os.windows.collectors.eventlog import EventLogCollector
from agent.os.windows.normalizer import normalize
from shared.schema import validate_section


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    collector = EventLogCollector(args.state)
    started = collector.start_stream()
    subprocess.run(
        ["cmd.exe", "/c", "exit", "0"], check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    subprocess.run(
        ["eventcreate.exe", "/T", "ERROR", "/ID", "1000", "/L", "APPLICATION",
         "/SO", "AttackLensProbe", "/D", "AttackLens subscription verification"],
        check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    time.sleep(5)
    rows = normalize("eventlog", collector.collect())
    errors = validate_section("eventlog", rows)
    collector.commit()
    first_health = collector.health_snapshot()
    collector.stop_stream()
    bookmarks = sorted(
        str(path.relative_to(Path(args.state)))
        for path in Path(args.state).rglob("*.bookmark")
    )

    resumed = EventLogCollector(args.state)
    resumed_ok = resumed.start_stream()
    time.sleep(1)
    resumed_health = resumed.health_snapshot()
    resumed.stop_stream()
    summary = {
        "started": started,
        "resumed": resumed_ok,
        "rows": len(rows),
        "schema_errors": errors,
        "bookmarks": bookmarks,
        "available_channels": sorted(
            channel for channel, health in first_health["subscriptions"].items()
            if health.get("available")
        ),
        "unavailable_channels": sorted(
            channel for channel, health in first_health["subscriptions"].items()
            if not health.get("available")
        ),
        "subscription_errors": {
            channel: health.get("last_error")
            for channel, health in first_health["subscriptions"].items()
            if not health.get("available")
        },
        "resumed_running": sum(
            bool(health.get("running"))
            for health in resumed_health["subscriptions"].values()
        ),
        "resume_errors": {
            channel: health.get("last_error")
            for channel, health in resumed_health["subscriptions"].items()
            if not health.get("available")
        },
    }
    Path(args.output).write_text(json.dumps(summary), encoding="utf-8")
    return 0 if started and resumed_ok and not errors and bookmarks else 2


if __name__ == "__main__":
    raise SystemExit(main())
