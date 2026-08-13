"""Opt-in live Windows-agent delivery check.

This script enrolls a temporary agent identity, queues one deliberately old
canonical record, and runs the production reliable sender until the manager
acknowledges it. It never prints credentials.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

from agent.agent.crypto import derive_keys
from agent.os.windows.reliable_outbox import ReliableOutbox
from agent.os.windows.win_agent import WindowsAgent


def _safe_identity() -> str:
    host = "".join(
        char.lower() if char.isalnum() else "-"
        for char in socket.gethostname()
    ).strip("-")
    return f"attacklens-win-live-{host}-{int(time.time())}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manager",
        default="http://13.233.122.80:8080",
    )
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument(
        "--records",
        type=int,
        default=1,
        help="number of durable replay records to queue (1-10000)",
    )
    parser.add_argument(
        "--all-sections",
        action="store_true",
        help="collect and forward every enabled source section before the probe",
    )
    parser.add_argument(
        "--sca",
        action="store_true",
        help="run and forward one complete Windows security assessment",
    )
    args = parser.parse_args()

    if not 1 <= args.records <= 10_000:
        parser.error("--records must be between 1 and 10000")

    manager = args.manager.rstrip("/")
    agent_id = _safe_identity()
    root_parent = (
        Path(__file__).resolve().parents[1] / "run"
    )
    root_parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="live-reliability-",
        dir=root_parent,
    ) as root:
        cfg = {
            "agent": {"id": agent_id, "name": socket.gethostname()},
            "manager": {
                "url": manager,
                "allow_insecure_transport": manager.startswith("http://"),
                "tls_verify": False,
                "timeout_sec": 10,
            },
            "enrollment": {"token": ""},
            "paths": {
                "security_dir": os.path.join(root, "security"),
                "spool_dir": os.path.join(root, "spool"),
                "data_dir": os.path.join(root, "data"),
                "log_dir": os.path.join(root, "logs"),
                "config_dir": os.path.join(root, "config"),
            },
            "logging": {
                "level": "INFO",
                "file": os.path.join(root, "logs", "agent.log"),
                "max_mb": 1,
                "backups": 1,
            },
            "collection": {
                "sections": {
                    "binaries": {"enabled": False},
                    "sbom": {"enabled": False},
                    "sca": {"enabled": bool(args.sca or args.all_sections), "interval_sec": 3600},
                }
            },
            "transport": {
                "initial_backoff_sec": 1,
                "max_backoff_sec": 5,
                "auth_failure_threshold": 3,
                "auto_reenroll": False,
                "min_free_mb": 16,
                "outbox_busy_timeout_ms": 1000,
            },
        }
        agent = WindowsAgent(cfg)
        agent._load_collectors()
        response = agent._post_enrollment_windows(
            payload={
                "agent_id": agent_id,
                "agent_name": socket.gethostname(),
                "hostname": socket.gethostname(),
                "os": "windows",
                "arch": os.environ.get("PROCESSOR_ARCHITECTURE", "unknown"),
                "timestamp": int(time.time()),
            },
            token="",
        )
        api_key = str(response.get("api_key") or "")
        if len(api_key) != 64:
            raise RuntimeError("manager enrollment returned an invalid API key")
        agent._agent_number = str(response.get("agent_number") or "live")
        agent._enc_key, agent._mac_key = derive_keys(api_key)

        with mock.patch(
            "agent.os.windows.reliable_outbox._PayloadProtector._repair_acl"
        ):
            agent._outbox = ReliableOutbox(
                cfg["paths"]["spool_dir"],
                cfg["paths"]["security_dir"],
                agent_id,
            )
            forwarded_sections: list[str] = []
            sca_summary: dict = {}
            sender: "threading.Thread | None" = None
            try:
                if args.all_sections:
                    collected = agent.collect_once()
                    for section, data in collected.items():
                        collector = agent._collectors.get(section)
                        try:
                            agent._queue_collected_data(section, data)
                            forwarded_sections.append(section)
                            commit = getattr(collector, "commit", None)
                            if callable(commit):
                                commit()
                        except Exception:
                            rollback = getattr(collector, "rollback", None)
                            if callable(rollback):
                                rollback()
                            raise
                        if section == "sca" and isinstance(data, dict):
                            sca_summary = data.get("summary") or {}
                elif args.sca:
                    from agent.os.windows.normalizer import normalize

                    sca_collector = agent._collectors["sca"]
                    try:
                        sca_data = normalize("sca", sca_collector())
                        agent._queue_collected_data("sca", sca_data)
                        sca_collector.commit()
                        forwarded_sections.append("sca")
                        sca_summary = sca_data.get("summary") or {}
                    except Exception:
                        sca_collector.rollback()
                        raise

                # Ten-minute-old collections prove replay-window-safe
                # re-encryption.  Batch enqueue also proves that a restart can
                # never expose a partially committed test set.
                messages = [
                    agent._new_message(
                        "agent_health",
                        {
                            "probe": "windows_reliable_delivery",
                            "platform": "windows",
                            "hostname": socket.gethostname(),
                            "sequence": sequence,
                            "record_count": args.records,
                        },
                        collected_at=int(time.time()) - 600,
                    )
                    for sequence in range(args.records)
                ]
                delivery_ids = agent._outbox.enqueue_many(messages)
                if len(delivery_ids) != args.records or len(set(delivery_ids)) != args.records:
                    raise RuntimeError("outbox did not create a unique durable delivery ID per record")
                persisted_stats = agent._outbox.stats()
                if persisted_stats["pending"] != args.records:
                    raise RuntimeError("outbox did not durably persist every queued record")

                # Simulate an offline service restart.  The second outbox
                # instance must decrypt and replay records written by the first.
                agent._outbox.close()
                agent._outbox = ReliableOutbox(
                    cfg["paths"]["spool_dir"],
                    cfg["paths"]["security_dir"],
                    agent_id,
                )
                reopened_stats = agent._outbox.stats()
                if reopened_stats["pending"] != args.records:
                    raise RuntimeError("outbox records were lost across reopen")
                sender = threading.Thread(
                    target=agent._reliable_sender_loop,
                    daemon=True,
                    name="live-manager-sender",
                )
                sender.start()
                deadline = time.monotonic() + max(5, args.timeout)
                while time.monotonic() < deadline:
                    stats = agent._outbox.stats()
                    if stats["pending"] == 0:
                        break
                    time.sleep(0.25)
                final_stats = agent._outbox.stats()
            finally:
                agent.stop()
                if sender is not None:
                    sender.join(timeout=10)
                agent._outbox.close()

        result = {
            "manager": manager,
            "agent_id": agent_id,
            "enrollment": "ok",
            "pending": final_stats["pending"],
            "dead_letters": final_stats["dead_letters"],
            "acknowledged": agent._delivery_snapshot()["acknowledged"],
            "connection_state": agent._connection_state,
            "old_collection_age_sec": 600,
            "requested_records": args.records,
            "unique_delivery_ids": len(set(delivery_ids)),
            "persisted_before_reopen": persisted_stats["pending"],
            "recovered_after_reopen": reopened_stats["pending"],
            "forwarded_section_count": len(forwarded_sections),
            "forwarded_sections": sorted(forwarded_sections),
            "sca_summary": sca_summary,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        if (
            result["pending"] != 0
            or result["dead_letters"] != 0
            or result["acknowledged"] != args.records
            or result["unique_delivery_ids"] != args.records
        ):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
