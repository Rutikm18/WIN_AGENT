"""Built-in status, capability, and manager connectivity diagnostics."""
from __future__ import annotations

import json
import os
import platform
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from agent.os.windows.integrity import IntegrityError, verify_current_install


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None, "root is not an object"
        return value, None
    except FileNotFoundError:
        return None, "not found"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _outbox_status(spool_dir: str) -> dict[str, Any]:
    path = Path(spool_dir) / "delivery-outbox.sqlite3"
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "bytes": path.stat().st_size if path.is_file() else 0,
    }
    if not path.is_file():
        return result
    conn = None
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2)
        quick = conn.execute("PRAGMA quick_check").fetchone()
        result["quick_check"] = quick[0] if quick else "unknown"
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(outbox)").fetchall()
        }
        if "state" in columns:
            result["states"] = {
                str(state): int(count)
                for state, count in conn.execute(
                    "SELECT state, COUNT(*) FROM outbox GROUP BY state"
                ).fetchall()
            }
        else:
            result["states"] = {"unknown": int(
                conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
            )}
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            conn.close()
    return result


def _service_status(name: str) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "available": False}
    if os.name != "nt":
        result["reason"] = "not_windows"
        return result
    try:
        import win32service
        import win32serviceutil

        status = win32serviceutil.QueryServiceStatus(name)
        state_names = {
            win32service.SERVICE_STOPPED: "stopped",
            win32service.SERVICE_START_PENDING: "start_pending",
            win32service.SERVICE_STOP_PENDING: "stop_pending",
            win32service.SERVICE_RUNNING: "running",
            win32service.SERVICE_PAUSED: "paused",
        }
        result.update({
            "available": True,
            "state": state_names.get(status[1], f"state_{status[1]}"),
            "win32_exit_code": int(status[3]),
        })
    except Exception as exc:
        result["reason"] = f"{type(exc).__name__}: {exc}"
    return result


def capability_report(cfg: dict[str, Any]) -> dict[str, Any]:
    """Return evidence-based capability state without overclaiming."""
    try:
        integrity = verify_current_install()
    except IntegrityError as exc:
        integrity = {"status": "failed", "error": str(exc)}
    try:
        import win32evtlog  # noqa: F401
        eventlog_api = True
    except ImportError:
        eventlog_api = False
    try:
        import win32service  # noqa: F401
        service_api = True
    except ImportError:
        service_api = False

    manager = cfg.get("manager", {})
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "frozen": bool(getattr(sys, "frozen", False)),
        },
        "service": {
            "scm_api": service_api,
            "startup_checkpoints": True,
            "watchdog_heartbeat": True,
            "single_instance_mutex": True,
            "preshutdown_flush": True,
            "power_event_handling": True,
            "recovery_actions_packaged": True,
            "delayed_auto_start_packaged": True,
        },
        "delivery": {
            "encrypted_transactional_outbox": True,
            "offline_collection_without_manager": True,
            "delete_only_after_ack": True,
            "retry_after": True,
            "fresh_nonce_per_retry": True,
            "disk_pressure_guard": True,
            "manager_idempotency_required_for_exactly_once": True,
        },
        "telemetry": {
            "native_eventlog_api": eventlog_api,
            "eventlog_checkpoint_per_channel": True,
            "security_channel": True,
            "powershell_channel": True,
            "defender_channel": True,
            "sysmon_channel": True,
            "terminal_services_channel": True,
            "wmi_activity_channel": True,
            "realtime_etw_session": False,
            "threat_intelligence_provider": False,
        },
        "process_visibility": {
            "command_line": True,
            "parent_pid": True,
            "authenticode_cached": True,
            "catalog_signature": False,
            "kernel_injection_signals": False,
        },
        "developer_security_audit": {
            "enabled": cfg.get("collection", {}).get("sections", {})
                .get("security_audit", {}).get("enabled", True),
            "cross_profile_filesystem": True,
            "loaded_user_registry_hives": True,
            "offline_user_hives_loaded": False,
            "ide_and_browser_extensions": True,
            "mcp_json_jsonc_toml": True,
            "mcp_yaml_metadata_only": True,
            "node_python_manifest_inventory": True,
            "user_tool_execution": False,
            "task_service_startup_risk": True,
            "git_hooks_and_workspace_execution": True,
            "credential_values_collected": False,
            "docker_environment_values_collected": False,
        },
        "transport": {
            "url_scheme": urlparse(str(manager.get("url", ""))).scheme,
            "tls_verify": bool(manager.get("tls_verify", True)),
            "spki_pin": bool(manager.get("spki_pin")),
            "explicit_proxy": bool(manager.get("proxy_url")),
            "explicit_plain_http_override": bool(
                manager.get("allow_insecure_transport", False)
            ),
        },
        "integrity": integrity,
        "package_signing": {
            "requires_release_certificate": True,
            "verified_at_runtime": integrity.get("status") == "verified",
        },
    }


def status_report(cfg: dict[str, Any]) -> dict[str, Any]:
    data_dir = Path(cfg["paths"]["data_dir"])
    runtime_path = data_dir / "agent.runtime.json"
    runtime, runtime_error = _read_json(runtime_path)
    now = int(time.time())
    runtime_age = (
        max(0, now - int(runtime.get("updated_at", 0)))
        if runtime and runtime.get("updated_at")
        else None
    )
    return {
        "generated_at": now,
        "agent_id": cfg.get("agent", {}).get("id"),
        "manager_url": cfg.get("manager", {}).get("url"),
        "runtime": runtime,
        "runtime_error": runtime_error,
        "runtime_age_sec": runtime_age,
        "outbox": _outbox_status(cfg["paths"]["spool_dir"]),
        "services": {
            "agent": _service_status("AttackLensAgent"),
            "watchdog": _service_status("AttackLensWatchdog"),
        },
        "capabilities": capability_report(cfg),
    }


def connectivity_test(
    cfg: dict[str, Any],
    *,
    transport_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    from agent.os.windows.tls_transport import WindowsTLSTransport

    manager = cfg["manager"]
    if not str(manager.get("url") or "").strip():
        return {
            "manager_url": "",
            "host": None,
            "port": None,
            "ok": False,
            "offline_spool": True,
            "error": "manager URL is not configured; telemetry remains in the encrypted local spool",
        }
    parsed = urlparse(manager["url"])
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    started = time.monotonic()
    result: dict[str, Any] = {
        "manager_url": manager["url"],
        "host": parsed.hostname,
        "port": port,
        "ok": False,
        "dns": {"ok": False},
        "tcp": {"ok": False},
        "http": {"ok": False},
    }
    if not parsed.hostname:
        result["error"] = "manager URL has no hostname"
        return result
    try:
        addresses = sorted({
            item[4][0] for item in socket.getaddrinfo(parsed.hostname, port)
        })
        result["dns"] = {"ok": True, "addresses": addresses}
    except Exception as exc:
        result["dns"]["error"] = f"{type(exc).__name__}: {exc}"
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result
    try:
        with socket.create_connection((parsed.hostname, port), timeout=10):
            result["tcp"] = {"ok": True}
    except Exception as exc:
        result["tcp"]["error"] = f"{type(exc).__name__}: {exc}"
        result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result

    factory = transport_factory or WindowsTLSTransport
    transport = None
    try:
        timeout = max(1, int(manager.get("timeout_sec", 30)))
        transport = factory(
            base_url=manager["url"],
            spki_pin=manager.get("spki_pin") or None,
            tls_verify=manager.get("ca_bundle") or manager.get("tls_verify", True),
            timeout=(min(10, timeout), timeout),
            proxy_url=manager.get("proxy_url") or None,
        )
        response = transport.get("/health")
        body: Any = None
        try:
            body = response.json()
        except Exception:
            body = str(getattr(response, "text", ""))[:512]
        status_code = int(response.status_code)
        result["http"] = {
            "ok": 200 <= status_code < 300,
            "status_code": status_code,
            "body": body,
        }
    except Exception as exc:
        result["http"]["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
    result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    result["ok"] = all(
        bool(result[key].get("ok")) for key in ("dns", "tcp", "http")
    )
    return result
