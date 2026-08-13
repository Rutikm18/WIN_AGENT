"""Windows boot-state telemetry and SCM persistence self-repair.

The service runs this policy at startup and every five minutes.  Repairs are
limited to the AttackLens Agent service and restore only the installation
contract: automatic delayed start and bounded restart recovery actions.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable


SERVICE_NAME = "AttackLensAgent"
WATCHDOG_SERVICE_NAME = "AttackLensWatchdog"
REPAIR_INTERVAL_SEC = 300
RESET_PERIOD_SEC = 86_400
RESTART_ACTIONS = ((1, 5_000), (1, 10_000), (1, 30_000))
WATCHDOG_RESTART_ACTIONS = ((1, 30_000), (1, 30_000), (1, 30_000))


def _normalise_actions(value: Any) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    normalised: list[tuple[int, int]] = []
    for entry in value:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            return ()
        normalised.append((int(entry[0]), int(entry[1])))
    return tuple(normalised)


def enforce_service_policy(
    *,
    service_name: str = SERVICE_NAME,
    repair: bool = True,
    win32service_module: Any | None = None,
    restart_actions: tuple[tuple[int, int], ...] | None = None,
    failure_actions_on_non_crash: bool = True,
) -> dict[str, Any]:
    """Audit and optionally restore the service's persistence contract.

    Failures are returned as structured evidence rather than raised so an SCM
    access problem can never become a new agent outage.
    """
    try:
        if win32service_module is None:
            if os.name != "nt":
                return {
                    "supported": False,
                    "service": service_name,
                    "compliant": None,
                    "repaired": [],
                    "error": "Windows SCM is unavailable on this platform",
                }
            import win32service as win32service_module

        ws = win32service_module
        desired_actions = _normalise_actions(
            restart_actions
            if restart_actions is not None
            else (
                WATCHDOG_RESTART_ACTIONS
                if service_name.casefold() == WATCHDOG_SERVICE_NAME.casefold()
                else RESTART_ACTIONS
            )
        )
        query_access = int(getattr(ws, "SERVICE_QUERY_CONFIG", 0x0001))
        change_access = int(getattr(ws, "SERVICE_CHANGE_CONFIG", 0x0002))
        manager = ws.OpenSCManager(
            None,
            None,
            int(getattr(ws, "SC_MANAGER_CONNECT", 0x0001)),
        )
        service = None
        try:
            service = ws.OpenService(
                manager,
                service_name,
                query_access | (change_access if repair else 0),
            )
            config = ws.QueryServiceConfig(service)
            start_type = int(config[1])
            failure = ws.QueryServiceConfig2(
                service,
                int(getattr(ws, "SERVICE_CONFIG_FAILURE_ACTIONS", 2)),
            )
            failure_flag = bool(ws.QueryServiceConfig2(
                service,
                int(getattr(ws, "SERVICE_CONFIG_FAILURE_ACTIONS_FLAG", 4)),
            ))
            delayed = bool(ws.QueryServiceConfig2(
                service,
                int(getattr(ws, "SERVICE_CONFIG_DELAYED_AUTO_START_INFO", 3)),
            ))

            desired_start = int(getattr(ws, "SERVICE_AUTO_START", 2))
            observed_actions = _normalise_actions((failure or {}).get("Actions"))
            observed_reset = int((failure or {}).get("ResetPeriod", -1))
            drift = {
                "start_type": start_type != desired_start,
                "delayed_auto_start": not delayed,
                "failure_actions": (
                    observed_actions != desired_actions
                    or observed_reset != RESET_PERIOD_SEC
                ),
                "failure_actions_on_non_crash": (
                    failure_flag != bool(failure_actions_on_non_crash)
                ),
            }
            repaired: list[str] = []

            if repair and drift["start_type"]:
                no_change = int(getattr(ws, "SERVICE_NO_CHANGE", 0xFFFFFFFF))
                ws.ChangeServiceConfig(
                    service,
                    no_change,
                    desired_start,
                    no_change,
                    None,
                    None,
                    0,
                    None,
                    None,
                    None,
                    None,
                )
                repaired.append("start_type")
            if repair and drift["delayed_auto_start"]:
                ws.ChangeServiceConfig2(
                    service,
                    int(getattr(ws, "SERVICE_CONFIG_DELAYED_AUTO_START_INFO", 3)),
                    True,
                )
                repaired.append("delayed_auto_start")
            if repair and drift["failure_actions"]:
                ws.ChangeServiceConfig2(
                    service,
                    int(getattr(ws, "SERVICE_CONFIG_FAILURE_ACTIONS", 2)),
                    {
                        "ResetPeriod": RESET_PERIOD_SEC,
                        "RebootMsg": None,
                        "Command": None,
                        "Actions": desired_actions,
                    },
                )
                repaired.append("failure_actions")
            if repair and drift["failure_actions_on_non_crash"]:
                ws.ChangeServiceConfig2(
                    service,
                    int(getattr(ws, "SERVICE_CONFIG_FAILURE_ACTIONS_FLAG", 4)),
                    bool(failure_actions_on_non_crash),
                )
                repaired.append("failure_actions_on_non_crash")

            return {
                "supported": True,
                "service": service_name,
                "compliant": not any(drift.values()) or bool(repair and repaired),
                "drift": drift,
                "repaired": repaired,
                "observed": {
                    "service_type": int(config[0]),
                    "start_type": start_type,
                    "error_control": int(config[2]),
                    "binary_path": str(config[3]),
                    "account": str(config[7]),
                    "display_name": str(config[8]),
                    "delayed_auto_start": delayed,
                    "reset_period_sec": observed_reset,
                    "failure_actions": [list(item) for item in observed_actions],
                    "failure_actions_on_non_crash": failure_flag,
                },
            }
        finally:
            if service is not None:
                ws.CloseServiceHandle(service)
            ws.CloseServiceHandle(manager)
    except Exception as exc:
        return {
            "supported": os.name == "nt" or win32service_module is not None,
            "service": service_name,
            "compliant": False,
            "repaired": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


class BootStateTracker:
    """Atomically preserve boot identity and clean/unclean shutdown state."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        boot_time_fn: Callable[[], float] | None = None,
        wall_time_fn: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self._boot_time_fn = boot_time_fn or self._default_boot_time
        self._wall_time_fn = wall_time_fn
        self._lock = threading.Lock()
        self._boot_time = int(self._boot_time_fn())
        self._started_at = int(self._wall_time_fn())

    @staticmethod
    def _default_boot_time() -> float:
        try:
            import psutil

            return float(psutil.boot_time())
        except Exception:
            # A stable approximation keeps the marker useful if psutil is
            # temporarily unavailable; the normal packaged agent includes it.
            return time.time() - time.monotonic()

    def _read(self) -> dict[str, Any] | None:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return None

    def _write(self, *, clean_stop: bool, reason: str = "") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        payload = {
            "schema": 1,
            "last_seen": int(self._wall_time_fn()),
            "clean_stop": bool(clean_stop),
            "boot_time": self._boot_time,
            "started_at": self._started_at,
            "pid": os.getpid(),
        }
        if reason:
            payload["stop_reason"] = reason
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.path)

    def begin_start(self) -> dict[str, Any]:
        with self._lock:
            previous = self._read()
            previous_boot = (
                int(previous["boot_time"])
                if previous and previous.get("boot_time") is not None
                else None
            )
            boot_changed = (
                previous_boot is not None
                and abs(previous_boot - self._boot_time) > 1
            )
            result = {
                "first_start": previous is None,
                "boot_changed": boot_changed,
                "unexpected_previous_stop": bool(
                    previous is not None and not previous.get("clean_stop", False)
                ),
                "previous_boot_time": previous_boot,
                "boot_time": self._boot_time,
                "previous_last_seen": previous.get("last_seen") if previous else None,
                "previous_clean_stop": previous.get("clean_stop") if previous else None,
            }
            # Mark dirty before any fallible network or collector startup.
            self._write(clean_stop=False)
            return result

    def touch(self) -> None:
        with self._lock:
            self._write(clean_stop=False)

    def mark_clean_stop(self, reason: str) -> None:
        with self._lock:
            self._write(clean_stop=True, reason=reason)
