"""Runtime tamper auditing for the Windows service.

The module deliberately separates detection from recovery.  ACL drift is safe
to repair in place; changed executables and configuration are reported but are
never overwritten by the running service.  Package repair remains the MSI's
responsibility and an administrator-authored config change takes effect after
a controlled service restart.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any, Callable, Mapping

from agent.os.windows.integrity import sha256_file, verify_current_install


INTEGRITY_RECHECK_SEC = 1800


def _normalise_path(value: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expandvars(value.strip().strip('"'))))


def _overlaps(exclusion: str, protected: str) -> bool:
    """Return true when a Defender path exclusion covers a protected path."""
    if not exclusion or not protected:
        return False
    candidate = _normalise_path(exclusion)
    target = _normalise_path(protected)
    if any(char in candidate for char in "*?"):
        return fnmatch.fnmatch(target, candidate) or fnmatch.fnmatch(
            os.path.join(target, "probe"), candidate
        )
    try:
        common = os.path.commonpath((candidate, target))
    except ValueError:
        return False
    return common in {candidate, target}


def defender_exclusion_status(
    protected_paths: list[str],
    *,
    winreg_module: Any | None = None,
) -> dict[str, Any]:
    """Check Defender path exclusions without returning the exclusion values."""
    try:
        if winreg_module is None:
            if os.name != "nt":
                return {"supported": False, "reason": "not_windows"}
            import winreg as winreg_module
        wr = winreg_module
        access = int(getattr(wr, "KEY_READ", 0x20019)) | int(
            getattr(wr, "KEY_WOW64_64KEY", 0x0100)
        )
        key = wr.OpenKey(
            wr.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            0,
            access,
        )
        exclusions: list[str] = []
        try:
            index = 0
            while True:
                try:
                    name, _value, _kind = wr.EnumValue(key, index)
                    exclusions.append(str(name))
                    index += 1
                except OSError:
                    break
        finally:
            close = getattr(wr, "CloseKey", None)
            if callable(close):
                close(key)
            elif hasattr(key, "Close"):
                key.Close()
        matches = sum(
            1
            for exclusion in exclusions
            if any(_overlaps(exclusion, item) for item in protected_paths if item)
        )
        return {
            "supported": True,
            "readable": True,
            "exclusion_count": len(exclusions),
            "protected_path_excluded": matches > 0,
            "protected_match_count": matches,
        }
    except FileNotFoundError:
        return {
            "supported": True,
            "readable": True,
            "exclusion_count": 0,
            "protected_path_excluded": False,
            "protected_match_count": 0,
        }
    except Exception as exc:
        return {
            "supported": os.name == "nt" or winreg_module is not None,
            "readable": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def audit_self_defense(
    paths: Mapping[str, str],
    *,
    config_path: str | None,
    config_digest: str | None,
    verify_integrity: bool = True,
    integrity_fn: Callable[[], dict[str, Any]] = verify_current_install,
    acl_check_fn: Callable[..., list[Any]] | None = None,
    acl_repair_fn: Callable[..., list[Any]] | None = None,
    defender_fn: Callable[[list[str]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Audit package/config/ACL/Defender state and repair only ACL drift."""
    from agent.os.windows.acl import ensure_runtime_acls

    check = acl_check_fn or ensure_runtime_acls
    repair = acl_repair_fn or ensure_runtime_acls
    alerts: list[dict[str, str]] = []
    result: dict[str, Any] = {"alerts": alerts, "repaired": []}

    if verify_integrity:
        try:
            result["install_integrity"] = integrity_fn()
        except Exception as exc:
            result["install_integrity"] = {
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
            }
            alerts.append({
                "code": "install_integrity_failed",
                "severity": "critical",
                "action": "Run an authenticated MSI repair or reinstall.",
            })

    if config_path and config_digest:
        try:
            changed = sha256_file(config_path) != config_digest
            result["config_integrity"] = {
                "status": "changed" if changed else "verified",
                "changed": changed,
            }
            if changed:
                alerts.append({
                    "code": "configuration_changed",
                    "severity": "warning",
                    "action": "Validate agent.toml and restart AttackLensAgent to apply the change.",
                })
        except OSError as exc:
            result["config_integrity"] = {
                "status": "unreadable",
                "error": f"{type(exc).__name__}: {exc}",
            }
            alerts.append({
                "code": "configuration_unreadable",
                "severity": "high",
                "action": "Restore the ProgramData config file and its ACL.",
            })
    else:
        result["config_integrity"] = {"status": "unknown", "changed": None}

    try:
        audited = check(paths, repair=False)
        drifted = [item for item in audited if not item.compliant and not item.skipped]
        result["acl"] = {
            "checked": len([item for item in audited if not item.skipped]),
            "drifted": len(drifted),
            "errors": [item.error for item in drifted if item.error],
        }
        if drifted:
            repaired = repair(paths, repair=True)
            failed = [item for item in repaired if not item.compliant and not item.skipped]
            result["repaired"] = sorted({item.policy for item in repaired if item.compliant})
            alerts.append({
                "code": "acl_drift_repaired" if not failed else "acl_repair_failed",
                "severity": "warning" if not failed else "critical",
                "action": (
                    "No operator action is required; the protected ACL was restored."
                    if not failed
                    else "Run the elevated repair command and inspect icacls output."
                ),
            })
    except Exception as exc:
        result["acl"] = {"checked": 0, "drifted": None, "error": f"{type(exc).__name__}: {exc}"}
        alerts.append({
            "code": "acl_audit_failed",
            "severity": "high",
            "action": "Run the elevated repair command and verify protected paths.",
        })

    protected = [
        str(paths.get("install_dir") or ""),
        str(paths.get("security_dir") or ""),
        str(paths.get("spool_dir") or ""),
        str(config_path or ""),
    ]
    defender = (defender_fn or defender_exclusion_status)(protected)
    result["defender_exclusions"] = defender
    if defender.get("protected_path_excluded"):
        alerts.append({
            "code": "agent_path_excluded_from_defender",
            "severity": "high",
            "action": "Remove the Defender path exclusion through approved endpoint policy.",
        })
    result["ok"] = not any(item["severity"] in {"critical", "high"} for item in alerts)
    return result
