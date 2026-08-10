"""Centralized Windows ACL policy and drift/repair helpers.

The Windows agent has several directories with different trust boundaries.
Keeping the exact ``icacls`` arguments here prevents the installer, runtime,
and keystore from silently drifting apart.

The module is importable off Windows.  Tests inject a runner, while production
uses ``icacls.exe`` only when running on Windows.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

log = logging.getLogger("agent.windows.acl")

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
ACL_TIMEOUT_SEC = 10

# SIDs keep commands stable across localized Windows installations.
SYSTEM = "*S-1-5-18"
NETWORK_SERVICE = "*S-1-5-20"
ADMINISTRATORS = "*S-1-5-32-544"
USERS = "*S-1-5-32-545"
EVERYONE = "*S-1-1-0"
AUTHENTICATED_USERS = "*S-1-5-11"
PROTECTED_REMOVE = (EVERYONE, AUTHENTICATED_USERS, USERS)


@dataclass(frozen=True)
class AclPolicy:
    """One directory/file ACL contract."""

    name: str
    grants: tuple[tuple[str, str], ...]
    remove: tuple[str, ...] = (EVERYONE, AUTHENTICATED_USERS)


@dataclass(frozen=True)
class AclResult:
    path: str
    policy: str
    compliant: bool
    changed: bool = False
    skipped: bool = False
    error: str | None = None
    output: str = ""


# F = full control, M = modify, RX = read/execute.  Service-owned data has no
# Users grant, preventing normal local users from tampering with telemetry or
# privileged inputs.
POLICIES: Mapping[str, AclPolicy] = {
    "secure_dir": AclPolicy(
        "secure_dir",
        ((SYSTEM, "(OI)(CI)(F)"), (NETWORK_SERVICE, "(OI)(CI)(F)"),
         (ADMINISTRATORS, "(OI)(CI)(F)")),
        remove=PROTECTED_REMOVE,
    ),
    "executable_dir": AclPolicy(
        "executable_dir",
        ((SYSTEM, "(OI)(CI)(F)"), (NETWORK_SERVICE, "(OI)(CI)(RX)"),
         (ADMINISTRATORS, "(OI)(CI)(F)"),
         (USERS, "(OI)(CI)(RX)")),
        remove=(EVERYONE, AUTHENTICATED_USERS),
    ),
    "log_dir": AclPolicy(
        "log_dir",
        ((SYSTEM, "(OI)(CI)(F)"), (NETWORK_SERVICE, "(OI)(CI)(M)"),
         (ADMINISTRATORS, "(OI)(CI)(M)")),
        remove=PROTECTED_REMOVE,
    ),
    "service_data_dir": AclPolicy(
        "service_data_dir",
        ((SYSTEM, "(OI)(CI)(F)"), (NETWORK_SERVICE, "(OI)(CI)(M)"),
         (ADMINISTRATORS, "(OI)(CI)(M)")),
        remove=PROTECTED_REMOVE,
    ),
    "status_dir": AclPolicy(
        "status_dir",
        # Contains only a deliberately sanitized health summary. Local users
        # may read it, but only service identities and administrators may
        # create or replace files in it.
        ((SYSTEM, "(OI)(CI)(F)"), (NETWORK_SERVICE, "(OI)(CI)(M)"),
         (ADMINISTRATORS, "(OI)(CI)(M)"), (USERS, "(OI)(CI)(RX)")),
        remove=(EVERYONE, AUTHENTICATED_USERS),
    ),
    "config_file": AclPolicy(
        "config_file",
        # The LocalSystem service reapplies this fail-closed ACL at startup.
        # It therefore needs WRITE_DAC (included in F), not read-only access.
        ((SYSTEM, "(F)"), (NETWORK_SERVICE, "(R)"),
         (ADMINISTRATORS, "(M)")),
        remove=PROTECTED_REMOVE,
    ),
    "key_file": AclPolicy(
        "key_file",
        # Enrollment and credential rotation atomically replace this file.
        ((SYSTEM, "(F)"), (NETWORK_SERVICE, "(R)"),
         (ADMINISTRATORS, "(R)")),
        remove=PROTECTED_REMOVE,
    ),
    "response_dir": AclPolicy(
        "response_dir",
        ((SYSTEM, "(OI)(CI)(F)"), (NETWORK_SERVICE, "(OI)(CI)(F)"),
         (ADMINISTRATORS, "(OI)(CI)(F)")),
        remove=PROTECTED_REMOVE,
    ),
}


Runner = Callable[..., subprocess.CompletedProcess[str]]


def policy(name: str) -> AclPolicy:
    """Return a named policy or raise a clear programming error."""
    try:
        return POLICIES[name]
    except KeyError:
        raise ValueError(f"unknown Windows ACL policy: {name}") from None


def build_icacls_command(path: str | os.PathLike[str],
                         acl_policy: AclPolicy | str) -> list[str]:
    """Build a deterministic repair command without executing it."""
    acl_policy = policy(acl_policy) if isinstance(acl_policy, str) else acl_policy
    target = os.fspath(path)
    command = ["icacls", target, "/inheritance:r"]
    for principal in acl_policy.remove:
        command.extend(["/remove:g", principal])
    for principal, rights in acl_policy.grants:
        command.extend(["/grant:r", f"{principal}:{rights}"])
    return command


def _default_runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, **kwargs)


def _run_icacls(command: Sequence[str], runner: Runner | None = None) -> subprocess.CompletedProcess[str]:
    run = runner or _default_runner
    return run(
        list(command),
        capture_output=True,
        text=True,
        creationflags=CREATE_NO_WINDOW,
        timeout=ACL_TIMEOUT_SEC,
        check=False,
    )


def _is_windows_or_injected(runner: Runner | None) -> bool:
    return sys.platform == "win32" or runner is not None


def _decode_output(result: subprocess.CompletedProcess[str]) -> str:
    stdout = result.stdout if isinstance(result.stdout, str) else ""
    stderr = result.stderr if isinstance(result.stderr, str) else ""
    return (stdout + "\n" + stderr).strip()


def _grant_visible(output: str, principal: str, rights: str) -> bool:
    """Best-effort policy check that tolerates localized account names."""
    sid = principal.lstrip("*")
    aliases = {
        "S-1-5-18": ("S-1-5-18", "SYSTEM", "NT AUTHORITY\\SYSTEM"),
        "S-1-5-20": ("S-1-5-20", "NETWORK SERVICE", "NT AUTHORITY\\NETWORK SERVICE"),
        "S-1-5-32-544": ("S-1-5-32-544", "Administrators", "BUILTIN\\Administrators"),
        "S-1-5-32-545": ("S-1-5-32-545", "Users", "BUILTIN\\Users"),
    }.get(sid, (sid,))
    upper = output.upper()
    return any(alias.upper() in upper for alias in aliases) and rights.upper() in upper


def check_acl(path: str | os.PathLike[str], acl_policy: AclPolicy | str,
              *, runner: Runner | None = None) -> AclResult:
    """Inspect current ACL text and report drift without changing it."""
    selected = policy(acl_policy) if isinstance(acl_policy, str) else acl_policy
    target = os.fspath(path)
    if not _is_windows_or_injected(runner):
        return AclResult(target, selected.name, compliant=False, skipped=True,
                         error="ACL checks require Windows")
    if not os.path.exists(target):
        return AclResult(target, selected.name, compliant=False,
                         error="path does not exist")
    try:
        result = _run_icacls(["icacls", target], runner)
    except (OSError, subprocess.SubprocessError) as exc:
        return AclResult(target, selected.name, compliant=False,
                         error=f"icacls check failed: {exc}")
    output = _decode_output(result)
    if result.returncode != 0:
        return AclResult(target, selected.name, compliant=False,
                         error=f"icacls returned {result.returncode}", output=output)
    compliant = all(_grant_visible(output, principal, rights)
                    for principal, rights in selected.grants)
    return AclResult(target, selected.name, compliant=compliant, output=output,
                     error=None if compliant else "ACL does not match policy")


def repair_acl(path: str | os.PathLike[str], acl_policy: AclPolicy | str,
               *, runner: Runner | None = None) -> AclResult:
    """Apply one ACL policy and return a structured failure instead of raising."""
    selected = policy(acl_policy) if isinstance(acl_policy, str) else acl_policy
    target = os.fspath(path)
    if not _is_windows_or_injected(runner):
        return AclResult(target, selected.name, compliant=False, skipped=True,
                         error="ACL repair requires Windows")
    if not os.path.exists(target):
        return AclResult(target, selected.name, compliant=False,
                         error="path does not exist")
    command = build_icacls_command(target, selected)
    try:
        result = _run_icacls(command, runner)
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("ACL repair failed policy=%s path=%s: %s", selected.name, target, exc)
        return AclResult(target, selected.name, compliant=False, error=str(exc))
    output = _decode_output(result)
    if result.returncode != 0:
        error = f"icacls returned {result.returncode}"
        log.warning("ACL repair failed policy=%s path=%s: %s", selected.name, target, error)
        return AclResult(target, selected.name, compliant=False, error=error, output=output)
    return AclResult(target, selected.name, compliant=True, changed=True, output=output)


def ensure_runtime_acls(paths: Mapping[str, str], *, repair: bool = True,
                        runner: Runner | None = None) -> list[AclResult]:
    """Check/repair the runtime trust boundaries used by the Windows agent.

    On Windows, missing directories are created before ACL application.  A
    caller decides whether a non-compliant result is fatal; the function never
    hides an ``icacls`` error.
    """
    if not _is_windows_or_injected(runner):
        return [AclResult("", "runtime", compliant=True, skipped=True)]

    targets: list[tuple[str, str, bool]] = []
    for key in ("security_dir", "spool_dir", "data_dir"):
        if paths.get(key):
            targets.append((paths[key], "service_data_dir", True))
    if paths.get("log_dir"):
        targets.append((paths["log_dir"], "log_dir", True))
    if paths.get("status_dir"):
        targets.append((paths["status_dir"], "status_dir", True))
    if paths.get("config_file"):
        targets.append((paths["config_file"], "config_file", False))
    if paths.get("response_dir"):
        targets.append((paths["response_dir"], "response_dir", True))

    results: list[AclResult] = []
    for target, policy_name, is_dir in targets:
        try:
            if is_dir:
                Path(target).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            results.append(AclResult(target, policy_name, compliant=False,
                                     error=f"cannot create ACL target: {exc}"))
            continue
        result = repair_acl(target, policy_name, runner=runner) if repair \
            else check_acl(target, policy_name, runner=runner)
        results.append(result)
    return results


def report_is_compliant(results: Iterable[AclResult]) -> bool:
    """Return false for errors, drift, or skipped checks."""
    return all(result.compliant and not result.skipped for result in results)
