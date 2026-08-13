"""Privacy-safe developer/AI attack-surface snapshot for Windows.

The section name and the seventeen capability/record-array pairs in this
module are a wire contract.  They intentionally retain the macOS capability
names (``launchd``, ``cron`` and ``homebrew``) while returning their closest
Windows equivalents.  This lets an existing manager and DeepMesh UI consume a
Windows snapshot without a platform-specific API.

No credential value or secret-bearing file content is collected.  Filesystem
and registry enumeration is bounded, external tools are trusted-path only,
and an unavailable optional product is represented by an empty capability.
"""
from __future__ import annotations

import json
import hashlib
import os
import queue
import re
import threading
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Iterable

from .base import WinBaseCollector
from .inventory import _native_scheduled_tasks
from .security_audit import (
    WindowsSecurityAuditCollector,
    _AI_RE,
    _PROFILE_SUSPICIOUS_RE,
    _bounded_text,
    _load_json_file,
    _redact_text,
    _sanitize_args,
    _strip_jsonc,
)

_MAX_ITEMS = 500
_MAX_FIELD = 2048
_MAX_SNAPSHOT = 6 * 1024 * 1024
_CAPABILITY_BUDGET = (_MAX_SNAPSHOT - (256 * 1024)) // 17
_COMMAND_TIMEOUT = 6
_MAX_PROFILE_COUNT = 64

# The manager's summary code counts these exact arrays.  Do not rename them.
DEVSEC_CAP_ITEM_KEYS: dict[str, str] = {
    "editor_extensions": "items",
    "mcp_servers": "servers",
    "browser_extensions": "items",
    "native_messaging": "items",
    "agent_cli_tools": "items",
    "ai_applications": "items",
    "listening_ports": "items",
    "processes": "items",
    "launchd": "items",
    "cron": "users",
    "shell_startup": "files",
    "node_packages": "users",
    "python_packages": "users",
    "homebrew": "formulae",
    "git": "users",
    "credential_locations": "users",
    "docker": "containers",
}
REQUIRED_CAPABILITIES = tuple(DEVSEC_CAP_ITEM_KEYS)

_DIRECT_SECRET_REPLACEMENTS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bsk-[a-z0-9_-]{4,}"),
    re.compile(r"(?i)\bgh[pousr]_[a-z0-9]{4,}"),
    re.compile(r"\bAKIA[A-Z0-9]{4,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
)
_ASSIGNED_SECRET = re.compile(
    r"(?i)(\b(?:password|passwd|token|api[-_]?key|secret|authorization)\b"
    r"\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;\]\}]+)"
)
_AGENT_COMMANDS = (
    "claude", "codex", "gemini", "aider", "ollama", "continue",
    "cline", "goose", "opencode", "fabric", "sgpt", "cursor", "code",
    "uv", "uvx", "npx", "pnpm", "bun", "docker",
)


def _redact_string(value: Any) -> str:
    """Redact common inline secrets, then apply the shared URL/argument scrubber."""
    # Text beyond the field limit is never emitted, so discard it before the
    # regex passes.  Most metadata values contain no sensitive marker; the
    # fast path avoids six regex scans for every ordinary path/name/version.
    text = str(value or "")[:_MAX_FIELD]
    lowered = text.casefold()
    if not any(marker in lowered for marker in (
        "sk-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "akia", "eyj",
        "password", "passwd", "token", "api_key", "api-key", "secret",
        "authorization", "bearer ", "://", "--api", "--auth",
    )):
        return text
    for pattern in _DIRECT_SECRET_REPLACEMENTS:
        text = pattern.sub("<redacted>", text)
    text = _ASSIGNED_SECRET.sub(r"\1<redacted>", text)
    return _redact_text(text, _MAX_FIELD)


def _bound_and_redact(value: Any) -> Any:
    """Recursively enforce list/field limits and remove inline secrets."""
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, bytes):
        return "<binary-not-collected>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_ITEMS:
                break
            result[str(key)[:256]] = _bound_and_redact(item)
        return result
    if isinstance(value, (list, tuple, set)):
        return [_bound_and_redact(item) for item in list(value)[:_MAX_ITEMS]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_string(value)


def _interesting(record: Any) -> bool:
    try:
        text = json.dumps(record, ensure_ascii=False, default=str)[:65536]
    except Exception:
        text = str(record)[:65536]
    return bool(_AI_RE.search(text))


def _mark_rows(rows: Iterable[Any]) -> list[Any]:
    marked: list[Any] = []
    for raw in list(rows)[:_MAX_ITEMS]:
        # The containing capability is already recursively bounded/redacted
        # by _part().  Do not repeat the expensive secret-regex pass here.
        row = raw
        if isinstance(row, dict):
            flag = _interesting(row)
            row.setdefault("interesting", flag)
            row.setdefault("flagged", flag)
        marked.append(row)
    return marked


def _path_under(path: Any, root: Path) -> bool:
    try:
        Path(str(path)).resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


class WinDeveloperSecurityCollector(WinBaseCollector):
    """Emit the DeepMesh developer-security contract for Windows."""

    name = "developer_security"
    # The section owns several bounded capabilities.  CLI calls inside it are
    # limited independently to six seconds.
    timeout = 150

    def __init__(
        self,
        profile_roots: Iterable[str | os.PathLike[str]] | None = None,
        *,
        audit: WindowsSecurityAuditCollector | None = None,
    ) -> None:
        self._audit = audit or WindowsSecurityAuditCollector(profile_roots)
        # Keep any nested CLI timeout below the outer six-second capability
        # boundary so the helper can return an empty/partial result cleanly.
        self._audit.timeout = min(3, _COMMAND_TIMEOUT)
        self._profile_roots = [Path(path) for path in profile_roots] if profile_roots else None
        self._profiles_cache: list[Path] = []
        self._issues: list[dict[str, str]] = []
        self._payload_pretrimmed = False

    def collect(self) -> dict[str, Any]:
        started = time.monotonic()
        self._issues = []
        self._payload_pretrimmed = False
        self._audit._deadline = started + max(1.0, float(self.timeout) - 3.0)
        self._audit._findings = []
        self._profiles_cache = self._profiles()

        builders: tuple[tuple[str, Callable[[], dict[str, Any]]], ...] = (
            ("editor_extensions", self._collect_editor_extensions),
            ("mcp_servers", self._collect_mcp_servers),
            ("browser_extensions", self._collect_browser_extensions),
            ("native_messaging", self._collect_native_messaging),
            ("agent_cli_tools", self._collect_agent_cli_tools),
            ("ai_applications", self._collect_ai_applications),
            ("listening_ports", self._collect_listening_ports),
            ("processes", self._collect_processes),
            ("launchd", self._collect_launchd),
            ("cron", self._collect_cron),
            ("shell_startup", self._collect_shell_startup),
            ("node_packages", self._collect_node_packages),
            ("python_packages", self._collect_python_packages),
            ("homebrew", self._collect_homebrew),
            ("git", self._collect_git),
            ("credential_locations", self._collect_credential_locations),
            ("docker", self._collect_docker),
        )
        errors: list[dict[str, str]] = []
        capabilities: dict[str, Any] = {}
        for capability, builder in builders:
            capabilities[capability] = self._part(capability, builder, errors)

        snapshot: dict[str, Any] = {
            "schema_version": 1,
            "platform": "windows",
            "scope": {
                "users": [path.name[:256] for path in self._profiles_cache][:_MAX_PROFILE_COUNT],
                "system_context": self._system_context(),
            },
            "privacy": {
                "secret_contents_collected": False,
                "credential_values_collected": False,
                "sensitive_values_redacted": True,
                "collection_scope": "metadata_and_paths_only",
            },
            "capabilities": capabilities,
            "collection": {
                "partial": bool(errors),
                "errors": errors,
                "issues": self._issues[:_MAX_ITEMS],
                "duration_ms": int((time.monotonic() - started) * 1000),
                "payload_truncated": self._payload_pretrimmed,
            },
        }
        self._refresh_counts(snapshot)
        self._trim_snapshot(snapshot)
        return snapshot

    def _part(
        self,
        capability: str,
        builder: Callable[[], dict[str, Any]],
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        try:
            # Filesystem and COM operations can block below Python (offline
            # redirected profiles, corrupt extension archives, provider
            # stalls).  Isolate every capability so one source cannot prevent
            # the other sixteen or the snapshot itself from being delivered.
            value = self._bounded_call(builder, _COMMAND_TIMEOUT)
            if not isinstance(value, dict):
                raise TypeError("capability collector must return a dict")
            key = DEVSEC_CAP_ITEM_KEYS[capability]
            if not isinstance(value.get(key), list):
                raise TypeError(f"capability record array {key!r} is missing")
            if self._encoded_size(value) > _CAPABILITY_BUDGET:
                self._shrink_lists_to_budget(value, _CAPABILITY_BUDGET)
                self._payload_pretrimmed = True
            # Redact only retained records.  This is both faster and avoids
            # processing unbounded attacker-controlled strings unnecessarily.
            value = _bound_and_redact(value)
            value[key] = _mark_rows(value[key])
            value["count"] = len(value[key])
            return value
        except Exception as exc:
            error = type(exc).__name__
            errors.append({"capability": capability, "error": error})
            return {"error": error}

    @staticmethod
    def _bounded_call(builder: Callable[[], Any], timeout: float = _COMMAND_TIMEOUT) -> Any:
        """Run a potentially blocking native API call behind a hard deadline."""
        result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                result.put_nowait((True, builder()))
            except BaseException as exc:  # propagated on the collection thread
                result.put_nowait((False, exc))

        worker = threading.Thread(target=invoke, daemon=True, name="devsec-native-api")
        worker.start()
        worker.join(max(0.1, float(timeout)))
        if worker.is_alive():
            raise TimeoutError("native API capability deadline exceeded")
        ok, value = result.get_nowait()
        if not ok:
            raise value
        return value

    def _profiles(self) -> list[Path]:
        if self._profile_roots is not None:
            return [path for path in self._profile_roots if self._safe_is_dir(path)][:_MAX_PROFILE_COUNT]
        excluded = {
            "default", "default user", "public", "all users",
            "defaultapppool", "systemprofile", "localservice", "networkservice",
        }
        return [
            path for path in self._audit._profiles()
            if path.name.casefold() not in excluded
        ][:_MAX_PROFILE_COUNT]

    @staticmethod
    def _safe_is_dir(path: Path) -> bool:
        try:
            return path.is_dir()
        except OSError:
            return False

    @staticmethod
    def _system_context() -> bool:
        username = str(os.environ.get("USERNAME") or os.environ.get("USER") or "")
        try:
            import win32api

            username = str(win32api.GetUserName() or username)
        except Exception:
            pass
        normalized = username.rsplit("\\", 1)[-1].strip().casefold()
        return normalized in {"system", "local system", "localsystem"}

    def _collect_editor_extensions(self) -> dict[str, Any]:
        return {"items": self._audit._ide_extensions(self._profiles_cache)}

    def _collect_mcp_servers(self) -> dict[str, Any]:
        servers: list[dict[str, Any]] = []
        config_files: list[dict[str, Any]] = []
        candidates: dict[str, Path] = {}
        for profile in self._profiles_cache:
            roaming = profile / "AppData" / "Roaming"
            known = (
                roaming / "Claude" / "claude_desktop_config.json",
                roaming / "Cursor" / "User" / "settings.json",
                roaming / "Cursor" / "User" / "mcp.json",
                roaming / "Code" / "User" / "settings.json",
                roaming / "Code" / "User" / "mcp.json",
                roaming / "Windsurf" / "User" / "settings.json",
                roaming / "Windsurf" / "User" / "mcp.json",
                profile / ".cursor" / "mcp.json",
                profile / ".vscode" / "mcp.json",
                profile / ".windsurf" / "mcp.json",
                profile / ".continue" / "config.json",
                profile / ".continue" / "config.yaml",
                profile / ".continue" / "config.yml",
                profile / ".codeium" / "windsurf" / "mcp_config.json",
                profile / ".claude.json",
                profile / ".claude" / "settings.json",
                profile / ".codex" / "config.toml",
                profile / ".config" / "mcp.json",
                profile / ".config" / "continue" / "config.yaml",
            )
            for editor in ("Code", "Cursor", "Windsurf"):
                storage = roaming / editor / "User" / "globalStorage"
                known += (
                    storage / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
                    storage / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
                )
            for path in known:
                if self._audit._path_is_file(path):
                    candidates.setdefault(os.path.normcase(str(path)), path)
            for root in (
                profile / "source", profile / "src", profile / "repos",
                profile / "projects", profile / "workspace", profile / "workspaces",
                profile / "Documents", profile / "Desktop",
            ):
                # Probe the conventional root and at most 128 immediate
                # repository children.  This finds projects/demo/.mcp.json
                # without an unbounded recursive walk through vendor trees or
                # redirected folders while the service runs as SYSTEM.
                repositories = [root]
                try:
                    repositories.extend(
                        child for child in list(root.iterdir())[:128]
                        if child.is_dir()
                    )
                except OSError:
                    pass
                for repository in repositories:
                    for relative in (
                        ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json",
                        ".windsurf/mcp.json", ".claude/settings.json",
                        ".codex/config.toml",
                    ):
                        path = repository / Path(relative)
                        if self._audit._path_is_file(path):
                            candidates.setdefault(os.path.normcase(str(path)), path)
        for path in list(candidates.values())[:_MAX_ITEMS]:
            text = _bounded_text(path)
            if not text:
                config_files.append({"path": str(path), "status": "unreadable_or_oversized"})
                continue
            maps: list[dict[str, Any]] = []
            status = "invalid"
            try:
                if path.suffix.casefold() in {".json", ".jsonc"}:
                    parsed = json.loads(_strip_jsonc(text))
                elif path.suffix.casefold() == ".toml":
                    import tomllib

                    parsed = tomllib.loads(text)
                elif path.suffix.casefold() in {".yaml", ".yml"}:
                    try:
                        import yaml

                        try:
                            parsed = yaml.safe_load(text) or {}
                        except yaml.YAMLError:
                            parsed = {}
                    except ImportError:
                        parsed = {}
                else:
                    parsed = {}
                maps = self._audit._find_mcp_maps(parsed)
                status = "parsed"
            except (ValueError, TypeError, json.JSONDecodeError):
                pass
            if not maps and not re.search(r"mcpServers|mcp[-_]server", text, re.I):
                continue
            config_files.append({
                "path": str(path), "status": status,
                "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
            })
            for mapping in maps:
                for name, raw in list(mapping.items())[:_MAX_ITEMS]:
                    cfg = raw if isinstance(raw, dict) else {}
                    environment = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
                    servers.append({
                        "name": str(name),
                        "command": cfg.get("command"),
                        "args": _sanitize_args(cfg.get("args")),
                        "env_names": sorted(str(key) for key in environment)[:128],
                        "cwd": cfg.get("cwd"),
                        "transport": cfg.get("transport") or cfg.get("type") or "stdio",
                        "source": str(path),
                    })
                    if len(servers) >= _MAX_ITEMS:
                        break
        return {"servers": servers[:_MAX_ITEMS], "config_files": config_files[:_MAX_ITEMS]}

    def _collect_browser_extensions(self) -> dict[str, Any]:
        rows = list(self._audit._browser_extensions(self._profiles_cache))
        rows.extend(self._firefox_extensions(_MAX_ITEMS - len(rows)))
        return {"items": rows[:_MAX_ITEMS]}

    def _firefox_extensions(self, remaining: int) -> list[dict[str, Any]]:
        if remaining <= 0:
            return []
        rows: list[dict[str, Any]] = []
        for profile in self._profiles_cache:
            roots = (
                profile / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
                profile / "AppData" / "Local" / "Mozilla" / "Firefox" / "Profiles",
            )
            for root in roots:
                try:
                    firefox_profiles = [path for path in root.iterdir() if path.is_dir()][:64]
                except OSError:
                    continue
                for firefox_profile in firefox_profiles:
                    extensions = firefox_profile / "extensions"
                    try:
                        candidates = list(extensions.iterdir())[:remaining - len(rows)]
                    except OSError:
                        continue
                    for candidate in candidates:
                        manifest: dict[str, Any] | None = None
                        try:
                            if candidate.is_dir():
                                raw = _load_json_file(candidate / "manifest.json")
                                manifest = raw if isinstance(raw, dict) else None
                            elif candidate.suffix.casefold() == ".xpi" and candidate.stat().st_size <= 64 * 1024 * 1024:
                                with zipfile.ZipFile(candidate) as archive:
                                    info = archive.getinfo("manifest.json")
                                    if info.file_size <= 1024 * 1024:
                                        raw = json.loads(archive.read(info).decode("utf-8-sig", errors="replace"))
                                        manifest = raw if isinstance(raw, dict) else None
                        except (OSError, KeyError, ValueError, zipfile.BadZipFile):
                            continue
                        if not manifest:
                            continue
                        gecko = manifest.get("browser_specific_settings") or manifest.get("applications") or {}
                        gecko = gecko.get("gecko", {}) if isinstance(gecko, dict) else {}
                        extension_id = str(gecko.get("id") or candidate.stem)
                        permissions = [str(item) for item in manifest.get("permissions", []) if item]
                        rows.append({
                            "browser": "firefox",
                            "browser_profile": firefox_profile.name,
                            "extension_id": extension_id,
                            "name": str(manifest.get("name") or extension_id),
                            "version": str(manifest.get("version") or "") or None,
                            "permissions": permissions[:128],
                            "path": str(candidate),
                        })
                        if len(rows) >= remaining:
                            return rows
        return rows

    def _collect_native_messaging(self) -> dict[str, Any]:
        rows = list(self._audit._native_messaging_hosts())
        rows.extend(self._native_manifest_files(_MAX_ITEMS - len(rows)))
        return {"items": self._dedupe(rows, ("browser", "name", "manifest"))}

    def _native_manifest_files(self, remaining: int) -> list[dict[str, Any]]:
        if remaining <= 0:
            return []
        roots: list[tuple[str, str, Path]] = []
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        roots.extend((
            ("chrome", "machine_file", program_data / "Google" / "Chrome" / "NativeMessagingHosts"),
            ("edge", "machine_file", program_data / "Microsoft" / "Edge" / "NativeMessagingHosts"),
            ("firefox", "machine_file", program_data / "Mozilla" / "NativeMessagingHosts"),
        ))
        for profile in self._profiles_cache:
            roots.extend((
                ("chrome", profile.name, profile / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "NativeMessagingHosts"),
                ("edge", profile.name, profile / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "NativeMessagingHosts"),
                ("firefox", profile.name, profile / "AppData" / "Roaming" / "Mozilla" / "NativeMessagingHosts"),
            ))
        rows: list[dict[str, Any]] = []
        for browser, scope, root in roots:
            try:
                manifests = list(root.glob("*.json"))[:remaining - len(rows)]
            except OSError:
                continue
            for manifest in manifests:
                try:
                    data = _load_json_file(manifest)
                    if not isinstance(data, dict):
                        continue
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
                rows.append({
                    "browser": browser,
                    "scope": scope,
                    "name": str(data.get("name") or manifest.stem),
                    "manifest": str(manifest),
                    "executable": data.get("path"),
                    "allowed_origins": data.get("allowed_origins", []),
                    "allowed_extensions": data.get("allowed_extensions", []),
                    "status": "parsed",
                })
                if len(rows) >= remaining:
                    return rows
        return rows

    def _collect_agent_cli_tools(self) -> dict[str, Any]:
        path_entries = self._fast_path_entries()
        matches: dict[str, list[str]] = {command: [] for command in _AGENT_COMMANDS}
        wanted = {
            command + suffix: command
            for command in _AGENT_COMMANDS
            for suffix in (".exe", ".com", ".cmd", ".bat", ".ps1", "")
        }
        seen_dirs: set[str] = set()
        for raw in path_entries[:256]:
            expanded = os.path.expandvars(str(raw).strip().strip('"'))
            if not expanded or not os.path.isabs(expanded) or expanded.startswith(("\\\\", "//")):
                continue
            normalized_dir = os.path.normcase(os.path.normpath(expanded))
            if normalized_dir in seen_dirs:
                continue
            seen_dirs.add(normalized_dir)
            try:
                with os.scandir(expanded) as iterator:
                    for entry in iterator:
                        command = wanted.get(entry.name.casefold())
                        if command is None:
                            continue
                        path = os.path.join(expanded, entry.name)
                        if path not in matches[command] and len(matches[command]) < 32:
                            matches[command].append(path)
            except OSError:
                continue
        return {"items": [
            {
                "command": command, "paths": paths,
                "shadowed": len(paths) > 1, "executed": False,
            }
            for command, paths in matches.items() if paths
        ]}

    def _fast_path_entries(self) -> list[str]:
        values = [item for item in os.environ.get("PATH", "").split(os.pathsep) if item]
        try:
            import winreg

            roots: list[tuple[Any, str]] = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
                (winreg.HKEY_CURRENT_USER, r"Environment"),
            ]
            roots.extend(
                (winreg.HKEY_USERS, sid + r"\Environment")
                for sid in self._audit._loaded_user_sids(winreg)
            )
            for hive, path in roots:
                try:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                        raw, _ = winreg.QueryValueEx(key, "Path")
                    values.extend(item for item in str(raw).split(";") if item)
                except OSError:
                    continue
        except ImportError:
            pass
        for profile in self._profiles_cache:
            values.extend(str(path) for path in (
                profile / "AppData" / "Roaming" / "npm",
                profile / ".local" / "bin",
                profile / ".cargo" / "bin",
                profile / ".bun" / "bin",
                profile / "scoop" / "shims",
                profile / "AppData" / "Local" / "Programs" / "Ollama",
                profile / "AppData" / "Local" / "Programs" / "Microsoft VS Code" / "bin",
                profile / "AppData" / "Local" / "Programs" / "Cursor" / "resources" / "app" / "bin",
            ))
        return values[:1000]

    def _collect_ai_applications(self) -> dict[str, Any]:
        rows = [
            row for row in self._audit._relevant_applications()
            if _interesting(row)
        ]
        for profile in self._profiles_cache:
            programs = profile / "AppData" / "Local" / "Programs"
            try:
                candidates = list(programs.iterdir())[:_MAX_ITEMS]
            except OSError:
                continue
            for path in candidates:
                if _AI_RE.search(path.name):
                    rows.append({
                        "name": path.name,
                        "version": None,
                        "publisher": None,
                        "install_location": str(path),
                        "source": "local_programs",
                    })
        return {"items": self._dedupe(rows, ("name", "install_location"))}

    def _collect_listening_ports(self) -> dict[str, Any]:
        return {"items": self._audit._listeners()}

    def _collect_processes(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
            invalid = ctypes.c_void_p(-1).value
            if snapshot == invalid:
                return {"items": rows}
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            try:
                available = bool(kernel32.Process32FirstW(snapshot, ctypes.byref(entry)))
                while available and len(rows) < _MAX_ITEMS:
                    name = str(entry.szExeFile or "")
                    if _AI_RE.search(name) or re.search(r"(?:mcp|agent)", name, re.I):
                        rows.append({
                            "pid": int(entry.th32ProcessID),
                            "ppid": int(entry.th32ParentProcessID),
                            "name": name,
                            "user": None,
                            "path": None,
                            "command_line": None,
                        })
                    available = bool(kernel32.Process32NextW(snapshot, ctypes.byref(entry)))
            finally:
                kernel32.CloseHandle(snapshot)
        except (ImportError, AttributeError, OSError):
            # Toolhelp32 is unavailable only on non-Windows source test hosts.
            # Feature absence is represented by an empty capability.
            return {"items": rows}
        return {"items": rows[:_MAX_ITEMS]}

    def _collect_launchd(self) -> dict[str, Any]:
        """Return Windows Run/RunOnce, Startup-folder and Winlogon entries."""
        rows = self._run_registry_entries()
        rows.extend(self._startup_folder_entries(_MAX_ITEMS - len(rows)))
        return {"items": rows[:_MAX_ITEMS]}

    def _run_registry_entries(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        try:
            import winreg
        except ImportError:
            return rows
        roots: list[tuple[Any, str, str]] = []
        for suffix in ("Run", "RunOnce"):
            path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\{suffix}"
            roots.extend((
                (winreg.HKEY_LOCAL_MACHINE, path, f"machine:{suffix}"),
                (winreg.HKEY_CURRENT_USER, path, f"current_user:{suffix}"),
            ))
            roots.extend(
                (winreg.HKEY_USERS, sid + "\\" + path, f"user:{sid}:{suffix}")
                for sid in self._audit._loaded_user_sids(winreg)
            )
        winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        roots.append((winreg.HKEY_LOCAL_MACHINE, winlogon, "machine:Winlogon"))
        views = (
            ("64", getattr(winreg, "KEY_WOW64_64KEY", 0)),
            ("32", getattr(winreg, "KEY_WOW64_32KEY", 0)),
        )
        for hive, path, scope in roots:
            for view_name, view in views:
                try:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
                        index = 0
                        while len(rows) < _MAX_ITEMS:
                            try:
                                name, value, _ = winreg.EnumValue(key, index)
                                index += 1
                            except OSError:
                                break
                            if scope.endswith("Winlogon") and str(name).casefold() not in {
                                "shell", "userinit", "notify",
                            }:
                                continue
                            rows.append({
                                "name": str(name),
                                "command": value,
                                "location": path,
                                "scope": scope,
                                "registry_view": view_name,
                            })
                except OSError:
                    continue
        return rows

    def _startup_folder_entries(self, remaining: int) -> list[dict[str, Any]]:
        if remaining <= 0:
            return []
        folders: list[tuple[str, Path]] = [(
            "all_users",
            Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
            / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        )]
        folders.extend((
            profile.name,
            profile / "AppData" / "Roaming" / "Microsoft" / "Windows"
            / "Start Menu" / "Programs" / "Startup",
        ) for profile in self._profiles_cache)
        rows: list[dict[str, Any]] = []
        for user, folder in folders:
            try:
                entries = list(folder.iterdir())[:remaining - len(rows)]
            except OSError:
                continue
            for entry in entries:
                rows.append({
                    "name": entry.name,
                    "command": None,
                    "location": str(folder),
                    "scope": f"startup_folder:{user}",
                    "path": str(entry),
                })
                if len(rows) >= remaining:
                    return rows
        return rows

    def _collect_cron(self) -> dict[str, Any]:
        tasks = self._scheduled_task_files()
        groups: dict[str, list[dict[str, Any]]] = {}
        for task in tasks:
            user = str(task.get("user") or "system_or_unspecified")
            groups.setdefault(user, []).append(task)
        users = [
            {"user": user, "items": items[:_MAX_ITEMS]}
            for user, items in sorted(groups.items())
        ]
        return {"users": users[:_MAX_ITEMS]}

    def _scheduled_task_files(self) -> list[dict[str, Any]]:
        # Prefer Task Scheduler's native metadata.  Opening and parsing every
        # task XML file can consume the entire six-second capability budget
        # under LocalSystem, which can read many more protected task files
        # than an interactive user.  Keep the XML path as a source/test-host
        # fallback when COM is unavailable.
        try:
            return list(_native_scheduled_tasks())[:_MAX_ITEMS]
        except Exception:
            pass

        root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        if not self._safe_is_dir(root):
            # Source-only test hosts may not expose the Windows Tasks folder.
            return []
        rows: list[dict[str, Any]] = []
        try:
            walker = os.walk(root, topdown=True, followlinks=False)
            for current, directories, files in walker:
                directories[:] = directories[:128]
                for name in files:
                    path = Path(current) / name
                    text = _bounded_text(path)
                    if not text:
                        continue
                    try:
                        task = ET.fromstring(text)
                    except ET.ParseError:
                        continue
                    fields: dict[str, list[str]] = {}
                    for node in task.iter():
                        label = node.tag.rsplit("}", 1)[-1]
                        if node.text and node.text.strip():
                            fields.setdefault(label, []).append(node.text.strip())
                    commands = fields.get("Command", [])
                    arguments = fields.get("Arguments", [])
                    rows.append({
                        "name": "\\" + str(path.relative_to(root)).replace(os.sep, "\\"),
                        "type": "schtasks",
                        "schedule": ",".join(fields.get("StartBoundary", [])[:8]) or None,
                        "command": " ; ".join(
                            f"{command} {arguments[index] if index < len(arguments) else ''}".strip()
                            for index, command in enumerate(commands[:16])
                        ) or None,
                        "user": (fields.get("UserId") or fields.get("GroupId") or [None])[0],
                        "enabled": str((fields.get("Enabled") or ["true"])[0]).casefold() != "false",
                    })
                    if len(rows) >= _MAX_ITEMS:
                        return rows
        except OSError:
            return rows
        return rows

    def _collect_shell_startup(self) -> dict[str, Any]:
        files = self._powershell_profile_files()
        files.extend(self._cmd_autorun_entries(_MAX_ITEMS - len(files)))
        return {"files": files[:_MAX_ITEMS]}

    def _powershell_profile_files(self) -> list[dict[str, Any]]:
        candidates: list[Path] = []
        for profile in self._profiles_cache:
            for folder in (
                profile / "Documents" / "WindowsPowerShell",
                profile / "Documents" / "PowerShell",
            ):
                candidates.extend((
                    folder / "profile.ps1",
                    folder / "Microsoft.PowerShell_profile.ps1",
                ))
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        candidates.extend((
            system_root / "System32" / "WindowsPowerShell" / "v1.0" / "profile.ps1",
            system_root / "System32" / "WindowsPowerShell" / "v1.0" / "Microsoft.PowerShell_profile.ps1",
        ))
        rows: list[dict[str, Any]] = []
        for path in candidates[:_MAX_ITEMS]:
            text = _bounded_text(path)
            if not text:
                continue
            rows.append({
                "path": str(path),
                "size": len(text.encode("utf-8", errors="replace")),
                "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
                "risk_signals": sorted(
                    name for name, pattern in _PROFILE_SUSPICIOUS_RE.items()
                    if pattern.search(text)
                ),
                "content_collected": False,
            })
        return rows

    def _cmd_autorun_entries(self, remaining: int) -> list[dict[str, Any]]:
        if remaining <= 0:
            return []
        try:
            import winreg
        except ImportError:
            return []
        path = r"SOFTWARE\Microsoft\Command Processor"
        roots: list[tuple[Any, str, str]] = [
            (winreg.HKEY_LOCAL_MACHINE, path, "machine"),
            (winreg.HKEY_CURRENT_USER, path, "current_user"),
        ]
        roots.extend(
            (winreg.HKEY_USERS, sid + "\\" + path, f"user:{sid}")
            for sid in self._audit._loaded_user_sids(winreg)
        )
        rows: list[dict[str, Any]] = []
        for scope, view in (("64", getattr(winreg, "KEY_WOW64_64KEY", 0)), ("32", getattr(winreg, "KEY_WOW64_32KEY", 0))):
            for hive, root, owner in roots:
                try:
                    with winreg.OpenKey(hive, root, 0, winreg.KEY_READ | view) as key:
                        command, _ = winreg.QueryValueEx(key, "AutoRun")
                    rows.append({
                        "path": f"registry:{owner}:{root}:AutoRun",
                        "kind": "cmd_autorun",
                        "registry_view": scope,
                        "command": command,
                    })
                except OSError:
                    continue
                if len(rows) >= remaining:
                    return rows
        return rows

    def _collect_node_packages(self) -> dict[str, Any]:
        groups: list[dict[str, Any]] = []
        roots: list[tuple[str, str, Path]] = []
        for profile in self._profiles_cache:
            roots.extend((
                (profile.name, "npm", profile / "AppData" / "Roaming" / "npm" / "node_modules"),
                (profile.name, "yarn", profile / "AppData" / "Local" / "Yarn" / "Data" / "global" / "node_modules"),
                (profile.name, "bun", profile / ".bun" / "install" / "global" / "node_modules"),
            ))
            pnpm_global = profile / "AppData" / "Local" / "pnpm" / "global"
            try:
                roots.extend(
                    (profile.name, "pnpm", version / "node_modules")
                    for version in list(pnpm_global.iterdir())[:32]
                    if version.is_dir()
                )
            except OSError:
                pass
        for environment in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            base = os.environ.get(environment)
            if base:
                roots.extend((
                    ("system", "npm", Path(base) / "nodejs" / "node_modules"),
                    ("system", "npm", Path(base) / "npm" / "node_modules"),
                ))
        by_user: dict[str, list[dict[str, Any]]] = {}
        for user, manager, root in roots:
            for package in self._node_package_dirs(root, _MAX_ITEMS - sum(map(len, by_user.values()))):
                name = package.name
                if package.parent.name.startswith("@"):
                    name = f"{package.parent.name}/{package.name}"
                version = None
                manifest = package / "package.json"
                text = _bounded_text(manifest, 256 * 1024)
                if text:
                    try:
                        data = json.loads(_strip_jsonc(text))
                        name = str(data.get("name") or name)
                        version = str(data.get("version") or "") or None
                    except (ValueError, json.JSONDecodeError, AttributeError):
                        pass
                by_user.setdefault(user, []).append({
                    "manager": manager, "name": name, "version": version,
                    "path": str(package), "ai_related": bool(_AI_RE.search(name)),
                })
        for user, packages in by_user.items():
            configs = []
            profile = next((path for path in self._profiles_cache if path.name == user), None)
            if profile:
                for path in (profile / ".npmrc", profile / ".yarnrc", profile / ".pnpmrc"):
                    if self._audit._path_is_file(path):
                        configs.append({"path": str(path), "content_collected": False})
            groups.append({"user": user, "packages": packages[:_MAX_ITEMS], "configs": configs})
        return {"users": groups[:_MAX_ITEMS]}

    @staticmethod
    def _node_package_dirs(root: Path, remaining: int) -> list[Path]:
        if remaining <= 0:
            return []
        found: list[Path] = []
        try:
            entries = list(root.iterdir())[:remaining]
        except OSError:
            return found
        for entry in entries:
            if entry.name.startswith("@"):
                try:
                    found.extend(path for path in list(entry.iterdir())[:remaining - len(found)] if path.is_dir())
                except OSError:
                    continue
            elif entry.is_dir():
                found.append(entry)
            if len(found) >= remaining:
                break
        return found

    def _collect_python_packages(self) -> dict[str, Any]:
        roots: list[tuple[str, Path, Path]] = []
        for profile in self._profiles_cache:
            for base in (
                profile / "AppData" / "Local" / "Programs" / "Python",
                profile / "AppData" / "Roaming" / "Python",
            ):
                try:
                    versions = [path for path in base.iterdir() if path.name.startswith("Python")][:32]
                except OSError:
                    continue
                for version in versions:
                    for site in (version / "Lib" / "site-packages", version / "site-packages"):
                        if self._safe_is_dir(site):
                            roots.append((profile.name, version, site))
        for environment in ("ProgramFiles", "ProgramFiles(x86)"):
            base_raw = os.environ.get(environment)
            if not base_raw:
                continue
            try:
                versions = list(Path(base_raw).glob("Python*"))[:32]
            except OSError:
                continue
            for version in versions:
                site = version / "Lib" / "site-packages"
                if self._safe_is_dir(site):
                    roots.append(("system", version, site))
        by_user: dict[str, dict[str, Any]] = {}
        remaining = _MAX_ITEMS
        for user, version, site in roots:
            group = by_user.setdefault(user, {
                "user": user, "packages": [], "configs": [], "interpreters": [],
            })
            interpreter = version / "python.exe"
            hint = {"path": str(interpreter), "version_hint": version.name, "executed": False}
            if hint not in group["interpreters"]:
                group["interpreters"].append(hint)
            try:
                distributions = list(site.glob("*.dist-info"))[:remaining]
            except OSError:
                continue
            for distribution in distributions:
                stem = distribution.name[:-10]
                name, separator, version_text = stem.rpartition("-")
                if not separator:
                    name, version_text = stem, ""
                group["packages"].append({
                    "manager": "pip", "name": name.replace("_", "-"),
                    "version": version_text or None, "path": str(distribution),
                    "ai_related": bool(_AI_RE.search(name)),
                })
                remaining -= 1
                if remaining <= 0:
                    break
            if remaining <= 0:
                break
        return {"users": list(by_user.values())[:_MAX_ITEMS]}

    def _group_by_profile(
        self,
        records: Iterable[dict[str, Any]],
        item_key: str,
        configs: Iterable[dict[str, Any]] = (),
    ) -> list[dict[str, Any]]:
        groups: dict[str, dict[str, Any]] = {}
        for record in list(records)[:_MAX_ITEMS]:
            owner = "system"
            path = (
                record.get("path") or record.get("root")
                if isinstance(record, dict) else None
            )
            for profile in self._profiles_cache:
                if path and _path_under(path, profile):
                    owner = profile.name
                    break
            group = groups.setdefault(owner, {"user": owner, item_key: [], "configs": []})
            group[item_key].append(record)
        for config in list(configs)[:_MAX_ITEMS]:
            owner = "system"
            path = config.get("path") if isinstance(config, dict) else None
            for profile in self._profiles_cache:
                if path and _path_under(path, profile):
                    owner = profile.name
                    break
            group = groups.setdefault(owner, {"user": owner, item_key: [], "configs": []})
            group["configs"].append(config)
        return list(groups.values())[:_MAX_ITEMS]

    def _collect_homebrew(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        rows.extend(self._chocolatey_packages(_MAX_ITEMS))
        rows.extend(self._scoop_packages(_MAX_ITEMS - len(rows)))
        rows.extend(self._winget_packages(_MAX_ITEMS - len(rows)))
        return {"formulae": rows[:_MAX_ITEMS], "casks": []}

    def _chocolatey_packages(self, remaining: int) -> list[dict[str, Any]]:
        root = Path(os.environ.get("ChocolateyInstall", r"C:\ProgramData\chocolatey")) / "lib"
        try:
            packages = list(root.iterdir())[:remaining]
        except OSError:
            return []
        rows = []
        for package in packages:
            if not package.is_dir():
                continue
            name = package.name
            version = None
            try:
                nuspecs = list(package.glob("*.nuspec"))[:1]
            except OSError:
                nuspecs = []
            if nuspecs:
                try:
                    if nuspecs[0].stat().st_size <= 1024 * 1024:
                        root_node = ET.parse(nuspecs[0]).getroot()
                        for node in root_node.iter():
                            label = node.tag.rsplit("}", 1)[-1].casefold()
                            if label == "id" and node.text:
                                name = node.text.strip()
                            elif label == "version" and node.text:
                                version = node.text.strip()
                except (OSError, ET.ParseError):
                    pass
            rows.append({
                "manager": "choco", "name": name,
                "version": version, "path": str(package),
            })
        return rows

    def _scoop_packages(self, remaining: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for profile in self._profiles_cache:
            root = profile / "scoop" / "apps"
            try:
                packages = list(root.iterdir())[:remaining - len(rows)]
            except OSError:
                continue
            for package in packages:
                if not package.is_dir():
                    continue
                version = None
                current = package / "current"
                try:
                    if current.exists():
                        version = current.resolve(strict=False).name
                except OSError:
                    pass
                rows.append({
                    "manager": "scoop", "name": package.name,
                    "version": version, "path": str(package), "user": profile.name,
                })
        return rows

    def _winget_packages(self, remaining: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for profile in self._profiles_cache:
            root = profile / "AppData" / "Local" / "Microsoft" / "WinGet" / "Packages"
            try:
                packages = list(root.iterdir())[:remaining - len(rows)]
            except OSError:
                continue
            for package in packages:
                if package.is_dir():
                    rows.append({
                        "manager": "winget", "name": package.name,
                        "version": None, "path": str(package), "user": profile.name,
                    })
        return rows

    def _collect_git(self) -> dict[str, Any]:
        users: list[dict[str, Any]] = []
        for profile in self._profiles_cache:
            items: list[dict[str, Any]] = []
            for path in (profile / ".gitconfig", profile / ".config" / "git" / "config"):
                text = _bounded_text(path, 1024 * 1024)
                if not text:
                    continue
                items.append({
                    "path": str(path),
                    "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
                    "settings": self._audit._parse_git_config(text),
                    "content_collected": False,
                })
            users.append({"user": profile.name, "items": items})
        system_items: list[dict[str, Any]] = []
        for path in (
            Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Git" / "config",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "etc" / "gitconfig",
        ):
            text = _bounded_text(path, 1024 * 1024)
            if text:
                system_items.append({
                    "path": str(path),
                    "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
                    "settings": self._audit._parse_git_config(text),
                    "content_collected": False,
                })
        if system_items:
            users.append({"user": "system", "items": system_items})
        return {"users": users[:_MAX_ITEMS]}

    def _collect_credential_locations(self) -> dict[str, Any]:
        users: list[dict[str, Any]] = []
        for profile in self._profiles_cache:
            locations: list[dict[str, Any]] = []
            direct = (
                profile / ".env",
                profile / ".env.local",
                profile / ".npmrc",
                profile / ".git-credentials",
                profile / ".aws" / "credentials",
                profile / ".netrc",
            )
            for path in direct:
                if self._audit._path_is_file(path):
                    locations.append(self._credential_path(path))
            ssh = profile / ".ssh"
            try:
                ssh_files = [path for path in ssh.iterdir() if path.is_file()][:_MAX_ITEMS]
            except OSError:
                ssh_files = []
            locations.extend(self._credential_path(path) for path in ssh_files)
            remaining = _MAX_ITEMS - len(locations)
            if remaining > 0:
                locations.extend(self._project_env_locations(profile, remaining))
            if locations:
                users.append({
                    "user": profile.name,
                    "locations": locations[:_MAX_ITEMS],
                    "credential_values_collected": False,
                })
        return {"users": users[:_MAX_ITEMS]}

    def _project_env_locations(self, profile: Path, remaining: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        roots = (
            profile / "source", profile / "src", profile / "repos",
            profile / "projects", profile / "workspace", profile / "workspaces",
            profile / "Documents", profile / "Desktop",
        )
        for root in roots:
            if not self._safe_is_dir(root):
                continue
            base_depth = len(root.parts)
            visited = 0
            try:
                for current, directories, files in os.walk(root, topdown=True, followlinks=False):
                    visited += 1
                    current_path = Path(current)
                    depth = len(current_path.parts) - base_depth
                    directories[:] = [
                        name for name in directories
                        if name not in {".git", "node_modules", ".venv", "venv", "dist", "build"}
                    ]
                    if depth >= 4:
                        directories[:] = []
                    for name in files:
                        if name == ".env" or name.startswith(".env."):
                            rows.append(self._credential_path(current_path / name))
                            if len(rows) >= remaining:
                                return rows
                    if visited >= 1500:
                        break
            except OSError:
                continue
        return rows

    def _credential_path(self, path: Path) -> dict[str, Any]:
        return {
            "path": str(path),
            "name": path.name,
            "size": self._audit._size(path),
            "modified_at": self._audit._mtime(path),
            "content_collected": False,
        }

    def _collect_docker(self) -> dict[str, Any]:
        docker = self._audit._trusted_docker()
        daemon_process = False
        try:
            import psutil

            for process in psutil.process_iter(["name"]):
                name = str(process.info.get("name") or "").casefold()
                if name in {"docker desktop.exe", "com.docker.backend.exe", "dockerd.exe"}:
                    daemon_process = True
                    break
        except Exception:
            daemon_process = False
        if not docker or not daemon_process or not self._docker_daemon_pipe():
            return {
                "installed": bool(docker), "running": False,
                "client": str(docker) if docker else None,
                "containers": [], "images": [],
            }
        value = self._audit._docker_audit()
        return {
            "installed": bool(value.get("available")),
            "running": bool(value.get("daemon_reachable")),
            "client": value.get("client"),
            "containers": value.get("containers", []),
            "images": value.get("images", [])[:_MAX_ITEMS],
        }

    @staticmethod
    def _docker_daemon_pipe() -> bool:
        try:
            import ctypes

            # Zero timeout: feature detection only; never wait for a daemon.
            return bool(ctypes.windll.kernel32.WaitNamedPipeW(
                r"\\.\pipe\docker_engine", 0,
            ))
        except (AttributeError, OSError):
            return False

    @staticmethod
    def _dedupe(rows: Iterable[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, ...]] = set()
        for row in rows:
            identity = tuple(str(row.get(key) or "").casefold() for key in keys)
            if identity in seen:
                continue
            seen.add(identity)
            result.append(row)
            if len(result) >= _MAX_ITEMS:
                break
        return result

    @staticmethod
    def _refresh_counts(snapshot: dict[str, Any]) -> None:
        capabilities = snapshot.get("capabilities", {})
        if not isinstance(capabilities, dict):
            return
        for capability, key in DEVSEC_CAP_ITEM_KEYS.items():
            value = capabilities.get(capability)
            if isinstance(value, dict) and "error" not in value:
                rows = value.get(key)
                value["count"] = len(rows) if isinstance(rows, list) else 0

    @staticmethod
    def _encoded_size(value: Any) -> int:
        return len(json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), default=str,
        ).encode("utf-8"))

    @classmethod
    def _shrink_lists_to_budget(cls, value: Any, budget: int) -> None:
        def halve_lists(node: Any) -> bool:
            changed = False
            if isinstance(node, dict):
                for item in node.values():
                    changed = halve_lists(item) or changed
            elif isinstance(node, list):
                for item in node:
                    changed = halve_lists(item) or changed
                if len(node) > 1:
                    del node[(len(node) + 1) // 2:]
                    changed = True
            return changed

        for _ in range(12):
            if cls._encoded_size(value) <= budget:
                return
            if not halve_lists(value):
                return

    def _trim_snapshot(self, snapshot: dict[str, Any]) -> None:
        if self._encoded_size(snapshot) <= _MAX_SNAPSHOT:
            return
        snapshot["collection"]["payload_truncated"] = True

        # Halve every nested list on each pass.  This is deterministic, keeps
        # all 17 capabilities present, and converges quickly even for an
        # adversarial collector result containing thousands of large rows.
        self._shrink_lists_to_budget(snapshot.get("capabilities", {}), _MAX_SNAPSHOT - 8192)
        self._refresh_counts(snapshot)


__all__ = [
    "DEVSEC_CAP_ITEM_KEYS",
    "REQUIRED_CAPABILITIES",
    "WinDeveloperSecurityCollector",
    "_MAX_FIELD",
    "_MAX_ITEMS",
    "_MAX_SNAPSHOT",
    "_bound_and_redact",
]
