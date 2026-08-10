"""Read-only developer and AI-tool security audit for Windows endpoints.

This collector implements the audit domains described in
``windowsagent_additional_Capabilities.md``.  It intentionally complements the
high-frequency inventory collectors: this section adds provenance, permission
and persistence context while running only every few hours.

Security invariants
-------------------
* Never emit credential values, environment values, file contents, or Docker
  container environment values.
* Never execute Python/Node/editor/Git shims found in a user's profile.  The
  Windows service is privileged and doing so would be a privilege escalation.
* Bound every filesystem walk, input file, output collection, and subprocess.
* Treat inaccessible/invalid inputs as partial coverage, never as a collector
  crash.
"""
from __future__ import annotations

import configparser
import hashlib
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import psutil

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.security_audit")

_AI_RE = re.compile(
    r"(?:copilot|cline|roo|continue|claude|gemini|codex|openai|codeium|"
    r"windsurf|tabnine|modelcontext|mcp|ollama|llama|langchain|crewai|"
    r"autogen|aider|goose|opencode|fabric|sgpt)",
    re.I,
)
_SCRIPT_HOST_RE = re.compile(
    r"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|"
    r"cscript(?:\.exe)?|python(?:w|\d+(?:\.\d+)?)?(?:\.exe)?|node(?:\.exe)?|"
    r"npm(?:\.cmd)?|npx(?:\.cmd)?|uvx(?:\.exe)?|curl(?:\.exe)?)",
    re.I,
)
_PROFILE_SUSPICIOUS_RE = {
    "download": re.compile(r"Invoke-WebRequest|\bcurl\b|\bwget\b", re.I),
    "dynamic_execution": re.compile(r"Invoke-Expression|\biex\b", re.I),
    "tool_bootstrap": re.compile(
        r"\b(?:npm|npx|python|pip|uvx|mcp|agent|ollama|claude|cursor)\b", re.I
    ),
    "encoded_command": re.compile(r"-(?:enc|encodedcommand)\b", re.I),
}
_SECRET_RE = re.compile(
    r"(?:pass(?:word|wd)?|secret|token|api[-_]?key|authorization|credential|"
    r"private[-_]?key|client[-_]?secret|access[-_]?key)",
    re.I,
)
_SENSITIVE_ARG_FLAGS = frozenset({
    "--api-key", "--apikey", "--token", "--password", "--passwd", "-p",
    "--secret", "--client-secret", "--authorization", "--auth",
})
_BROWSER_RISK_PERMISSIONS = frozenset({
    "nativemessaging", "clipboardread", "clipboardwrite", "cookies", "history",
    "debugger", "webrequest", "webrequestblocking", "management", "proxy",
    "downloads", "privacy", "tabs",
})
_EXECUTION_FILES = (
    ".vscode/tasks.json", ".vscode/settings.json", ".vscode/launch.json",
    ".devcontainer/devcontainer.json", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "Makefile", "package.json", "pyproject.toml",
    "requirements.txt", ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json",
    ".claude/settings.json", ".codex/config.toml",
)
_AI_COMMANDS = (
    "claude", "codex", "gemini", "aider", "ollama", "cursor", "code",
    "continue", "cline", "goose", "opencode", "fabric", "sgpt", "uv",
    "uvx", "npx", "docker", "python", "node", "npm",
)
_MAX_FILE_BYTES = 1024 * 1024
_MAX_RECORDS = 500
_MAX_FINDINGS = 500
_MAX_PROFILES = 64


def _bounded_text(path: Path, max_bytes: int = _MAX_FILE_BYTES) -> str:
    """Read a small text file without following an unbounded input."""
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except (OSError, ValueError):
        return ""


def _sha256(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _strip_jsonc(text: str) -> str:
    """Strip JSONC comments while preserving comment-like text in strings."""
    out: list[str] = []
    i = 0
    in_string = False
    escaped = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif ch == "/" and nxt == "/":
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
        elif ch == "/" and nxt == "*":
            i += 2
            while i + 1 < len(text) and text[i:i + 2] != "*/":
                i += 1
            i = min(len(text), i + 2)
        else:
            out.append(ch)
            i += 1
    # JSONC permits trailing commas.  At this point strings are intact; this
    # conservative expression only removes commas immediately before ] or }.
    return re.sub(r",\s*([}\]])", r"\1", "".join(out))


def _load_json_file(path: Path) -> Any:
    text = _bounded_text(path)
    if not text:
        raise ValueError("empty, inaccessible, or oversized JSON file")
    return json.loads(_strip_jsonc(text))


def _safe_url(value: str) -> str:
    """Remove URL credentials and sensitive query values."""
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value[:512]
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parts.port:
            host = f"{host}:{parts.port}"
        query = urlencode([
            (key, "<redacted>" if _SECRET_RE.search(key) else val)
            for key, val in parse_qsl(parts.query, keep_blank_values=True)
        ])
        return urlunsplit((parts.scheme, host, parts.path, query, parts.fragment))[:512]
    except (TypeError, ValueError):
        # A malformed port or authority can make urllib reject the URL.  Do
        # not fall back to the original value because it may contain userinfo.
        scheme = str(value).split(":", 1)[0][:32]
        return f"{scheme}://<redacted-invalid-url>" if scheme else "<redacted-invalid-url>"


def _redact_text(value: Any, limit: int = 512) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)\bBearer\s+\S+", "Bearer <redacted>", text)
    text = re.sub(
        r"(?i)(--?(?:api[-_]?key|token|password|passwd|secret|auth(?:orization)?)"
        r"(?:=|\s+))([^\s]+)",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)"
        r"[A-Z0-9_]*)=([^\s]+)",
        r"\1=<redacted>",
        text,
    )
    # Sanitize every URL independently so embedded userinfo cannot escape.
    text = re.sub(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"]+", lambda m: _safe_url(m.group(0)), text)
    return text[:limit]


def _sanitize_args(args: Any) -> list[str]:
    if not isinstance(args, list):
        args = [args] if args is not None else []
    result: list[str] = []
    hide_next = False
    for raw in args[:64]:
        value = str(raw)
        if hide_next:
            result.append("<redacted>")
            hide_next = False
            continue
        lower = value.lower()
        if lower in _SENSITIVE_ARG_FLAGS or _SECRET_RE.fullmatch(lower.lstrip("-")):
            result.append(value[:128])
            hide_next = True
        elif "=" in value and _SECRET_RE.search(value.split("=", 1)[0]):
            result.append(value.split("=", 1)[0][:128] + "=<redacted>")
        else:
            result.append(_redact_text(value, 256))
    return result


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


class WindowsSecurityAuditCollector(WinBaseCollector):
    """Bounded audit of developer tools, AI agents and execution surfaces."""

    name = "security_audit"
    timeout = 25
    max_duration_sec = 180

    def __init__(self, profile_roots: Iterable[str | os.PathLike[str]] | None = None) -> None:
        self._profile_override = [Path(p) for p in profile_roots] if profile_roots else None
        self._deadline = float("inf")
        self._coverage: dict[str, dict[str, Any]] = {}
        self._findings: list[dict[str, Any]] = []
        self._last_health: dict[str, Any] = {}

    def collect(self) -> dict:
        self._deadline = time.monotonic() + self.max_duration_sec
        self._coverage = {}
        self._findings = []
        profiles = self._profiles()
        result: dict[str, Any] = {
            "schema_version": 1,
            "collected_at": int(time.time()),
            "execution_context": {
                "username": os.environ.get("USERNAME"),
                "service_profile_aware": True,
                "user_tools_executed": False,
            },
            "profiles": [str(p) for p in profiles],
        }
        domains: tuple[tuple[str, Callable[[], Any], Any], ...] = (
            ("ide_extensions", lambda: self._ide_extensions(profiles), []),
            ("mcp", lambda: self._mcp_inventory(profiles), {"servers": [], "config_files": []}),
            ("node", lambda: self._node_inventory(profiles), {"packages": [], "configs": []}),
            ("python", lambda: self._python_inventory(profiles), {"installations": [], "packages": [], "configs": []}),
            ("applications", self._relevant_applications, []),
            ("ai_cli_tools", lambda: self._command_inventory(profiles), []),
            ("powershell", lambda: self._powershell_audit(profiles), {"profiles": [], "path": []}),
            ("scheduled_tasks", self._scheduled_tasks, []),
            ("services", self._services, []),
            ("startup", lambda: self._startup_entries(profiles), []),
            ("processes", self._relevant_processes, []),
            ("listeners", self._listeners, []),
            ("browser_extensions", lambda: self._browser_extensions(profiles), []),
            ("native_messaging", self._native_messaging_hosts, []),
            ("git", lambda: self._git_audit(profiles), {"configs": [], "repositories": []}),
            ("credentials", lambda: self._credential_metadata(profiles), {"saved_credentials": [], "files": []}),
            ("docker", self._docker_audit, {"available": False, "containers": [], "images": []}),
        )
        for name, fn, default in domains:
            result[name] = self._domain(name, fn, default)
        result["findings"] = self._findings[:_MAX_FINDINGS]
        result["coverage"] = dict(self._coverage)
        result["partial"] = any(v["status"] != "complete" for v in self._coverage.values())
        self._last_health = {
            "last_run": result["collected_at"],
            "partial": result["partial"],
            "findings": len(result["findings"]),
            "coverage": dict(self._coverage),
        }
        return result

    def health_snapshot(self) -> dict[str, Any]:
        return dict(self._last_health)

    def _domain(self, name: str, fn: Callable[[], Any], default: Any) -> Any:
        if time.monotonic() >= self._deadline:
            self._coverage[name] = {"status": "skipped", "reason": "collector_deadline"}
            return default
        started = time.monotonic()
        try:
            value = fn()
            count = len(value) if isinstance(value, list) else None
            self._coverage[name] = {
                "status": "complete",
                "duration_ms": int((time.monotonic() - started) * 1000),
                **({"records": count} if count is not None else {}),
            }
            return value
        except Exception as exc:
            log.debug("security_audit[%s]: %s", name, exc)
            self._coverage[name] = {
                "status": "error",
                "error": type(exc).__name__,
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
            return default

    def _finding(self, finding_id: str, severity: str, category: str,
                 title: str, evidence: str) -> None:
        if len(self._findings) >= _MAX_FINDINGS:
            return
        self._findings.append({
            "id": finding_id,
            "severity": severity,
            "category": category,
            "title": title[:256],
            "evidence": _redact_text(evidence, 512),
        })

    def _profiles(self) -> list[Path]:
        if self._profile_override is not None:
            return [p for p in self._profile_override if self._path_is_dir(p)][:_MAX_PROFILES]
        found: list[Path] = []
        try:
            import winreg
            root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root, 0, flags) as key:
                index = 0
                while index < _MAX_RECORDS:
                    try:
                        sid = winreg.EnumKey(key, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(key, sid) as sub:
                            raw, _ = winreg.QueryValueEx(sub, "ProfileImagePath")
                        path = Path(os.path.expandvars(str(raw)))
                        if path.is_dir():
                            found.append(path)
                    except OSError:
                        continue
        except (ImportError, OSError):
            pass
        users = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
        try:
            found.extend(p for p in users.iterdir() if p.is_dir())
        except OSError:
            pass
        current = Path(os.environ.get("USERPROFILE", ""))
        if str(current) and self._path_is_dir(current):
            found.append(current)
        excluded = {"default", "default user", "public", "all users", "defaultapppool"}
        unique: dict[str, Path] = {}
        for path in found:
            if path.name.lower() in excluded:
                continue
            unique.setdefault(os.path.normcase(str(path)), path)
        return list(unique.values())[:_MAX_PROFILES]

    @staticmethod
    def _loaded_user_sids(winreg: Any) -> list[str]:
        """Return interactive user hives that are already loaded, without loading NTUSER.DAT."""
        sids: list[str] = []
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, "") as key:
                index = 0
                while len(sids) < _MAX_RECORDS:
                    try:
                        sid = winreg.EnumKey(key, index)
                        index += 1
                    except OSError:
                        break
                    if re.fullmatch(r"S-1-5-21-(?:\d+-){3}\d+", sid):
                        sids.append(sid)
        except OSError:
            pass
        return sids

    # ---- IDE and MCP -----------------------------------------------------

    def _ide_extensions(self, profiles: list[Path]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for profile in profiles:
            for editor, root in (
                ("vscode", profile / ".vscode" / "extensions"),
                ("cursor", profile / ".cursor" / "extensions"),
                ("windsurf", profile / ".windsurf" / "extensions"),
            ):
                try:
                    children = list(root.iterdir())[:_MAX_RECORDS]
                except OSError:
                    continue
                for extension in children:
                    if len(records) >= _MAX_RECORDS:
                        return records
                    manifest = extension / "package.json"
                    if not self._path_is_file(manifest) or not _within(manifest, root):
                        continue
                    try:
                        data = _load_json_file(manifest)
                        if not isinstance(data, dict):
                            continue
                    except (ValueError, json.JSONDecodeError):
                        continue
                    name = str(data.get("name") or extension.name)
                    publisher = str(data.get("publisher") or "")
                    haystack = " ".join((name, publisher, json.dumps(data, default=str)[:65536]))
                    signals = sorted({
                        signal for signal, pattern in {
                            "startup_activation": r"onStartupFinished|\*",
                            "workspace_activation": r"workspaceContains",
                            "child_process": r"child_process",
                            "terminal_or_shell": r"terminal|shell",
                            "network": r"https?://|\bhttp\b",
                        }.items() if re.search(pattern, haystack, re.I)
                    })
                    record = {
                        "editor": editor,
                        "name": name[:256],
                        "publisher": publisher[:256] or None,
                        "version": str(data.get("version") or "")[:64] or None,
                        "path": str(extension),
                        "ai_related": bool(_AI_RE.search(haystack)),
                        "activation_events": [str(x)[:256] for x in _as_list(data.get("activationEvents"))[:32]],
                        "risk_signals": signals,
                    }
                    records.append(record)
                    if signals and record["ai_related"]:
                        self._finding(
                            "ide_extension_sensitive", "medium", "ide_extensions",
                            f"AI-related {editor} extension has sensitive capabilities",
                            f"{publisher}.{name}: {','.join(signals)}",
                        )
        return records

    @staticmethod
    def _find_mcp_maps(node: Any) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        if isinstance(node, dict):
            for key, value in node.items():
                normalized = re.sub(r"[^a-z]", "", str(key).lower())
                if normalized in {"mcpservers", "modelcontextprotocolservers"} and isinstance(value, dict):
                    found.append(value)
                found.extend(WindowsSecurityAuditCollector._find_mcp_maps(value))
        elif isinstance(node, list):
            for value in node:
                found.extend(WindowsSecurityAuditCollector._find_mcp_maps(value))
        return found

    def _mcp_inventory(self, profiles: list[Path]) -> dict[str, Any]:
        candidates: dict[str, Path] = {}
        for profile in profiles:
            appdata = profile / "AppData" / "Roaming"
            known = (
                appdata / "Claude" / "claude_desktop_config.json",
                appdata / "Cursor" / "User" / "settings.json",
                appdata / "Code" / "User" / "settings.json",
                profile / ".cursor" / "mcp.json",
                profile / ".vscode" / "mcp.json",
                profile / ".claude.json",
                profile / ".claude" / "settings.json",
                profile / ".windsurf" / "mcp.json",
                profile / ".codex" / "config.toml",
            )
            for path in known:
                if self._path_is_file(path):
                    candidates[os.path.normcase(str(path))] = path
            for root in (appdata / "Claude", appdata / "Cursor", appdata / "Code",
                         profile / ".cursor", profile / ".vscode", profile / ".config",
                         profile / ".codex", profile / ".claude"):
                for path in self._walk_files(root, 3, 250, {".json", ".jsonc", ".yaml", ".yml", ".toml"}):
                    if re.search(r"mcp|config|settings", path.name, re.I):
                        candidates.setdefault(os.path.normcase(str(path)), path)
            for root in (
                profile / "source", profile / "src", profile / "repos",
                profile / "projects", profile / "workspace", profile / "workspaces",
                profile / "Documents", profile / "Desktop",
            ):
                for path in self._walk_files(root, 4, 250, {".json", ".jsonc", ".yaml", ".yml", ".toml"}):
                    if re.search(r"mcp", path.name, re.I) or (
                        path.name.lower() in {"settings.json", "config.toml"}
                        and path.parent.name.lower() in {".cursor", ".vscode", ".claude", ".codex"}
                    ):
                        candidates.setdefault(os.path.normcase(str(path)), path)
        servers: list[dict[str, Any]] = []
        files: list[dict[str, Any]] = []
        for path in list(candidates.values())[:_MAX_RECORDS]:
            text = _bounded_text(path)
            if not text:
                files.append({"path": str(path), "status": "unreadable_or_oversized"})
                continue
            maps: list[dict[str, Any]] = []
            parse_status = "text_match_only"
            if path.suffix.lower() in {".json", ".jsonc"}:
                try:
                    data = json.loads(_strip_jsonc(text))
                    maps = self._find_mcp_maps(data)
                    parse_status = "parsed"
                except (ValueError, json.JSONDecodeError):
                    parse_status = "invalid"
            elif path.suffix.lower() == ".toml":
                try:
                    import tomllib
                    data = tomllib.loads(text)
                    maps = self._find_mcp_maps(data)
                    parse_status = "parsed"
                except (ValueError, TypeError):
                    parse_status = "invalid"
            match = bool(re.search(r"mcpServers|mcp[-_]server|model\.context\.protocol", text, re.I))
            if not maps and not match:
                continue
            files.append({
                "path": str(path), "status": parse_status,
                "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
            })
            for server_map in maps:
                for name, raw in list(server_map.items())[:_MAX_RECORDS]:
                    if len(servers) >= _MAX_RECORDS:
                        break
                    cfg = raw if isinstance(raw, dict) else {}
                    command = _redact_text(cfg.get("command"), 512)
                    args = _sanitize_args(cfg.get("args"))
                    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
                    record = {
                        "name": str(name)[:256],
                        "command": command or None,
                        "args": args,
                        "env_names": sorted(str(k)[:128] for k in env)[:128],
                        "cwd": _redact_text(cfg.get("cwd"), 512) or None,
                        "transport": str(cfg.get("transport") or cfg.get("type") or "stdio")[:64],
                        "source": str(path),
                    }
                    servers.append(record)
                    joined = " ".join([command, *args])
                    if re.search(r"\b(?:npx|uvx)\b", joined, re.I) and not re.search(r"@\d|==\d", joined):
                        self._finding(
                            "mcp_unpinned_launcher", "high", "mcp",
                            "MCP server uses an unpinned package launcher",
                            f"{name}: {joined}",
                        )
                    if command and any(str(profile).lower() in command.lower() for profile in profiles):
                        self._finding(
                            "mcp_user_writable_command", "high", "mcp",
                            "MCP server command resolves inside a user profile",
                            f"{name}: {command}",
                        )
        return {"servers": servers, "config_files": files}

    # ---- Toolchains and applications ------------------------------------

    def _node_inventory(self, profiles: list[Path]) -> dict[str, Any]:
        roots: list[tuple[str, Path]] = []
        for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            base = os.environ.get(env_name)
            if base:
                roots.extend((
                    ("npm", Path(base) / "nodejs" / "node_modules"),
                    ("npm", Path(base) / "npm" / "node_modules"),
                ))
        configs: list[dict[str, Any]] = []
        for profile in profiles:
            roots.extend((
                ("npm", profile / "AppData" / "Roaming" / "npm" / "node_modules"),
                ("yarn", profile / "AppData" / "Local" / "Yarn" / "Data" / "global" / "node_modules"),
            ))
            pnpm_global = profile / "AppData" / "Local" / "pnpm" / "global"
            try:
                roots.extend(("pnpm", version / "node_modules") for version in list(pnpm_global.iterdir())[:32])
            except OSError:
                pass
            for config in (profile / ".npmrc", profile / ".yarnrc", profile / ".pnpmrc"):
                parsed = self._safe_kv_config(config)
                if parsed is not None:
                    configs.append({"path": str(config), "settings": parsed})
        packages: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for manager, root in roots:
            for manifest in self._node_manifests(root):
                if len(packages) >= _MAX_RECORDS:
                    break
                try:
                    data = _load_json_file(manifest)
                    name = str(data.get("name") or manifest.parent.name)
                    version = str(data.get("version") or "") or None
                except (ValueError, json.JSONDecodeError, AttributeError):
                    continue
                key = (manager, name.lower(), str(version))
                if key in seen:
                    continue
                seen.add(key)
                packages.append({
                    "manager": manager, "name": name[:256], "version": version,
                    "path": str(manifest.parent), "ai_related": bool(_AI_RE.search(name)),
                })
        return {"packages": packages, "configs": configs}

    def _node_manifests(self, root: Path) -> Iterable[Path]:
        try:
            children = list(root.iterdir())[:_MAX_RECORDS]
        except OSError:
            return []
        found: list[Path] = []
        for child in children:
            if child.name.startswith("@") and self._path_is_dir(child):
                try:
                    found.extend(pkg / "package.json" for pkg in list(child.iterdir())[:_MAX_RECORDS])
                except OSError:
                    continue
            elif self._path_is_dir(child):
                found.append(child / "package.json")
        return [p for p in found[:_MAX_RECORDS] if self._path_is_file(p) and _within(p, root)]

    def _python_inventory(self, profiles: list[Path]) -> dict[str, Any]:
        site_roots: list[Path] = []
        configs: list[dict[str, Any]] = []
        installations: list[dict[str, Any]] = []
        for profile in profiles:
            patterns = (
                profile / "AppData" / "Local" / "Programs" / "Python",
                profile / "AppData" / "Roaming" / "Python",
            )
            for base in patterns:
                try:
                    versions = list(base.glob("Python*"))[:32]
                except OSError:
                    versions = []
                for version in versions:
                    for root in (version / "Lib" / "site-packages", version / "site-packages"):
                        if self._path_is_dir(root):
                            site_roots.append(root)
                    exe = version / "python.exe"
                    installations.append({
                        "version_hint": version.name, "path": str(exe if exe.exists() else version),
                        "executed": False,
                    })
            for config in (profile / "pip" / "pip.ini", profile / "AppData" / "Roaming" / "pip" / "pip.ini"):
                parsed = self._safe_ini_config(config)
                if parsed is not None:
                    configs.append({"path": str(config), "settings": parsed})
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base_raw = os.environ.get(env_name)
            if not base_raw:
                continue
            for version in list(Path(base_raw).glob("Python*"))[:32]:
                root = version / "Lib" / "site-packages"
                if self._path_is_dir(root):
                    site_roots.append(root)
                    installations.append({"version_hint": version.name, "path": str(version / "python.exe"), "executed": False})
        packages: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for root in site_roots[:64]:
            try:
                metadata_files = [p / "METADATA" for p in root.glob("*.dist-info")][:_MAX_RECORDS]
            except OSError:
                continue
            for metadata in metadata_files:
                if len(packages) >= _MAX_RECORDS:
                    break
                name = version = ""
                for line in _bounded_text(metadata, 256 * 1024).splitlines():
                    if line.startswith("Name:") and not name:
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:") and not version:
                        version = line.split(":", 1)[1].strip()
                    if name and version:
                        break
                if not name:
                    continue
                key = (str(root).lower(), name.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                packages.append({
                    "manager": "pip", "name": name[:256], "version": version[:128] or None,
                    "path": str(metadata.parent), "ai_related": bool(_AI_RE.search(name)),
                })
        return {"installations": installations[:128], "packages": packages, "configs": configs}

    def _safe_kv_config(self, path: Path) -> dict[str, Any] | None:
        text = _bounded_text(path, 256 * 1024)
        if not text:
            return None
        settings: dict[str, Any] = {}
        safe_keys = {"registry", "proxy", "https-proxy", "ignore-scripts", "prefix", "cache"}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if _SECRET_RE.search(key) or key.startswith("//"):
                settings[key[:128]] = "<present-redacted>"
            elif key.lower() in safe_keys:
                settings[key[:128]] = _redact_text(value, 512)
        registry = str(settings.get("registry") or "")
        if registry and "registry.npmjs.org" not in registry.lower():
            self._finding("node_custom_registry", "medium", "node", "Node package manager uses a custom registry", registry)
        if str(settings.get("ignore-scripts") or "").lower() in {"false", "0", "no"}:
            self._finding("node_lifecycle_scripts", "low", "node", "Node lifecycle scripts are enabled", str(path))
        return settings

    def _safe_ini_config(self, path: Path) -> dict[str, Any] | None:
        text = _bounded_text(path, 256 * 1024)
        if not text:
            return None
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error:
            return {"parse_status": "invalid"}
        result: dict[str, Any] = {}
        for section in parser.sections():
            for key, value in parser.items(section):
                label = f"{section}.{key}"
                if _SECRET_RE.search(key):
                    result[label] = "<present-redacted>"
                elif key.lower() in {"index-url", "extra-index-url", "proxy", "trusted-host", "no-index"}:
                    result[label] = _redact_text(value, 512)
        return result

    def _relevant_applications(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            import winreg
        except ImportError:
            return records
        locations: list[tuple[Any, str]] = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        locations.extend(
            (winreg.HKEY_USERS, sid + r"\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            for sid in self._loaded_user_sids(winreg)
        )
        views = (getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0))
        seen: set[tuple[str, str]] = set()
        for hive, root in locations:
            for view in views:
                try:
                    with winreg.OpenKey(hive, root, 0, winreg.KEY_READ | view) as key:
                        index = 0
                        while len(records) < _MAX_RECORDS:
                            try:
                                child = winreg.EnumKey(key, index)
                                index += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(key, child) as sub:
                                    name = str(winreg.QueryValueEx(sub, "DisplayName")[0])
                                    try:
                                        version = str(winreg.QueryValueEx(sub, "DisplayVersion")[0])
                                    except OSError:
                                        version = ""
                                    try:
                                        publisher = str(winreg.QueryValueEx(sub, "Publisher")[0])
                                    except OSError:
                                        publisher = ""
                                    try:
                                        location = str(winreg.QueryValueEx(sub, "InstallLocation")[0])
                                    except OSError:
                                        location = ""
                            except OSError:
                                continue
                            haystack = f"{name} {publisher}"
                            if not (_AI_RE.search(haystack) or re.search(
                                r"Visual Studio Code|Cursor|Windsurf|ChatGPT|LM Studio|Docker|Python|Node", haystack, re.I
                            )):
                                continue
                            dedupe = (name.lower(), version.lower())
                            if dedupe in seen:
                                continue
                            seen.add(dedupe)
                            records.append({
                                "name": name[:256], "version": version[:128] or None,
                                "publisher": publisher[:256] or None,
                                "install_location": location[:1024] or None,
                                "ai_related": bool(_AI_RE.search(haystack)),
                            })
                except OSError:
                    continue
        return records

    def _candidate_path_entries(self, profiles: list[Path]) -> list[tuple[str, str]]:
        values: list[tuple[str, str]] = []
        values.extend(("process", part) for part in os.environ.get("PATH", "").split(os.pathsep) if part)
        try:
            import winreg
            for hive, subkey, source in (
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "machine"),
                (winreg.HKEY_CURRENT_USER, r"Environment", "current_user"),
            ):
                try:
                    with winreg.OpenKey(hive, subkey) as key:
                        raw, _ = winreg.QueryValueEx(key, "Path")
                    values.extend((source, part) for part in str(raw).split(";") if part)
                except OSError:
                    continue
            for sid in self._loaded_user_sids(winreg):
                try:
                    with winreg.OpenKey(winreg.HKEY_USERS, sid + r"\Environment") as key:
                        raw, _ = winreg.QueryValueEx(key, "Path")
                    values.extend((f"user:{sid}", part) for part in str(raw).split(";") if part)
                except OSError:
                    continue
        except ImportError:
            pass
        # These common command locations may not appear in the LocalSystem PATH.
        for profile in profiles:
            for path in (
                profile / "AppData" / "Roaming" / "npm",
                profile / ".local" / "bin",
                profile / ".cargo" / "bin",
                profile / "scoop" / "shims",
                profile / "AppData" / "Local" / "Programs" / "Microsoft VS Code" / "bin",
                profile / "AppData" / "Local" / "Programs" / "cursor" / "resources" / "app" / "bin",
            ):
                if self._path_is_dir(path):
                    values.append(("profile_common", str(path)))
        return values[:2000]

    def _command_inventory(self, profiles: list[Path]) -> list[dict[str, Any]]:
        path_entries = self._candidate_path_entries(profiles)
        extensions = (".exe", ".com", ".cmd", ".bat", ".ps1", "")
        records: list[dict[str, Any]] = []
        for command in _AI_COMMANDS:
            matches: list[str] = []
            for _, raw_dir in path_entries:
                directory = Path(os.path.expandvars(raw_dir.strip().strip('"')))
                for suffix in extensions:
                    candidate = directory / (command + suffix)
                    try:
                        if candidate.is_file():
                            normalized = os.path.normcase(str(candidate.resolve(strict=False)))
                            if normalized not in {os.path.normcase(p) for p in matches}:
                                matches.append(str(candidate))
                    except OSError:
                        continue
            if not matches:
                continue
            user_controlled = [
                path for path in matches
                if any(_within(Path(path), profile) for profile in profiles)
            ]
            record = {
                "command": command, "paths": matches[:32],
                "shadowed": len(matches) > 1,
                "user_profile_paths": user_controlled[:32],
                "executed": False,
            }
            records.append(record)
            if len(matches) > 1:
                self._finding("command_shadowing", "medium", "ai_cli_tools", f"Command {command} is shadowed", "; ".join(matches))
            if user_controlled:
                self._finding("user_controlled_cli", "low", "ai_cli_tools", f"Command {command} is installed in a user profile", "; ".join(user_controlled))
        return records

    # ---- Profiles, persistence, processes and network -------------------

    def _powershell_audit(self, profiles: list[Path]) -> dict[str, Any]:
        profile_records: list[dict[str, Any]] = []
        candidates: list[Path] = []
        for profile in profiles:
            for folder in (profile / "Documents" / "WindowsPowerShell", profile / "Documents" / "PowerShell"):
                candidates.extend((folder / "profile.ps1", folder / "Microsoft.PowerShell_profile.ps1"))
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        candidates.extend((
            system_root / "System32" / "WindowsPowerShell" / "v1.0" / "profile.ps1",
            system_root / "System32" / "WindowsPowerShell" / "v1.0" / "Microsoft.PowerShell_profile.ps1",
        ))
        for path in candidates[:_MAX_RECORDS]:
            text = _bounded_text(path)
            if not text:
                continue
            signals = sorted(name for name, pattern in _PROFILE_SUSPICIOUS_RE.items() if pattern.search(text))
            record = {
                "path": str(path), "size": len(text.encode("utf-8", errors="replace")),
                "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
                "risk_signals": signals,
            }
            profile_records.append(record)
            if signals:
                self._finding("powershell_profile_execution", "high", "powershell", "PowerShell profile contains sensitive startup behavior", f"{path}: {','.join(signals)}")

        path_records: list[dict[str, Any]] = []
        seen: dict[str, int] = {}
        for source, raw in self._candidate_path_entries(profiles):
            expanded = os.path.expandvars(raw.strip().strip('"'))
            normalized = os.path.normcase(os.path.normpath(expanded))
            seen[normalized] = seen.get(normalized, 0) + 1
            relative = not os.path.isabs(expanded)
            user_profile = any(_within(Path(expanded), profile) for profile in profiles) if not relative else False
            exists = self._path_is_dir(Path(expanded)) if expanded else False
            record = {
                "source": source, "path": expanded[:1024], "exists": exists,
                "relative": relative, "user_profile": user_profile,
            }
            path_records.append(record)
            if relative:
                self._finding("relative_path_entry", "high", "powershell", "PATH contains a relative entry", expanded)
            elif user_profile:
                self._finding("user_writable_path_entry", "medium", "powershell", "PATH contains a user-profile directory", expanded)
        for record in path_records:
            normalized = os.path.normcase(os.path.normpath(record["path"]))
            record["duplicate"] = seen.get(normalized, 0) > 1
        return {"profiles": profile_records, "path": path_records[:_MAX_RECORDS]}

    def _ps_json(self, script: str, default: Any) -> Any:
        output = self._run_ps(script)
        try:
            return json.loads(output.strip()) if output.strip() else default
        except (ValueError, json.JSONDecodeError):
            return default

    def _scheduled_tasks(self) -> list[dict[str, Any]]:
        raw = self._ps_json(
            "$ErrorActionPreference='SilentlyContinue'; @((Get-ScheduledTask | ForEach-Object {"
            "$t=$_; foreach($a in @($t.Actions)){[pscustomobject]@{TaskPath=$t.TaskPath;TaskName=$t.TaskName;"
            "State=[string]$t.State;Execute=$a.Execute;Arguments=$a.Arguments;WorkingDirectory=$a.WorkingDirectory;"
            "UserId=$t.Principal.UserId;RunLevel=[string]$t.Principal.RunLevel}}}) | ConvertTo-Json -Compress -Depth 4)",
            [],
        )
        records: list[dict[str, Any]] = []
        for item in _as_list(raw)[:_MAX_RECORDS]:
            if not isinstance(item, dict):
                continue
            execute = _redact_text(item.get("Execute"), 1024)
            arguments = _redact_text(item.get("Arguments"), 1024)
            signals: list[str] = []
            if _SCRIPT_HOST_RE.search(execute):
                signals.append("script_host")
            if re.search(r"\\Users\\|%USERPROFILE%|AppData", execute + " " + arguments, re.I):
                signals.append("user_profile_execution")
            if re.search(r"https?://|-(?:enc|encodedcommand)\b|Invoke-Expression|\biex\b", arguments, re.I):
                signals.append("download_or_obfuscated")
            name = str(item.get("TaskPath") or "\\") + str(item.get("TaskName") or "")
            records.append({
                "name": name[:1024], "state": str(item.get("State") or "unknown").lower(),
                "execute": execute or None, "arguments": arguments or None,
                "working_directory": _redact_text(item.get("WorkingDirectory"), 1024) or None,
                "user": str(item.get("UserId") or "")[:256] or None,
                "run_level": str(item.get("RunLevel") or "")[:64] or None,
                "risk_signals": signals,
            })
            if signals:
                self._finding("scheduled_task_sensitive", "high", "scheduled_tasks", "Scheduled task has a sensitive execution pattern", f"{name}: {execute} {arguments}")
        return records

    @staticmethod
    def _service_unquoted_path(path: str) -> bool:
        value = path.strip()
        if not value or value.startswith('"'):
            return False
        match = re.match(r"(?i)^(.+?\.(?:exe|com|bat|cmd))(?=\s|$)", value)
        return bool(match and " " in match.group(1))

    def _services(self) -> list[dict[str, Any]]:
        raw = self._ps_json(
            "@(Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ProcessId | ConvertTo-Json -Compress)",
            [],
        )
        records: list[dict[str, Any]] = []
        for item in _as_list(raw)[:_MAX_RECORDS]:
            if not isinstance(item, dict):
                continue
            path = _redact_text(item.get("PathName"), 2048)
            signals: list[str] = []
            if self._service_unquoted_path(path):
                signals.append("unquoted_service_path")
            if re.search(r"\\Users\\|AppData", path, re.I):
                signals.append("user_profile_binary")
            if _SCRIPT_HOST_RE.search(path):
                signals.append("script_host")
            record = {
                "name": str(item.get("Name") or "")[:256],
                "display_name": str(item.get("DisplayName") or "")[:256] or None,
                "state": str(item.get("State") or "unknown").lower(),
                "start_mode": str(item.get("StartMode") or "unknown").lower(),
                "path": path or None, "account": str(item.get("StartName") or "")[:256] or None,
                "pid": item.get("ProcessId"), "risk_signals": signals,
            }
            records.append(record)
            if signals:
                self._finding("service_path_risk", "high", "services", "Windows service has a risky executable path", f"{record['name']}: {path}; {','.join(signals)}")
        return records

    def _startup_entries(self, profiles: list[Path]) -> list[dict[str, Any]]:
        raw = self._ps_json(
            "@(Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress)",
            [],
        )
        records: list[dict[str, Any]] = []
        for item in _as_list(raw)[:_MAX_RECORDS]:
            if not isinstance(item, dict):
                continue
            command = _redact_text(item.get("Command"), 1024)
            signals = []
            if _SCRIPT_HOST_RE.search(command):
                signals.append("script_host")
            if re.search(r"https?://|-(?:enc|encodedcommand)\b|Invoke-Expression|\biex\b", command, re.I):
                signals.append("download_or_obfuscated")
            records.append({
                "name": str(item.get("Name") or "")[:256], "command": command,
                "location": str(item.get("Location") or "")[:512],
                "user": str(item.get("User") or "")[:256], "risk_signals": signals,
            })
            if signals:
                self._finding("startup_sensitive", "high", "startup", "Startup entry invokes a sensitive command", command)
        # Win32_StartupCommand can omit transient RunOnce values.  Read both
        # registry views and every already-loaded user hive as a second source.
        try:
            import winreg
            registry_roots: list[tuple[Any, str, str]] = []
            for suffix in ("Run", "RunOnce"):
                registry_roots.append((
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SOFTWARE\Microsoft\Windows\CurrentVersion\{suffix}",
                    f"machine:{suffix}",
                ))
                registry_roots.extend((
                    winreg.HKEY_USERS,
                    sid + rf"\SOFTWARE\Microsoft\Windows\CurrentVersion\{suffix}",
                    f"user:{sid}:{suffix}",
                ) for sid in self._loaded_user_sids(winreg))
            for hive, subkey, scope in registry_roots:
                try:
                    with winreg.OpenKey(hive, subkey) as key:
                        index = 0
                        while len(records) < _MAX_RECORDS:
                            try:
                                name, value, _ = winreg.EnumValue(key, index)
                                index += 1
                            except OSError:
                                break
                            command = _redact_text(value, 1024)
                            if any(r.get("command") == command and r.get("name") == name for r in records):
                                continue
                            signals = ["script_host"] if _SCRIPT_HOST_RE.search(command) else []
                            records.append({
                                "name": str(name)[:256], "command": command,
                                "location": scope, "user": None, "risk_signals": signals,
                            })
                except OSError:
                    continue
        except ImportError:
            pass
        for profile in profiles:
            for folder in (
                profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
                Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            ):
                try:
                    files = list(folder.iterdir())[:128]
                except OSError:
                    continue
                for path in files:
                    records.append({
                        "name": path.name, "command": None, "location": str(folder),
                        "user": profile.name, "file": str(path),
                        "sha256": _sha256(path), "risk_signals": ["startup_folder"],
                    })
        return records[:_MAX_RECORDS]

    def _relevant_processes(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        attrs = ["pid", "ppid", "name", "username", "exe", "cmdline"]
        try:
            iterator = psutil.process_iter(attrs)
        except Exception:
            return records
        for proc in iterator:
            try:
                info = proc.info
                raw_cmd = " ".join(str(x) for x in (info.get("cmdline") or []))
                haystack = f"{info.get('name') or ''} {raw_cmd}"
                if not (_AI_RE.search(haystack) or re.search(r"\b(?:mcp|agent)\b", haystack, re.I)):
                    continue
                records.append({
                    "pid": info.get("pid"), "ppid": info.get("ppid"),
                    "name": str(info.get("name") or "")[:256],
                    "user": str(info.get("username") or "")[:256] or None,
                    "path": str(info.get("exe") or "")[:1024] or None,
                    "command_line": _redact_text(raw_cmd, 1024) or None,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                continue
        return records[:_MAX_RECORDS]

    def _listeners(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        processes: dict[int, dict[str, Any]] = {}
        try:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                processes[int(proc.info["pid"])] = proc.info
        except Exception:
            pass
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return records
        for conn in connections:
            try:
                is_tcp = conn.status == psutil.CONN_LISTEN
                is_udp = conn.type == 2 and not conn.status
                if not (is_tcp or is_udp) or not conn.laddr:
                    continue
                address = str(conn.laddr.ip or "0.0.0.0")
                public_bind = address in {"0.0.0.0", "::", "*"}
                proc = processes.get(int(conn.pid or 0), {})
                record = {
                    "address": address, "port": int(conn.laddr.port),
                    "protocol": "udp" if is_udp else "tcp", "pid": conn.pid,
                    "process": str(proc.get("name") or "")[:256] or None,
                    "path": str(proc.get("exe") or "")[:1024] or None,
                    "public_bind": public_bind,
                }
                records.append(record)
                if public_bind and _AI_RE.search(str(record.get("process") or "")):
                    self._finding("ai_public_listener", "high", "listeners", "AI-related process listens on all interfaces", f"{record['process']} {address}:{record['port']}")
            except (AttributeError, TypeError, ValueError):
                continue
        return records[:_MAX_RECORDS]

    # ---- Browser extensions and native messaging -----------------------

    def _browser_extensions(self, profiles: list[Path]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for profile in profiles:
            browsers = (
                ("chrome", profile / "AppData" / "Local" / "Google" / "Chrome" / "User Data"),
                ("edge", profile / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data"),
                ("brave", profile / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data"),
            )
            for browser, user_data in browsers:
                try:
                    browser_profiles = [
                        p for p in user_data.iterdir()
                        if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))
                    ][:64]
                except OSError:
                    continue
                for browser_profile in browser_profiles:
                    extensions_root = browser_profile / "Extensions"
                    for manifest in self._walk_files(extensions_root, 3, _MAX_RECORDS, {".json"}, exact_name="manifest.json"):
                        if len(records) >= _MAX_RECORDS:
                            return records
                        try:
                            data = _load_json_file(manifest)
                            if not isinstance(data, dict):
                                continue
                        except (ValueError, json.JSONDecodeError):
                            continue
                        permissions = [str(x) for x in _as_list(data.get("permissions"))]
                        host_permissions = [str(x) for x in _as_list(data.get("host_permissions"))]
                        risk = sorted({p.lower() for p in permissions if p.lower() in _BROWSER_RISK_PERMISSIONS})
                        if any(p in {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"} for p in host_permissions):
                            risk.append("all_hosts")
                        extension_id = manifest.parents[1].name if len(manifest.parents) > 1 else ""
                        name = str(data.get("name") or extension_id)
                        record = {
                            "browser": browser, "browser_profile": browser_profile.name,
                            "extension_id": extension_id[:128], "name": name[:256],
                            "version": str(data.get("version") or "")[:64] or None,
                            "permissions": permissions[:128], "host_permissions": host_permissions[:128],
                            "risk_signals": sorted(set(risk)), "path": str(manifest.parent),
                        }
                        records.append(record)
                        if risk:
                            severity = "high" if "debugger" in risk or "nativemessaging" in risk or "all_hosts" in risk else "medium"
                            self._finding("browser_extension_permissions", severity, "browser_extensions", "Browser extension has security-sensitive permissions", f"{browser}:{extension_id}: {','.join(sorted(set(risk)))}")
        return records

    def _native_messaging_hosts(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            import winreg
        except ImportError:
            return records
        roots: list[tuple[Any, str, str, str]] = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Google\Chrome\NativeMessagingHosts", "machine", "chrome"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Google\Chrome\NativeMessagingHosts", "current_user", "chrome"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Edge\NativeMessagingHosts", "machine", "edge"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Edge\NativeMessagingHosts", "current_user", "edge"),
        ]
        for sid in self._loaded_user_sids(winreg):
            roots.extend((
                (winreg.HKEY_USERS, sid + r"\SOFTWARE\Google\Chrome\NativeMessagingHosts", f"user:{sid}", "chrome"),
                (winreg.HKEY_USERS, sid + r"\SOFTWARE\Microsoft\Edge\NativeMessagingHosts", f"user:{sid}", "edge"),
            ))
        views = (getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0))
        seen: set[tuple[str, str]] = set()
        for hive, root, scope, browser in roots:
            for view in views:
                try:
                    with winreg.OpenKey(hive, root, 0, winreg.KEY_READ | view) as key:
                        index = 0
                        while len(records) < _MAX_RECORDS:
                            try:
                                host = winreg.EnumKey(key, index)
                                index += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(key, host) as sub:
                                    manifest_raw, _ = winreg.QueryValueEx(sub, "")
                            except OSError:
                                continue
                            manifest = Path(os.path.expandvars(str(manifest_raw)))
                            key_id = (browser, os.path.normcase(str(manifest)))
                            if key_id in seen:
                                continue
                            seen.add(key_id)
                            executable = None
                            origins: list[str] = []
                            parse_status = "missing"
                            try:
                                data = _load_json_file(manifest)
                                executable = _redact_text(data.get("path"), 1024)
                                origins = [str(x)[:512] for x in _as_list(data.get("allowed_origins"))[:128]]
                                parse_status = "parsed"
                            except (ValueError, json.JSONDecodeError, AttributeError):
                                pass
                            record = {
                                "browser": browser, "scope": scope, "name": host[:256],
                                "manifest": str(manifest), "executable": executable,
                                "allowed_origins": origins, "status": parse_status,
                            }
                            records.append(record)
                            if executable and re.search(r"\\Users\\|AppData", executable, re.I):
                                self._finding("native_host_user_profile", "high", "native_messaging", "Browser native-messaging host executes from a user profile", f"{host}: {executable}")
                except OSError:
                    continue
        return records

    # ---- Git, credentials and Docker ------------------------------------

    def _git_audit(self, profiles: list[Path]) -> dict[str, Any]:
        configs: list[dict[str, Any]] = []
        config_paths: list[tuple[str, Path]] = []
        for profile in profiles:
            config_paths.extend((
                ("global", profile / ".gitconfig"),
                ("global", profile / ".config" / "git" / "config"),
            ))
        program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        config_paths.append(("system", program_data / "Git" / "config"))
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(env_name):
                config_paths.append(("system", Path(os.environ[env_name]) / "Git" / "etc" / "gitconfig"))
        for scope, path in config_paths:
            text = _bounded_text(path)
            if not text:
                continue
            settings = self._parse_git_config(text)
            configs.append({
                "scope": scope, "path": str(path), "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
                "settings": settings,
            })
            for key in ("core.hookspath", "core.sshcommand", "credential.helper"):
                if key in settings:
                    self._finding("git_execution_config", "medium", "git", f"Git {key} is configured", f"{path}: {settings[key]}")

        repositories: list[dict[str, Any]] = []
        for profile in profiles:
            roots = (
                profile / "source", profile / "src", profile / "repos",
                profile / "projects", profile / "workspace", profile / "workspaces",
                profile / "Documents", profile / "Desktop",
            )
            for root in roots:
                for repo in self._discover_repositories(root, 3, 50 - len(repositories)):
                    if len(repositories) >= 50:
                        break
                    hooks_dir = repo / ".git" / "hooks"
                    hooks: list[dict[str, Any]] = []
                    try:
                        hook_files = [p for p in hooks_dir.iterdir() if p.is_file() and not p.name.endswith(".sample")][:128]
                    except OSError:
                        hook_files = []
                    for hook in hook_files:
                        hooks.append({"name": hook.name, "path": str(hook), "sha256": _sha256(hook), "size": self._size(hook)})
                    exec_files: list[dict[str, Any]] = []
                    for relative in _EXECUTION_FILES:
                        target = repo / Path(relative)
                        text = _bounded_text(target)
                        if not text:
                            continue
                        signals = sorted(name for name, pattern in _PROFILE_SUSPICIOUS_RE.items() if pattern.search(text))
                        exec_files.append({"path": str(target), "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(), "risk_signals": signals})
                    workflows = repo / ".github" / "workflows"
                    for target in self._walk_files(workflows, 1, 64, {".yml", ".yaml"}):
                        text = _bounded_text(target)
                        if text:
                            exec_files.append({"path": str(target), "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(), "risk_signals": []})
                    record = {"root": str(repo), "hooks": hooks, "execution_files": exec_files[:128]}
                    repositories.append(record)
                    if hooks:
                        self._finding("git_hooks_present", "medium", "git", "Repository has active Git hooks", f"{repo}: {','.join(h['name'] for h in hooks)}")
        return {"configs": configs, "repositories": repositories}

    @staticmethod
    def _parse_git_config(text: str) -> dict[str, str]:
        section = ""
        result: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].split('"', 1)[0].strip().lower().replace(" ", ".")
                continue
            if "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            full_key = f"{section}.{key.lower()}" if section else key.lower()
            if full_key in {"credential.helper", "core.hookspath", "core.sshcommand"}:
                result[full_key[:256]] = _redact_text(value, 512)
            elif _SECRET_RE.search(full_key):
                result[full_key[:256]] = "<present-redacted>"
            else:
                result[full_key[:256]] = _redact_text(value, 512)
        return result

    def _discover_repositories(self, root: Path, max_depth: int, limit: int) -> list[Path]:
        try:
            usable_root = root.is_dir()
        except OSError:
            usable_root = False
        if limit <= 0 or not usable_root:
            return []
        found: list[Path] = []
        base_depth = len(root.parts)
        visited = 0
        try:
            for current, dirs, _ in os.walk(root, topdown=True, followlinks=False):
                visited += 1
                if visited > 1500 or len(found) >= limit or time.monotonic() >= self._deadline:
                    break
                current_path = Path(current)
                depth = len(current_path.parts) - base_depth
                dirs[:] = [d for d in dirs if d not in {"node_modules", ".venv", "venv", "dist", "build", "AppData"}]
                if ".git" in dirs or (current_path / ".git").is_file():
                    found.append(current_path)
                    dirs[:] = []
                elif depth >= max_depth:
                    dirs[:] = []
        except OSError:
            pass
        return found

    def _credential_metadata(self, profiles: list[Path]) -> dict[str, Any]:
        saved: list[dict[str, Any]] = []
        # cmdkey.exe lists target/type/user metadata and never returns secret
        # material.  Use the trusted System32 binary, not a PATH-resolved shim.
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        cmdkey = system_root / "System32" / "cmdkey.exe"
        if self._path_is_file(cmdkey):
            output = self._run([str(cmdkey), "/list"])
            current: dict[str, Any] = {}
            for raw in output.splitlines():
                line = raw.strip()
                match = re.match(r"(?i)(Target|Type|User):\s*(.*)", line)
                if not match:
                    continue
                key, value = match.group(1).lower(), match.group(2)
                if key == "target" and current:
                    saved.append(current)
                    current = {}
                current[key] = _redact_text(value, 512)
            if current:
                saved.append(current)

        files: list[dict[str, Any]] = []
        for profile in profiles:
            known_dirs = (
                ("aws", profile / ".aws"), ("azure", profile / ".azure"),
                ("docker", profile / ".docker"), ("kubernetes", profile / ".kube"),
                ("ssh", profile / ".ssh"), ("codex", profile / ".codex"),
                ("claude", profile / ".claude"),
            )
            for kind, root in known_dirs:
                for path in self._walk_files(root, 3, 128, None):
                    if len(files) >= _MAX_RECORDS:
                        break
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    files.append({
                        "kind": kind, "path": str(path), "name": path.name,
                        "size": stat.st_size, "modified_at": int(stat.st_mtime),
                        "content_collected": False,
                    })
            for name in (".env", ".env.local", ".netrc", "credentials.json", "secrets.json"):
                path = profile / name
                if self._path_is_file(path):
                    files.append({
                        "kind": "likely_secret", "path": str(path), "name": path.name,
                        "size": self._size(path), "modified_at": self._mtime(path),
                        "content_collected": False,
                    })
        if files:
            self._finding("credential_files_present", "info", "credentials", "Credential or secret-bearing files are present", f"{len(files)} metadata-only records")
        return {"saved_credentials": saved[:_MAX_RECORDS], "files": files[:_MAX_RECORDS]}

    def _trusted_docker(self) -> Path | None:
        candidates: list[Path] = []
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if base:
                candidates.extend((
                    Path(base) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
                    Path(base) / "Docker" / "resources" / "bin" / "docker.exe",
                ))
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        candidates.append(system_root / "System32" / "docker.exe")
        return next((p for p in candidates if self._path_is_file(p)), None)

    def _docker_audit(self) -> dict[str, Any]:
        docker = self._trusted_docker()
        result: dict[str, Any] = {
            "available": bool(docker), "client": str(docker) if docker else None,
            "containers": [], "images": [], "volumes": [], "networks": [],
            "user_resolved_cli_executed": False,
        }
        if not docker:
            return result
        ps_output = self._run([str(docker), "ps", "--all", "--no-trunc", "--format", "{{json .}}"])
        summaries = []
        for line in ps_output.splitlines()[:128]:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    summaries.append(item)
            except (ValueError, json.JSONDecodeError):
                continue
        ids = [str(x.get("ID") or x.get("Id") or "") for x in summaries if x.get("ID") or x.get("Id")]
        inspected: list[dict[str, Any]] = []
        if ids and time.monotonic() < self._deadline:
            raw = self._run([str(docker), "inspect", *ids[:64]])
            try:
                parsed = json.loads(raw or "[]")
                inspected = [x for x in _as_list(parsed) if isinstance(x, dict)]
            except (ValueError, json.JSONDecodeError):
                inspected = []
        by_id = {str(x.get("Id") or ""): x for x in inspected}
        for summary in summaries:
            container_id = str(summary.get("ID") or summary.get("Id") or "")
            detail = by_id.get(container_id) or next((v for key, v in by_id.items() if key.startswith(container_id)), {})
            host = detail.get("HostConfig") if isinstance(detail.get("HostConfig"), dict) else {}
            config = detail.get("Config") if isinstance(detail.get("Config"), dict) else {}
            mounts = detail.get("Mounts") if isinstance(detail.get("Mounts"), list) else []
            cap_add = [str(x) for x in _as_list(host.get("CapAdd"))]
            environment_names = sorted({str(x).split("=", 1)[0] for x in _as_list(config.get("Env"))})[:256]
            sensitive_env_names = [name for name in environment_names if _SECRET_RE.search(name)]
            socket_mount = any("docker.sock" in str(m.get("Source") or "").lower() for m in mounts if isinstance(m, dict))
            host_root_mount = any(
                str(m.get("Source") or "").rstrip("\\/").upper() in {"", "C:"}
                for m in mounts if isinstance(m, dict) and m.get("Source")
            )
            network_mode = str(host.get("NetworkMode") or "")
            risks = []
            if bool(host.get("Privileged")):
                risks.append("privileged")
            if socket_mount:
                risks.append("docker_socket_mount")
            if host_root_mount:
                risks.append("host_root_mount")
            if network_mode.lower() == "host":
                risks.append("host_network")
            if any(cap.upper() == "SYS_ADMIN" for cap in cap_add):
                risks.append("sys_admin")
            if sensitive_env_names:
                risks.append("sensitive_environment_names")
            image_name = str(config.get("Image") or summary.get("Image") or "")
            if image_name.endswith(":latest") or (":" not in image_name.split("/")[-1] and "@sha256:" not in image_name):
                risks.append("unpinned_image")
            record = {
                "id": container_id[:64], "name": str(summary.get("Names") or summary.get("Name") or "").lstrip("/")[:256],
                "image": image_name[:512], "state": str(summary.get("State") or summary.get("Status") or "")[:128],
                "privileged": bool(host.get("Privileged")), "network_mode": network_mode[:128] or None,
                "cap_add": cap_add[:128],
                "mounts": [{"type": m.get("Type"), "source": str(m.get("Source") or "")[:1024], "destination": str(m.get("Destination") or "")[:1024], "read_only": not bool(m.get("RW", True))} for m in mounts[:128] if isinstance(m, dict)],
                "environment_names": environment_names, "sensitive_environment_names": sensitive_env_names,
                "environment_values_collected": False, "risk_signals": risks,
            }
            result["containers"].append(record)
            if risks:
                severity = "critical" if any(x in risks for x in ("privileged", "docker_socket_mount", "host_root_mount", "sys_admin")) else "medium"
                self._finding("docker_container_risk", severity, "docker", "Docker container has elevated host exposure", f"{record['name']}: {','.join(risks)}")

        images_out = self._run([str(docker), "image", "ls", "--digests", "--no-trunc", "--format", "{{json .}}"])
        for line in images_out.splitlines()[:_MAX_RECORDS]:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    result["images"].append({
                        "repository": str(item.get("Repository") or "")[:512],
                        "tag": str(item.get("Tag") or "")[:128],
                        "digest": str(item.get("Digest") or "")[:256] or None,
                        "id": str(item.get("ID") or "")[:256],
                    })
            except (ValueError, json.JSONDecodeError):
                continue
        for key, command in (("volumes", ["volume", "ls", "--format", "{{.Name}}"]), ("networks", ["network", "ls", "--format", "{{.Name}}"])):
            output = self._run([str(docker), *command])
            result[key] = [line.strip()[:512] for line in output.splitlines()[:_MAX_RECORDS] if line.strip()]
        return result

    # ---- Bounded filesystem helpers -------------------------------------

    def _walk_files(self, root: Path, max_depth: int, limit: int,
                    extensions: set[str] | None, exact_name: str | None = None) -> list[Path]:
        try:
            usable_root = root.is_dir()
        except OSError:
            usable_root = False
        if not usable_root or limit <= 0:
            return []
        found: list[Path] = []
        base_depth = len(root.parts)
        visited = 0
        try:
            for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
                visited += 1
                if visited > 2000 or len(found) >= limit or time.monotonic() >= self._deadline:
                    break
                current_path = Path(current)
                depth = len(current_path.parts) - base_depth
                dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "Cache", "Code Cache", "GPUCache"}]
                if depth >= max_depth:
                    dirs[:] = []
                for name in files:
                    if exact_name is not None and name.lower() != exact_name.lower():
                        continue
                    path = current_path / name
                    if extensions is not None and path.suffix.lower() not in extensions:
                        continue
                    if _within(path, root):
                        found.append(path)
                        if len(found) >= limit:
                            break
        except OSError:
            pass
        return found

    @staticmethod
    def _size(path: Path) -> int | None:
        try:
            return path.stat().st_size
        except OSError:
            return None

    @staticmethod
    def _path_is_file(path: Path) -> bool:
        try:
            return path.is_file()
        except OSError:
            return False

    @staticmethod
    def _path_is_dir(path: Path) -> bool:
        try:
            return path.is_dir()
        except OSError:
            return False

    @staticmethod
    def _mtime(path: Path) -> int | None:
        try:
            return int(path.stat().st_mtime)
        except OSError:
            return None


__all__ = [
    "WindowsSecurityAuditCollector",
    "_redact_text",
    "_sanitize_args",
    "_strip_jsonc",
]
