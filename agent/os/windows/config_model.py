"""Typed and defensive configuration loading for the Windows agent.

The service must reject an invalid configuration before it performs network,
enrollment, or collector work.  This module deliberately contains no Windows
API calls so it can be unit-tested on any platform.
"""
from __future__ import annotations

import copy
import os
import ntpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10 and older
    import tomli as tomllib  # type: ignore[no-reuse-import]


SUPPORTED_COLLECTIONS = frozenset({
    "metrics", "connections", "processes", "ports", "network", "arp",
    "mounts", "battery", "openfiles", "services", "users", "hardware",
    "containers", "storage", "tasks", "apps", "packages", "binaries",
    "sbom", "security", "sysctl", "configs", "sca", "eventlog",
    "security_audit", "developer_security", "persistence",
})
ALLOWED_TOP_LEVEL = frozenset({
    "agent", "manager", "enrollment", "paths", "logging", "collection",
    "policy", "response", "transport", "diagnostics", "config_schema",
})
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _programdata() -> str:
    return os.environ.get("PROGRAMDATA", r"C:\ProgramData")


def default_paths() -> dict[str, str]:
    base = os.path.join(_programdata(), "AttackLens")
    return {
        "config_dir": os.path.join(base, "config"),
        "security_dir": os.path.join(base, "security"),
        "log_dir": os.path.join(base, "logs"),
        "spool_dir": os.path.join(base, "spool"),
        "data_dir": os.path.join(base, "data"),
        "status_dir": os.path.join(base, "status"),
    }


class ConfigValidationError(ValueError):
    """Validation failure containing safe, operator-facing messages."""

    def __init__(self, errors: list[str] | tuple[str, ...]):
        self.errors = tuple(errors)
        super().__init__("agent.toml validation failed:\n" +
                         "\n".join(f"  - {error}" for error in self.errors))


@dataclass(frozen=True)
class AgentConfig:
    id: str
    name: str


@dataclass(frozen=True)
class ManagerConfig:
    url: str
    tls_verify: bool | str = False
    ca_bundle: str | None = None
    spki_pin: str | None = None
    timeout_sec: int = 30
    allow_insecure_transport: bool = True
    api_key: str | None = None
    proxy_url: str | None = None
    proxy_pac_url: str | None = None
    proxy_auto_detect: bool = True

    @property
    def effective_tls_verify(self) -> bool | str:
        return self.ca_bundle or self.tls_verify


@dataclass(frozen=True)
class CollectionConfig:
    sections: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class RuntimeConfig:
    agent: AgentConfig
    manager: ManagerConfig
    enrollment: dict[str, Any]
    paths: dict[str, str]
    logging: dict[str, Any]
    collection: CollectionConfig
    optional: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return a compatibility dict for existing runtime modules."""
        manager: dict[str, Any] = {
            "url": self.manager.url,
            "tls_verify": self.manager.tls_verify,
            "timeout_sec": self.manager.timeout_sec,
            "allow_insecure_transport": self.manager.allow_insecure_transport,
        }
        if self.manager.ca_bundle:
            manager["ca_bundle"] = self.manager.ca_bundle
        if self.manager.spki_pin:
            manager["spki_pin"] = self.manager.spki_pin
        if self.manager.api_key:
            manager["api_key"] = self.manager.api_key
        if self.manager.proxy_url:
            manager["proxy_url"] = self.manager.proxy_url
        if self.manager.proxy_pac_url:
            manager["proxy_pac_url"] = self.manager.proxy_pac_url
        manager["proxy_auto_detect"] = self.manager.proxy_auto_detect
        result: dict[str, Any] = {
            "agent": {"id": self.agent.id, "name": self.agent.name},
            "manager": manager,
            "enrollment": copy.deepcopy(self.enrollment),
            "paths": copy.deepcopy(self.paths),
            "logging": copy.deepcopy(self.logging),
            "collection": {"sections": copy.deepcopy(self.collection.sections)},
        }
        result.update(copy.deepcopy(self.optional))
        return result


def _section(raw: Mapping[str, Any], name: str, errors: list[str]) -> Mapping[str, Any]:
    value = raw.get(name, {})
    if not isinstance(value, Mapping):
        errors.append(f"[{name}] must be a table")
        return {}
    return value


def _string(table: Mapping[str, Any], key: str, path: str, errors: list[str],
            *, required: bool = False, default: str = "") -> str:
    value = table.get(key, default)
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        errors.append(f"{path} must be a string")
        return default
    value = value.strip()
    if required and not value:
        errors.append(f"{path} is required")
    return value


def _bool(table: Mapping[str, Any], key: str, path: str, errors: list[str],
          *, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        errors.append(f"{path} must be a TOML boolean (true or false)")
        return default
    return value


def _int(table: Mapping[str, Any], key: str, path: str, errors: list[str],
         *, default: int, minimum: int, maximum: int) -> int:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{path} must be an integer")
        return default
    if not minimum <= value <= maximum:
        errors.append(f"{path} must be between {minimum} and {maximum}")
    return value


def _is_absolute_windows_path(value: str) -> bool:
    return os.path.isabs(value) or ntpath.isabs(value)


def _validate(raw: Mapping[str, Any]) -> RuntimeConfig:
    errors: list[str] = []
    unknown = sorted(set(raw) - ALLOWED_TOP_LEVEL)
    errors.extend(f"unsupported top-level section [{name}]" for name in unknown)
    schema = raw.get("config_schema", 1)
    if isinstance(schema, bool) or not isinstance(schema, int) or schema < 1:
        errors.append("config_schema must be a positive integer")

    agent_raw = _section(raw, "agent", errors)
    agent_id = _string(agent_raw, "id", "[agent] id", errors, required=True)
    agent_name = _string(agent_raw, "name", "[agent] name", errors,
                          default=os.environ.get("COMPUTERNAME", "windows-agent"))
    if agent_id and not _NAME_RE.fullmatch(agent_id):
        errors.append("[agent] id contains unsupported characters (use letters, digits, _, ., :, or -)")
    if len(agent_name) > 255:
        errors.append("[agent] name must be 255 characters or fewer")

    manager_raw = _section(raw, "manager", errors)
    # A manager is optional at install/first start. With no URL the agent
    # operates in encrypted offline-spool mode until configuration is updated.
    url = _string(manager_raw, "url", "[manager] url", errors, default="")
    allow_http = _bool(manager_raw, "allow_insecure_transport",
                       "[manager] allow_insecure_transport", errors, default=True)
    try:
        parsed = urlsplit(url) if url else None
    except ValueError:
        parsed = None
        errors.append("[manager] url is malformed")
    if parsed:
        if parsed.scheme not in {"https", "http"}:
            errors.append("[manager] url must use http:// or https://")
        elif parsed.scheme == "http" and not allow_http:
            errors.append("[manager] url must use https:// unless allow_insecure_transport = true")
        if not parsed.hostname:
            errors.append("[manager] url must include a hostname")
        if parsed.username or parsed.password:
            errors.append("[manager] url must not contain username or password")
        try:
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                errors.append("[manager] url port must be between 1 and 65535")
        except ValueError:
            errors.append("[manager] url contains an invalid port")

    tls_value = manager_raw.get("tls_verify", False)
    if not isinstance(tls_value, (bool, str)):
        errors.append("[manager] tls_verify must be a TOML boolean or a CA bundle path")
        tls_value = False
    elif isinstance(tls_value, str):
        # TOML booleans are native bools.  Reject quoted boolean-looking values
        # instead of treating them as relative CA-bundle paths; the latter
        # produces a misleading path-validation error and can hide an MSI
        # property/config-generation bug.
        normalized_tls = tls_value.strip().lower()
        if normalized_tls in {"true", "false"}:
            errors.append("[manager] tls_verify must be a TOML boolean (true or false), not a quoted string")
            tls_value = True
        elif not tls_value.strip():
            errors.append("[manager] tls_verify CA bundle path cannot be empty")
            tls_value = True
    ca_bundle = manager_raw.get("ca_bundle")
    if ca_bundle is not None and (not isinstance(ca_bundle, str) or not ca_bundle.strip()):
        errors.append("[manager] ca_bundle must be a non-empty path")
        ca_bundle = None
    if ca_bundle and tls_value is False:
        errors.append("[manager] ca_bundle cannot be combined with tls_verify = false")
    effective_ca = ca_bundle or (tls_value if isinstance(tls_value, str) else None)
    if effective_ca and not _is_absolute_windows_path(effective_ca):
        errors.append("[manager] CA bundle path must be absolute")
    spki_pin = manager_raw.get("spki_pin")
    if spki_pin is not None:
        if not isinstance(spki_pin, str) or not spki_pin.startswith("sha256//") or len(spki_pin) <= 8:
            errors.append("[manager] spki_pin must use the sha256//<base64> format")
    timeout_sec = _int(manager_raw, "timeout_sec", "[manager] timeout_sec", errors,
                       default=30, minimum=1, maximum=300)
    api_key = manager_raw.get("api_key")
    if api_key is not None and (not isinstance(api_key, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", api_key)):
        errors.append("[manager] api_key must be a 64-character hexadecimal value")
        api_key = None
    proxy_url = manager_raw.get("proxy_url")
    if proxy_url is not None:
        if not isinstance(proxy_url, str) or not proxy_url.strip():
            errors.append("[manager] proxy_url must be a non-empty URL")
            proxy_url = None
        else:
            try:
                parsed_proxy = urlsplit(proxy_url)
            except ValueError:
                parsed_proxy = None
            if (
                parsed_proxy is None
                or parsed_proxy.scheme not in {"http", "https"}
                or not parsed_proxy.hostname
            ):
                errors.append("[manager] proxy_url must use http:// or https:// and include a host")
    proxy_pac_url = manager_raw.get("proxy_pac_url")
    if proxy_pac_url is not None:
        if not isinstance(proxy_pac_url, str) or not proxy_pac_url.strip():
            errors.append("[manager] proxy_pac_url must be a non-empty URL")
            proxy_pac_url = None
        else:
            try:
                parsed_pac = urlsplit(proxy_pac_url)
            except ValueError:
                parsed_pac = None
            if (
                parsed_pac is None
                or parsed_pac.scheme not in {"http", "https"}
                or not parsed_pac.hostname
            ):
                errors.append(
                    "[manager] proxy_pac_url must use http:// or https:// and include a host"
                )
    proxy_auto_detect = _bool(
        manager_raw,
        "proxy_auto_detect",
        "[manager] proxy_auto_detect",
        errors,
        default=True,
    )

    paths_raw = _section(raw, "paths", errors)
    paths = default_paths()
    for key in paths:
        if key in paths_raw:
            value = _string(paths_raw, key, f"[paths] {key}", errors, required=True)
            if value and not _is_absolute_windows_path(value):
                errors.append(f"[paths] {key} must be an absolute Windows path")
            if value:
                paths[key] = value

    logging_raw = _section(raw, "logging", errors)
    log_level = _string(logging_raw, "level", "[logging] level", errors, default="INFO").upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        errors.append("[logging] level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
    log_file = _string(logging_raw, "file", "[logging] file", errors,
                       default=os.path.join(paths["log_dir"], "agent.log"))
    max_mb = _int(logging_raw, "max_mb", "[logging] max_mb", errors,
                  default=10, minimum=1, maximum=1024)
    backups = _int(logging_raw, "backups", "[logging] backups", errors,
                   default=5, minimum=0, maximum=100)

    collection_raw = _section(raw, "collection", errors)
    sections_raw = collection_raw.get("sections", {})
    if not isinstance(sections_raw, Mapping):
        errors.append("[collection] sections must be a table")
        sections_raw = {}
    sections: dict[str, dict[str, Any]] = {}
    for name, value in sections_raw.items():
        if name not in SUPPORTED_COLLECTIONS:
            errors.append(f"[collection.sections.{name}] is not a supported Windows collector")
            continue
        if not isinstance(value, Mapping):
            errors.append(f"[collection.sections.{name}] must be a table")
            continue
        enabled = value.get("enabled", True)
        if not isinstance(enabled, bool):
            errors.append(f"[collection.sections.{name}] enabled must be a TOML boolean")
            enabled = True
        interval = value.get("interval_sec", 300)
        if isinstance(interval, bool) or not isinstance(interval, int):
            errors.append(f"[collection.sections.{name}] interval_sec must be an integer")
            interval = 300
        elif not 1 <= interval <= 604800:
            errors.append(f"[collection.sections.{name}] interval_sec must be between 1 and 604800")
        sections[name] = {"enabled": enabled, "interval_sec": interval}

    enrollment_raw = _section(raw, "enrollment", errors)
    enrollment = dict(enrollment_raw)
    if "token" in enrollment and not isinstance(enrollment["token"], str):
        errors.append("[enrollment] token must be a string")
        enrollment["token"] = ""

    transport_raw = _section(raw, "transport", errors)
    allowed_transport = {
        "initial_backoff_sec",
        "max_backoff_sec",
        "auth_failure_threshold",
        "auto_reenroll",
        "min_free_mb",
        "outbox_busy_timeout_ms",
        "delivery_stall_sec",
    }
    errors.extend(
        f"[transport] unsupported key: {key}"
        for key in sorted(set(transport_raw) - allowed_transport)
    )
    initial_backoff = _int(
        transport_raw,
        "initial_backoff_sec",
        "[transport] initial_backoff_sec",
        errors,
        default=5,
        minimum=1,
        maximum=300,
    )
    max_backoff = _int(
        transport_raw,
        "max_backoff_sec",
        "[transport] max_backoff_sec",
        errors,
        default=300,
        minimum=5,
        maximum=3600,
    )
    if max_backoff < initial_backoff:
        errors.append(
            "[transport] max_backoff_sec must be greater than or equal to "
            "initial_backoff_sec"
        )
    transport = {
        "initial_backoff_sec": initial_backoff,
        "max_backoff_sec": max_backoff,
        "auth_failure_threshold": _int(
            transport_raw,
            "auth_failure_threshold",
            "[transport] auth_failure_threshold",
            errors,
            default=3,
            minimum=1,
            maximum=20,
        ),
        "auto_reenroll": _bool(
            transport_raw,
            "auto_reenroll",
            "[transport] auto_reenroll",
            errors,
            default=False,
        ),
        "min_free_mb": _int(
            transport_raw,
            "min_free_mb",
            "[transport] min_free_mb",
            errors,
            default=128,
            minimum=16,
            maximum=102400,
        ),
        "outbox_busy_timeout_ms": _int(
            transport_raw,
            "outbox_busy_timeout_ms",
            "[transport] outbox_busy_timeout_ms",
            errors,
            default=5000,
            minimum=100,
            maximum=60000,
        ),
        "delivery_stall_sec": _int(
            transport_raw,
            "delivery_stall_sec",
            "[transport] delivery_stall_sec",
            errors,
            default=300,
            minimum=60,
            maximum=86400,
        ),
    }
    if transport["auto_reenroll"] and not str(enrollment.get("token") or "").strip():
        errors.append(
            "[transport] auto_reenroll requires a non-empty [enrollment] token "
            "so a revoked identity cannot silently use open enrollment"
        )

    if effective_ca and isinstance(effective_ca, str) and not _is_absolute_windows_path(effective_ca):
        pass  # already reported above; keep the error list deterministic

    if errors:
        raise ConfigValidationError(errors)

    optional = {key: copy.deepcopy(value) for key, value in raw.items()
                if key in {"policy", "response", "diagnostics"}}
    optional["transport"] = transport
    return RuntimeConfig(
        agent=AgentConfig(agent_id, agent_name),
        manager=ManagerConfig(
            url=url,
            tls_verify=tls_value,
            ca_bundle=ca_bundle,
            spki_pin=spki_pin,
            timeout_sec=timeout_sec,
            allow_insecure_transport=allow_http,
            api_key=api_key,
            proxy_url=proxy_url,
            proxy_pac_url=proxy_pac_url,
            proxy_auto_detect=proxy_auto_detect,
        ),
        enrollment=enrollment,
        paths=paths,
        logging={"level": log_level, "file": log_file, "max_mb": max_mb, "backups": backups},
        collection=CollectionConfig(sections),
        optional=optional,
    )


def load_config_dict(raw: Mapping[str, Any]) -> RuntimeConfig:
    """Validate an already parsed TOML mapping."""
    if not isinstance(raw, Mapping):
        raise ConfigValidationError(("configuration root must be a TOML table",))
    return _validate(raw)


def load_config(path: str | os.PathLike[str]) -> RuntimeConfig:
    """Read and validate one TOML file without leaking its contents in errors."""
    config_path = Path(path)
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError:
        raise ConfigValidationError((f"config file not found: {config_path}",)) from None
    except PermissionError:
        raise ConfigValidationError((f"config file is not readable: {config_path}",)) from None
    except tomllib.TOMLDecodeError as exc:
        # Python 3.11 exposed lineno/colno on TOMLDecodeError, but Python 3.13
        # removed those attributes.  Keep diagnostics useful where available
        # without embedding the malformed config (which may contain secrets).
        line = getattr(exc, "lineno", None)
        column = getattr(exc, "colno", None)
        if line is not None and column is not None:
            detail = f"invalid TOML near line {line}, column {column}"
        else:
            detail = "invalid TOML"
        raise ConfigValidationError((detail,)) from None
    except OSError as exc:
        raise ConfigValidationError((f"cannot read config file {config_path}: {exc.strerror or exc}",)) from None
    return _validate(raw)


def validate_config_file(path: str | os.PathLike[str]) -> RuntimeConfig:
    """Public validation entry point used by the service and CLI."""
    return load_config(path)
