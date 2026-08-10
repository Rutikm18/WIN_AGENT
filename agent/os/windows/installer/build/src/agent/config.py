"""
agent/agent/config.py — Validated config models for agent.conf / agent.toml.

Fail-fast at startup: if agent.conf is malformed or missing required
fields, the agent prints a clear error and exits rather than silently
failing later.

New in v2
─────────
  • [enrollment]  — first-run token + keystore backend
  • [watchdog]    — process monitor settings
  • [paths]       — canonical macOS install paths
  • [binaries]    — managed binary paths
  • api_key removed from [manager] — key lives in keystore, not config file

Usage in core.py:
    from .config import AgentConfig
    cfg = AgentConfig.from_toml("agent.conf")
    raw = cfg.to_dict()   # raw dict for legacy internal consumers
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print("ERROR: Python 3.11+ required, or: pip install tomli", file=sys.stderr)
        sys.exit(1)


# ── Sub-models ────────────────────────────────────────────────────────────────

@dataclass
class AgentIdentity:
    id: str
    name: str = "Unknown Mac"
    description: str = ""

    def __post_init__(self) -> None:
        slug = self.id.replace("-", "").replace("_", "")
        if not self.id or not slug.isalnum():
            raise ValueError(
                f"[agent] id must be alphanumeric with hyphens/underscores, "
                f"got: {self.id!r}"
            )


@dataclass
class ManagerConnectionConfig:
    url: str
    tls_verify: bool = True
    timeout_sec: int = 30
    retry_attempts: int = 3
    retry_delay_sec: int = 5
    max_queue_size: int = 500
    # api_key is NOT loaded from config — it lives in the keystore.
    # Kept here (default="") for internal compatibility only.
    api_key: str = ""

    def __post_init__(self) -> None:
        if not self.url.startswith("https://"):
            raise ValueError(
                f"[manager] url must start with https://, got: {self.url!r}"
            )
        if not self.tls_verify:
            import logging
            logging.getLogger("agent.config").warning(
                "TLS verification disabled (tls_verify = false) — "
                "acceptable only with self-signed certs in development"
            )


@dataclass
class EnrollmentConfig:
    """
    First-run enrollment settings.
    token is cleared from config after successful enrollment.
    """
    token:    str = ""          # one-time operator-issued enrollment token
    keystore: str = "keychain"  # "keychain" (macOS Keychain) | "file" (0600 file)

    def __post_init__(self) -> None:
        if self.keystore not in ("keychain", "file"):
            raise ValueError(
                f"[enrollment] keystore must be 'keychain' or 'file', "
                f"got: {self.keystore!r}"
            )


@dataclass
class WatchdogConfig:
    """Settings for the process watchdog (macintel-watchdog binary)."""
    enabled:            bool = True
    check_interval_sec: int  = 30    # how often to poll agent health
    max_restarts:       int  = 5     # crash limit within restart_window_sec
    restart_window_sec: int  = 300   # sliding window for rate-limiting restarts


@dataclass
class PathsConfig:
    """
    Canonical filesystem paths for a production macOS installation.

    Layout (set by agent/os/macos/installer/install.sh):
      /Library/Jarvis/
        bin/                         — macintel-agent, macintel-watchdog binaries
      /Library/Jarvis/
        agent.toml                   — configuration (this file)
        security/                    — API keys (chmod 700, root only)
        data/                        — telemetry queue
        spool/                       — disk spool for offline sends
      /Library/Jarvis/logs/        — rotating log files
      /Library/Jarvis/jarvis-agent.pid    — PID file
    """
    install_dir:  str = "/Library/Jarvis"
    config_dir:   str = "/Library/Jarvis"
    log_dir:      str = "/Library/Jarvis/logs"
    data_dir:     str = "/Library/Jarvis/data"
    security_dir: str = "/Library/Jarvis/security"
    spool_dir:    str = "/Library/Jarvis/spool"
    pid_file:     str = "/Library/Jarvis/jarvis-agent.pid"


@dataclass
class BinariesConfig:
    """Paths to compiled binaries managed by the watchdog."""
    agent:    str = "/Library/Jarvis/bin/macintel-agent"
    watchdog: str = "/Library/Jarvis/bin/macintel-watchdog"


@dataclass
class SectionConfig:
    enabled:      bool = True
    interval_sec: int  = 60
    send:         bool = True


@dataclass
class CollectionConfig:
    enabled:  bool = True
    tick_sec: int  = 5
    sections: dict[str, SectionConfig] = field(default_factory=dict)


@dataclass
class LoggingConfig:
    level:   str = "INFO"
    file:    str = "/Library/Jarvis/logs/agent.log"
    max_mb:  int = 10
    backups: int = 3

    _VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    def __post_init__(self) -> None:
        self.level = self.level.upper()
        if self.level not in self._VALID_LEVELS:
            raise ValueError(
                f"[logging] level must be one of {self._VALID_LEVELS}, "
                f"got: {self.level!r}"
            )


# ── Root config ───────────────────────────────────────────────────────────────

@dataclass
class AgentConfig:
    agent:      AgentIdentity
    manager:    ManagerConnectionConfig
    collection: CollectionConfig
    logging:    LoggingConfig
    enrollment: EnrollmentConfig  = field(default_factory=EnrollmentConfig)
    watchdog:   WatchdogConfig    = field(default_factory=WatchdogConfig)
    paths:      PathsConfig       = field(default_factory=PathsConfig)
    binaries:   BinariesConfig    = field(default_factory=BinariesConfig)

    @classmethod
    def from_toml(cls, path: str) -> "AgentConfig":
        """Load and validate config from a TOML file. Raises on any error."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"Config file not found: {path}\n"
                f"  Copy the example: "
                f"cp agent/config/agent.conf.example agent.conf"
            )
        with open(p, "rb") as f:
            raw = tomllib.load(f)

        try:
            agent_cfg  = AgentIdentity(**raw.get("agent", {}))
            mgr_raw    = dict(raw.get("manager", {}))
            mgr_raw.pop("api_key", None)   # never load api_key from file
            mgr_cfg    = ManagerConnectionConfig(**mgr_raw)
            coll_cfg   = _parse_collection(raw.get("collection", {}))
            log_cfg    = LoggingConfig(**raw.get("logging", {}))
            enroll_cfg = EnrollmentConfig(**raw.get("enrollment", {}))
            wd_cfg     = WatchdogConfig(**raw.get("watchdog", {}))
            paths_cfg  = PathsConfig(**raw.get("paths", {}))
            bins_cfg   = BinariesConfig(**raw.get("binaries", {}))
        except TypeError as exc:
            raise ValueError(f"Config error in {path}: {exc}") from exc

        return cls(
            agent=agent_cfg,
            manager=mgr_cfg,
            collection=coll_cfg,
            logging=log_cfg,
            enrollment=enroll_cfg,
            watchdog=wd_cfg,
            paths=paths_cfg,
            binaries=bins_cfg,
        )

    def to_dict(self) -> dict:
        """Return a raw dict for internal consumers."""
        sections = {
            name: {"enabled": s.enabled, "interval_sec": s.interval_sec,
                   "send": s.send}
            for name, s in self.collection.sections.items()
        }
        return {
            "agent":  {"id": self.agent.id, "name": self.agent.name,
                       "description": self.agent.description},
            "manager": {"url": self.manager.url, "tls_verify": self.manager.tls_verify,
                        "timeout_sec": self.manager.timeout_sec,
                        "retry_attempts": self.manager.retry_attempts,
                        "retry_delay_sec": self.manager.retry_delay_sec,
                        "max_queue_size": self.manager.max_queue_size},
            "enrollment": {"token": self.enrollment.token,
                           "keystore": self.enrollment.keystore},
            "watchdog": {"enabled": self.watchdog.enabled,
                         "check_interval_sec": self.watchdog.check_interval_sec,
                         "max_restarts": self.watchdog.max_restarts,
                         "restart_window_sec": self.watchdog.restart_window_sec},
            "paths": {"install_dir": self.paths.install_dir,
                      "config_dir": self.paths.config_dir,
                      "log_dir": self.paths.log_dir,
                      "data_dir": self.paths.data_dir,
                      "security_dir": self.paths.security_dir,
                      "spool_dir": self.paths.spool_dir,
                      "pid_file": self.paths.pid_file},
            "binaries": {"agent": self.binaries.agent,
                         "watchdog": self.binaries.watchdog},
            "collection": {"enabled": self.collection.enabled,
                           "tick_sec": self.collection.tick_sec,
                           "sections": sections},
            "logging": {"level": self.logging.level, "file": self.logging.file,
                        "max_mb": self.logging.max_mb, "backups": self.logging.backups},
        }


# ── Internal ──────────────────────────────────────────────────────────────────

def _parse_collection(raw: dict) -> CollectionConfig:
    sections_raw = dict(raw)
    sections_raw.pop("enabled",  None)
    sections_raw.pop("tick_sec", None)
    sections_per_name = sections_raw.pop("sections", {})
    sections = {
        name: SectionConfig(**cfg)
        for name, cfg in sections_per_name.items()
    }
    return CollectionConfig(
        enabled=raw.get("enabled", True),
        tick_sec=raw.get("tick_sec", 5),
        sections=sections,
    )
