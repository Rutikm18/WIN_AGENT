"""
shared/sections.py — Canonical section definitions.

Single source of truth for:
  - Valid section names (agent collector registry + manager API validation)
  - Default collection intervals and categories

To add a new section:
  1. Add a SectionDef entry to SECTION_DEFS below
  2. Create a collector class in agent/agent/collectors/<category>.py
  3. Register it in agent/agent/collectors/__init__.py
  4. Add a [collection.sections.<name>] block in agent.toml.example
  5. Run: make test
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class SectionDef:
    name: str
    category: str           # volatile | network | system | posture | inventory
    default_interval: int   # seconds
    description: str


SECTION_DEFS: tuple[SectionDef, ...] = (
    # ── Volatile (10 s) ──────────────────────────────────────────────────
    SectionDef("metrics",     "volatile",  10,    "CPU, RAM, swap, load average"),
    SectionDef("connections", "volatile",  10,    "Established TCP connections"),
    SectionDef("processes",   "volatile",  10,    "Top processes by CPU + RAM"),
    # ── Network (30 s – 2 min) ───────────────────────────────────────────
    SectionDef("ports",       "network",   30,    "All LISTEN sockets"),
    SectionDef("network",     "network",   120,   "Interfaces, DNS, WiFi, routing"),
    SectionDef("arp",         "network",   120,   "ARP table — local network hosts"),
    SectionDef("mounts",      "network",   120,   "Active filesystem mounts"),
    # ── System state (2 min) ─────────────────────────────────────────────
    SectionDef("battery",     "system",    120,   "Charge %, cycle count, condition"),
    SectionDef("openfiles",   "system",    120,   "Top processes by open FD count"),
    SectionDef("services",    "system",    120,   "launchd daemons and login items"),
    SectionDef("users",       "system",    120,   "Local users, groups, login history"),
    SectionDef("hardware",    "system",    120,   "USB, Thunderbolt, Bluetooth"),
    SectionDef("containers",  "system",    120,   "Docker / Podman containers"),
    # ── Storage (10 min) ─────────────────────────────────────────────────
    SectionDef("storage",     "inventory", 600,   "Disk usage per volume"),
    SectionDef("tasks",       "inventory", 600,   "Crontabs and launchd timers"),
    # ── Security posture (1 hr) ──────────────────────────────────────────
    SectionDef("security",    "posture",   3600,  "SIP, Gatekeeper, FileVault, Firewall"),
    SectionDef("sysctl",      "posture",   3600,  "Kernel security parameters"),
    SectionDef("configs",     "posture",   3600,  "Shell rc, SSH config, /etc/hosts"),
    SectionDef("sca",         "posture",   3600,  "Security configuration assessment"),
    SectionDef("eventlog",    "security",  300,   "Windows Event Log security events"),
    SectionDef("persistence", "security",  1800,  "Windows persistence inventory and changes"),
    SectionDef("developer_security", "security", 3600, "Privacy-safe developer and AI attack surface"),
    SectionDef("security_audit", "security", 21600, "Developer and AI security surface audit"),
    SectionDef("agent_health", "control",   60,    "Agent health and delivery status"),
    SectionDef("agent_lifecycle", "control", 60,   "Agent boot and lifecycle events"),
    # ── Software inventory (24 hr) ───────────────────────────────────────
    SectionDef("apps",        "inventory", 86400, "Installed .app bundles"),
    SectionDef("packages",    "inventory", 86400, "brew, pip, npm, gems"),
    SectionDef("binaries",    "inventory", 86400, "Executables in known bin dirs"),
    SectionDef("sbom",        "inventory", 86400, "Full software bill of materials"),
)

# O(1) lookup by name
SECTIONS: dict[str, SectionDef] = {s.name: s for s in SECTION_DEFS}

# Frozenset of valid names — used for fast validation in the API layer
VALID_SECTION_NAMES: FrozenSet[str] = frozenset(SECTIONS)
