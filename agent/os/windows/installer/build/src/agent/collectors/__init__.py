"""
agent/agent/collectors — Modular data collector registry.

Each submodule groups logically related collectors:

  volatile.py   — high-frequency:  metrics, connections, processes      (10 s)
  network.py    — network state:   ports, network, arp, mounts          (30 s – 2 min)
  system.py     — system state:    battery, openfiles, services,
                                   users, hardware, containers           (2 min)
  posture.py    — security posture: security, sysctl, configs           (1 hr)
  inventory.py  — software:        storage, tasks, apps, packages,
                                   binaries, sbom                        (10 min – 24 hr)

────────────────────────────────────────────────────────────────────────────────
To add a new collector (takes ~5 minutes):

  1. Choose the right submodule (or create a new one).
  2. Subclass BaseCollector:

       class MyCollector(BaseCollector):
           name = "my_section"

           def collect(self) -> dict:
               return {"key": _run(["some_command"])}

  3. Import and register it in the COLLECTORS dict below.
  4. Add an entry in shared/sections.py (for API validation).
  5. Add a [collection.sections.my_section] block in agent.toml.example.
  6. Run: make test
────────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from .volatile  import MetricsCollector, ConnectionsCollector, ProcessesCollector
from .network   import PortsCollector, NetworkCollector, ArpCollector, MountsCollector
from .system    import (
    BatteryCollector, OpenFilesCollector, ServicesCollector,
    UsersCollector, HardwareCollector, ContainersCollector,
)
from .posture   import SecurityCollector, SysctlCollector, ConfigsCollector
from .inventory import (
    StorageCollector, TasksCollector, AppsCollector,
    PackagesCollector, BinariesCollector, SbomCollector,
)

# ── Collector registry ────────────────────────────────────────────────────────
# Keys MUST match:
#   - [collection.sections.<key>] in agent.toml
#   - VALID_SECTION_NAMES in shared/sections.py
COLLECTORS: dict[str, object] = {
    # volatile (10 s)
    "metrics":     MetricsCollector(),
    "connections": ConnectionsCollector(),
    "processes":   ProcessesCollector(),
    # network (30 s – 2 min)
    "ports":       PortsCollector(),
    "network":     NetworkCollector(),
    "arp":         ArpCollector(),
    "mounts":      MountsCollector(),
    # system (2 min)
    "battery":     BatteryCollector(),
    "openfiles":   OpenFilesCollector(),
    "services":    ServicesCollector(),
    "users":       UsersCollector(),
    "hardware":    HardwareCollector(),
    "containers":  ContainersCollector(),
    # inventory (10 min)
    "storage":     StorageCollector(),
    "tasks":       TasksCollector(),
    # posture (1 hr)
    "security":    SecurityCollector(),
    "sysctl":      SysctlCollector(),
    "configs":     ConfigsCollector(),
    # inventory (24 hr)
    "apps":        AppsCollector(),
    "packages":    PackagesCollector(),
    "binaries":    BinariesCollector(),
    "sbom":        SbomCollector(),
}

__all__ = ["COLLECTORS"]
