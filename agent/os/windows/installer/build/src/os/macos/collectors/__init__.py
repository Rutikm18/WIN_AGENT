"""
agent/os/macos/collectors — macOS ARM64 collector registry.

Each submodule groups related collectors:

  base.py      — macOS-specific helpers (JSON system_profiler, codesign, etc.)
  volatile.py  — high-frequency: metrics, connections, processes       (10 s)
  network.py   — network state:  ports, network, arp, mounts           (30 s – 2 min)
  system.py    — system state:   battery, openfiles, services,
                                  users, hardware, containers           (2 min)
  posture.py   — security posture: security, sysctl, configs           (1 hr)
  inventory.py — software:        storage, tasks, apps, packages,
                                  binaries, sbom                        (10 min – 24 hr)
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
