"""
agent/os/windows/collectors/__init__.py — Windows collector registry.

Maps section name → callable collector instance.
Same interface as agent/agent/collectors/__init__.py so core.py can
swap implementations transparently on OS detection.
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

# Instantiated once at import time — collectors are stateless singletons.
COLLECTORS: dict[str, object] = {
    c.name: c()
    for c in [
        # volatile  (10 s)
        MetricsCollector, ConnectionsCollector, ProcessesCollector,
        # network   (30 s – 2 min)
        PortsCollector, NetworkCollector, ArpCollector, MountsCollector,
        # system    (2 min)
        BatteryCollector, OpenFilesCollector, ServicesCollector,
        UsersCollector, HardwareCollector, ContainersCollector,
        # posture   (1 hr)
        SecurityCollector, SysctlCollector, ConfigsCollector,
        # inventory (10 min – 24 hr)
        StorageCollector, TasksCollector, AppsCollector,
        PackagesCollector, BinariesCollector, SbomCollector,
    ]
}

__all__ = ["COLLECTORS"]
