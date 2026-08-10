"""
agent/os/windows/collectors/__init__.py — Windows collector registry.

Maps section name → callable collector instance.
Same interface as agent/agent/collectors/__init__.py so core.py can
swap implementations transparently on OS detection.
"""
from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping

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
from .sca       import ScaCollector
from .eventlog  import EventLogCollector
from .security_audit import WindowsSecurityAuditCollector

_COLLECTOR_TYPES = [
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
        # security configuration assessment (12 hr)
        ScaCollector,
        # windows-only (5 min)
        EventLogCollector,
        # developer/AI security audit (6 hr)
        WindowsSecurityAuditCollector,
]


class _LazyCollectorRegistry(Mapping[str, object]):
    """Construct collectors only when requested by the runtime scheduler.

    EventLog and SCA collectors load persistent cursors in their constructors.
    Eager construction at module import made harmless operations such as test
    discovery and diagnostics depend on access to protected ProgramData.
    """

    def __init__(self, collector_types: list[type]) -> None:
        self._types = {
            collector_type.name: collector_type
            for collector_type in collector_types
        }
        self._instances: dict[str, object] = {}
        self._lock = threading.Lock()

    def __getitem__(self, name: str) -> object:
        try:
            collector_type = self._types[name]
        except KeyError:
            raise KeyError(name) from None
        instance = self._instances.get(name)
        if instance is None:
            with self._lock:
                instance = self._instances.get(name)
                if instance is None:
                    instance = collector_type()
                    self._instances[name] = instance
        return instance

    def __iter__(self) -> Iterator[str]:
        return iter(self._types)

    def __len__(self) -> int:
        return len(self._types)

    def __contains__(self, name: object) -> bool:
        return name in self._types


COLLECTORS: Mapping[str, object] = _LazyCollectorRegistry(_COLLECTOR_TYPES)

__all__ = ["COLLECTORS", "EventLogCollector", "WindowsSecurityAuditCollector"]
