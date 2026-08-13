"""Shared manager-side analysis for Windows persistence change telemetry."""
from __future__ import annotations

from typing import Any, Callable


_MITRE_BY_SURFACE = {
    "run_key": "T1547.001",
    "startup_folder": "T1547.001",
    "scheduled_task": "T1053.005",
    "service": "T1543.003",
    "driver": "T1543.003",
    "wmi_filter": "T1546.003",
    "wmi_consumer": "T1546.003",
    "wmi_binding": "T1546.003",
    "ifeo": "T1546.012",
    "com_hijack": "T1546.015",
    "appinit": "T1546.010",
    "winlogon": "T1547.004",
    "winlogon_notify": "T1547.004",
    "lsa_package": "T1547.005",
    "security_provider": "T1547.005",
    "print_monitor": "T1547.010",
    "netsh_helper": "T1546.007",
}

_HIGH_RISK = {
    "wmi_filter", "wmi_consumer", "wmi_binding", "ifeo", "com_hijack",
    "appinit", "winlogon_notify", "lsa_package", "security_provider",
    "print_monitor", "netsh_helper",
}


def analyze_persistence(
    data: Any,
    make_finding: Callable[..., dict],
) -> list[dict]:
    """Turn baseline deltas into deterministic, deduplicated findings."""
    if not isinstance(data, list):
        return []
    findings: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        change = str(item.get("change") or "").lower()
        if change not in {"added", "modified", "removed"}:
            continue
        surface = str(item.get("surface") or "unknown").lower()
        name = str(item.get("name") or "unnamed")
        location = str(item.get("location") or "")
        entry_id = str(item.get("entry_id") or f"{surface}:{location}:{name}")
        high_risk = surface in _HIGH_RISK
        if change == "removed":
            severity, score = ("medium", 5.0) if high_risk else ("low", 3.0)
        else:
            severity, score = ("high", 7.5) if high_risk else ("medium", 5.5)
        findings.append(make_finding(
            category="persistence",
            item_key=f"persistence:{entry_id}:{change}",
            severity=severity,
            score=score,
            title=f"Persistence {change}: {surface} — {name}",
            desc=(
                f"Windows persistence entry was {change} at {location or 'an unknown location'}. "
                "Validate the owning software, signer, and change authorization."
            ),
            evidence=item,
            source="rule:persistence_change",
            mitre=_MITRE_BY_SURFACE.get(surface, "T1547"),
            tags=["windows", "persistence", surface, change],
        ))
    return findings


__all__ = ["analyze_persistence"]
