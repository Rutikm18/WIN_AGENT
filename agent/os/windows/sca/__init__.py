"""
agent/os/windows/sca — Security Configuration Assessment package.

Self-contained CIS-benchmark configuration-audit engine for the Windows agent.

Exports:
    ScaEngine        — policy evaluator (runner-driven, never raises)
    load_policies    — operator drop-in loader (JSON always; YAML if PyYAML present)
    BUNDLED_POLICIES — the built-in Windows baseline policy list
"""
from __future__ import annotations

from .engine import ScaEngine, load_policies
from .cis_windows import BUNDLED_POLICIES, POLICY

__all__ = ["ScaEngine", "load_policies", "BUNDLED_POLICIES", "POLICY"]
