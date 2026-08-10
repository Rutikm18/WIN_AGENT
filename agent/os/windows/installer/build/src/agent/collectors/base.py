"""
agent/agent/collectors/base.py — Abstract base class and subprocess helper.

Every collector:
  1. Subclasses BaseCollector
  2. Declares `name` (str class attribute matching agent.toml section key)
  3. Implements `collect()` — returns dict or list, NEVER raises
  4. Is callable via __call__ (drop-in for legacy function dict)

_run() is the ONLY place subprocess.run is called in the collectors.
Centralising it here allows:
  - Uniform timeout enforcement
  - Single mock point in tests
  - Consistent error handling + logging
"""
from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Union

log = logging.getLogger(__name__)

CollectorResult = Union[dict, list]


def _run(cmd: list[str], timeout: int = 10) -> str:
    """
    Run a subprocess command, return stdout as a UTF-8 string.
    Returns "" on any failure — never raises.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return result.stdout
    except FileNotFoundError:
        log.debug("Command not found: %s", cmd[0])
        return ""
    except subprocess.TimeoutExpired:
        log.warning("Collector command timed out after %ds: %s", timeout, cmd[0])
        return ""
    except Exception as exc:
        log.debug("Command failed [%s]: %s", " ".join(cmd), exc)
        return ""


class BaseCollector(ABC):
    """
    Abstract base for all data collectors.

    Subclass, declare `name`, implement `collect()`.
    Instances are callable:

        c = MetricsCollector()
        data = c()   # same as c.collect()
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Section name — must match the key in COLLECTORS and agent.toml."""
        ...

    @abstractmethod
    def collect(self) -> CollectorResult:
        """
        Collect section data.
        Must return {} or [] on failure — must never raise.
        """
        ...

    def __call__(self) -> CollectorResult:
        """Make collector instances callable (drop-in for plain functions)."""
        return self.collect()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} section={self.name!r}>"
