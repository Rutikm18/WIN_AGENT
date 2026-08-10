"""Windows named-mutex guard for the AttackLens agent service."""
from __future__ import annotations

import ctypes
import os
from typing import Any

ERROR_ALREADY_EXISTS = 183
DEFAULT_MUTEX_NAME = r"Global\AttackLensAgent"


class AlreadyRunningError(RuntimeError):
    """Raised when another agent process owns the global mutex."""


class SingleInstanceGuard:
    """Own a kernel mutex for the process lifetime.

    Windows closes the handle automatically on process termination, including
    crashes. The explicit release path keeps foreground/debug runs tidy.
    """

    def __init__(
        self,
        name: str = DEFAULT_MUTEX_NAME,
        *,
        kernel32: Any | None = None,
        get_last_error: Any | None = None,
    ) -> None:
        self.name = name
        self._kernel32 = kernel32
        self._get_last_error = get_last_error
        self._handle: Any = None

    @property
    def acquired(self) -> bool:
        return bool(self._handle)

    def acquire(self) -> "SingleInstanceGuard":
        if self.acquired:
            return self
        if os.name != "nt" and self._kernel32 is None:
            # The production module is Windows-only. A no-op elsewhere keeps
            # source validation and documentation tooling portable.
            self._handle = object()
            return self

        kernel32 = self._kernel32 or ctypes.WinDLL("kernel32", use_last_error=True)
        create_mutex = kernel32.CreateMutexW
        if self._kernel32 is None:
            create_mutex.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
            create_mutex.restype = ctypes.c_void_p

        handle = create_mutex(None, False, self.name)
        last_error = (
            int(self._get_last_error())
            if self._get_last_error is not None
            else int(ctypes.get_last_error())
        )
        if not handle:
            raise OSError(last_error, f"CreateMutexW failed for {self.name}")
        if last_error == ERROR_ALREADY_EXISTS:
            try:
                kernel32.CloseHandle(handle)
            finally:
                raise AlreadyRunningError(
                    f"another AttackLens agent instance owns {self.name}"
                )
        self._kernel32 = kernel32
        self._handle = handle
        return self

    def release(self) -> None:
        if not self.acquired:
            return
        handle, self._handle = self._handle, None
        if os.name != "nt" and not self._kernel32:
            return
        kernel32 = self._kernel32
        if kernel32 is not None:
            try:
                kernel32.ReleaseMutex(handle)
            finally:
                kernel32.CloseHandle(handle)

    def __enter__(self) -> "SingleInstanceGuard":
        return self.acquire()

    def __exit__(self, *_: Any) -> None:
        self.release()
