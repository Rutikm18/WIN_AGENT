"""Behavior tests for the Windows named-mutex single-instance guard."""
from __future__ import annotations

import os
import subprocess
import sys
import uuid

import pytest

from agent.os.windows.single_instance import (
    AlreadyRunningError,
    SingleInstanceGuard,
)


class FakeKernel:
    def __init__(self, handle=321):
        self.handle = handle
        self.created = []
        self.released = []
        self.closed = []

    def CreateMutexW(self, security, initial_owner, name):
        self.created.append((security, bool(initial_owner), str(name)))
        return self.handle

    def ReleaseMutex(self, handle):
        self.released.append(handle)
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


def test_guard_takes_initial_ownership_and_release_is_idempotent():
    kernel = FakeKernel()
    guard = SingleInstanceGuard(
        kernel32=kernel,
        get_last_error=lambda: 0,
    )
    assert guard.acquire() is guard
    assert guard.acquire() is guard
    assert kernel.created == [(None, True, r"Global\AttackLensAgent")]

    guard.release()
    guard.release()
    assert kernel.released == [321]
    assert kernel.closed == [321]


def test_duplicate_handle_is_closed_without_releasing_foreign_mutex():
    kernel = FakeKernel()
    with pytest.raises(AlreadyRunningError):
        SingleInstanceGuard(
            kernel32=kernel,
            get_last_error=lambda: 183,
        ).acquire()
    assert kernel.released == []
    assert kernel.closed == [321]


def test_create_mutex_failure_reports_win32_error():
    kernel = FakeKernel(handle=0)
    with pytest.raises(OSError) as exc_info:
        SingleInstanceGuard(
            kernel32=kernel,
            get_last_error=lambda: 5,
        ).acquire()
    assert exc_info.value.errno == 5
    assert kernel.closed == []


@pytest.mark.skipif(os.name != "nt", reason="requires the Windows kernel mutex API")
def test_real_global_mutex_blocks_a_second_process():
    name = rf"Global\AttackLensAgent-Test-{uuid.uuid4()}"
    guard = SingleInstanceGuard(name=name).acquire()
    child = """
import sys
from agent.os.windows.single_instance import AlreadyRunningError, SingleInstanceGuard
try:
    SingleInstanceGuard(name=sys.argv[1]).acquire()
except AlreadyRunningError:
    raise SystemExit(23)
raise SystemExit(0)
"""
    try:
        result = subprocess.run(
            [sys.executable, "-c", child, name],
            check=False,
            timeout=15,
        )
        assert result.returncode == 23
    finally:
        guard.release()
