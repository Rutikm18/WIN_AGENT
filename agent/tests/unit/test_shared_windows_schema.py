from __future__ import annotations

from shared.schema import validate_section


def test_windows_eventlog_section_is_canonical() -> None:
    assert validate_section("eventlog", [{
        "event_id": 4688,
        "timestamp": 1_700_000_000,
        "computer": "HOST-1",
        "channel": "Security",
        "category": "process_create",
        "subject": "DOMAIN\\user",
        "detail": {"image": r"C:\Windows\System32\cmd.exe"},
    }]) == []


def test_windows_security_audit_section_is_canonical() -> None:
    assert validate_section("security_audit", {
        "schema_version": 1,
        "partial": False,
        "coverage": {"developer_tools": {"status": "ok"}},
        "findings": [],
    }) == []


def test_agent_health_and_lifecycle_are_extensible_dict_sections() -> None:
    assert validate_section("agent_health", {"future_field": {"nested": True}}) == []
    assert validate_section("agent_lifecycle", {"event": "system_boot"}) == []
    assert validate_section("agent_health", []) != []
