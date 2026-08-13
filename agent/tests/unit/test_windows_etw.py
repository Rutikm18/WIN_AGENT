from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psutil


def test_process_start_parser_maps_pid_parent_time_and_integrity():
    from agent.os.windows.etw.process_provider import parse_process_event

    row = parse_process_event((1, {
        "ProcessID": "123", "ParentProcessID": "45",
        "CreateTime": "\u200e2026\u200e-\u200e08\u200e-\u200e11T18:27:23Z",
        "ImageName": r"\Device\HarddiskVolume3\Windows\cmd.exe",
        "MandatoryLabel": "S-1-16-12288", "ProcessTokenIsElevated": "1",
        "ProcessSequenceNumber": "99", "SessionID": "1",
    }))
    assert row["event"] == "start"
    assert row["pid"] == 123 and row["ppid"] == 45
    assert row["name"] == "cmd.exe"
    assert row["integrity_level"] == "high"
    assert row["elevated"] is True
    assert row["started_at"] is not None


def test_process_stop_parser_maps_exit_fields_and_rejects_noise():
    from agent.os.windows.etw.process_provider import parse_process_event

    row = parse_process_event((2, {
        "ProcessID": "123", "CreateTime": "2026-08-11T18:27:23Z",
        "ExitTime": "2026-08-11T18:27:24Z", "ExitCode": "5",
        "ImageName": "cmd.exe", "ProcessSequenceNumber": "99",
    }))
    assert row["event"] == "stop" and row["exit_code"] == 5
    assert row["event_at"] >= row["started_at"]
    assert parse_process_event((3, {"Task Name": "THREADSTART"})) is None


def test_dns_parser_maps_query_completion_network_and_filters_noise():
    from agent.os.windows.etw.dns_provider import parse_dns_event

    query = parse_dns_event((3006, {
        "EventHeader": {"TimeStamp": 116444736000000000, "ProcessId": 10},
        "QueryName": "example.test", "QueryType": "1",
    }))
    complete = parse_dns_event((3008, {
        "EventHeader": {"TimeStamp": 116444736010000000, "ProcessId": 10},
        "QueryName": "example.test", "QueryType": "1",
        "QueryStatus": "0", "QueryResults": "93.184.216.34",
    }))
    sent = parse_dns_event((3010, {
        "EventHeader": {"TimeStamp": 116444736020000000},
        "QueryName": "example.test", "QueryType": "1",
        "DnsServerIpAddress": "10.0.0.53", "ClientPID": "55",
    }))
    assert query["event"] == "query" and query["timestamp"] == 0
    assert complete["status"] == 0 and complete["results"] == "93.184.216.34"
    assert sent["pid"] == 55 and sent["dns_server"] == "10.0.0.53"
    assert parse_dns_event((9999, {})) is None


def test_event_buffer_is_bounded_counts_drop_and_drains_in_order():
    from agent.os.windows.etw.session import EventBuffer

    buffer = EventBuffer(2)
    buffer.append({"n": 1})
    buffer.append({"n": 2})
    buffer.append({"n": 3})
    assert buffer.stats() == {
        "received": 3, "dropped": 1, "buffered": 2, "capacity": 2,
    }
    assert buffer.drain(1) == [{"n": 2}]
    assert buffer.drain(5) == [{"n": 3}]


def test_pywintrace_session_lifecycle_and_callback_are_idempotent():
    from agent.os.windows.etw.session import PyWinTraceSession

    trace = MagicMock()
    backend = SimpleNamespace(
        GUID=lambda value: value,
        ProviderInfo=lambda *args, **kwargs: (args, kwargs),
        ETW=MagicMock(return_value=trace),
    )
    session = PyWinTraceSession(
        provider_name="Provider", provider_guid="{GUID}",
        parser=lambda raw: {"value": raw}, backend=backend,
    )
    assert session.start() is True
    assert session.start() is True
    callback = backend.ETW.call_args.kwargs["event_callback"]
    callback("event")
    assert session.drain() == [{"value": "event"}]
    session.stop()
    session.stop()
    trace.start.assert_called_once_with()
    trace.stop.assert_called_once_with()


def test_pywintrace_permission_failure_degrades_without_raise():
    from agent.os.windows.etw.session import PyWinTraceSession

    trace = MagicMock()
    trace.start.side_effect = PermissionError("denied")
    backend = SimpleNamespace(
        GUID=lambda value: value,
        ProviderInfo=lambda *args, **kwargs: object(),
        ETW=MagicMock(return_value=trace),
    )
    session = PyWinTraceSession(
        provider_name="Provider", provider_guid="{GUID}",
        parser=lambda raw: raw, backend=backend,
    )
    assert session.start() is False
    health = session.health_snapshot()
    assert health["available"] is False and "PermissionError" in health["last_error"]


def test_process_collector_adds_etw_events_to_snapshot_schema():
    from agent.os.windows.collectors.volatile import ProcessesCollector
    from agent.os.windows.normalizer import normalize
    from shared.schema import validate_section

    provider = MagicMock()
    provider.drain.return_value = [{
        "event": "stop", "pid": 123, "ppid": None, "name": "short.exe",
        "image_path": None, "started_at": 100, "event_at": 101,
        "integrity_level": None, "elevated": None, "sequence": 7,
        "session_id": 0, "exit_code": 0,
    }]
    provider.health_snapshot.return_value = {"running": True}
    collector = ProcessesCollector(event_provider=provider)
    with patch("psutil.process_iter", return_value=[]):
        rows = normalize("processes", collector.collect())
    assert rows[0]["pid"] == 123 and rows[0]["status"] == "stopped"
    assert rows[0]["_win"]["source"] == "etw"
    assert validate_section("processes", rows) == []


def test_connections_collector_keeps_dns_etw_when_socket_snapshot_fails():
    from agent.os.windows.collectors.volatile import ConnectionsCollector
    from agent.os.windows.normalizer import normalize
    from shared.schema import validate_section

    provider = MagicMock()
    provider.drain.return_value = [{
        "event": "sent", "event_id": 3010, "timestamp": 100,
        "query_name": "example.test", "query_type": 1, "status": None,
        "results": None, "pid": 55, "dns_server": "10.0.0.53",
        "interface": "Ethernet", "interface_index": 7,
    }]
    collector = ConnectionsCollector(event_provider=provider)
    with patch("psutil.process_iter", return_value=[]), patch(
        "psutil.net_connections", side_effect=PermissionError("denied")
    ), patch("psutil.Process", side_effect=psutil.NoSuchProcess(55)):
        rows = normalize("connections", collector.collect())
    assert rows[0]["proto"] == "dns" and rows[0]["remote_port"] == 53
    assert rows[0]["_win"]["query_name"] == "example.test"
    assert validate_section("connections", rows) == []
