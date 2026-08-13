from agent.os.windows.eventlog_source import register_event_source


def test_register_event_source_uses_application_log_and_message_dll():
    calls = []

    def add(*args, **kwargs):
        calls.append((args, kwargs))

    result = register_event_source(
        add_source_fn=add,
        message_dll=r"C:\Program Files\AttackLens\win32evtlog.pyd",
    )
    assert result["registered"] is True
    assert calls == [(("AttackLensAgent",), {
        "msgDLL": r"C:\Program Files\AttackLens\win32evtlog.pyd",
        "eventLogType": "Application",
    })]


def test_register_event_source_returns_structured_failure():
    def denied(*_args, **_kwargs):
        raise PermissionError("denied")

    result = register_event_source(add_source_fn=denied)
    assert result["registered"] is False
    assert result["supported"] is True
    assert "PermissionError" in result["error"]
