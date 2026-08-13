from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock


def _backend():
    api = SimpleNamespace(
        EvtSubscribeActionError=0,
        EvtSubscribeActionDeliver=1,
        EvtSubscribeStartAfterBookmark=3,
        EvtSubscribeStartAtOldestRecord=2,
        EvtSubscribeToFutureEvents=1,
        EvtRenderEventXml=1,
        EvtRenderBookmark=2,
        EvtCreateBookmark=MagicMock(side_effect=lambda xml: ("bookmark", xml)),
        EvtSubscribe=MagicMock(return_value="subscription"),
        EvtRender=MagicMock(),
        EvtUpdateBookmark=MagicMock(),
        EvtClose=MagicMock(),
    )
    return api


def test_subscription_uses_xpath_callback_and_per_event_bookmark(tmp_path):
    from agent.os.windows.evtlog.subscription import ChannelSubscription

    api = _backend()
    api.EvtRender.side_effect = lambda handle, flag: (
        "<Event/>" if flag == api.EvtRenderEventXml else "<Bookmark RecordId='7'/>"
    )
    subscription = ChannelSubscription(
        channel="Security", event_ids=(4624, 4688),
        bookmark_path=tmp_path / "security.bookmark",
        parser=lambda xml, channel: {"event_id": 4688, "channel": channel},
        backend=api, capacity=2,
    )
    assert subscription.start() is True
    subscribe_args = api.EvtSubscribe.call_args.kwargs
    assert subscribe_args["ChannelPath"] == "Security"
    assert subscribe_args["Flags"] == api.EvtSubscribeToFutureEvents
    assert subscribe_args["Bookmark"] is None
    assert "EventID=4624" in subscribe_args["Query"]
    callback = subscribe_args["Callback"]
    assert callback(api.EvtSubscribeActionDeliver, "Security", "event") == 0
    assert subscription.drain(1) == [(
        {"event_id": 4688, "channel": "Security"},
        "<Bookmark RecordId='7'/>",
    )]
    api.EvtUpdateBookmark.assert_called_once()
    subscription.stop()
    assert api.EvtClose.call_count >= 1


def test_existing_bookmark_resumes_after_it(tmp_path):
    from agent.os.windows.evtlog.subscription import ChannelSubscription

    path = tmp_path / "security.bookmark"
    path.write_text("<Bookmark RecordId='8'/>", encoding="utf-8")
    api = _backend()
    subscription = ChannelSubscription(
        channel="Security", event_ids=(4688,), bookmark_path=path,
        parser=lambda xml, channel: {}, backend=api,
    )
    assert subscription.start() is True
    subscribe_args = api.EvtSubscribe.call_args.kwargs
    assert subscribe_args["Flags"] == api.EvtSubscribeStartAfterBookmark
    assert subscribe_args["Bookmark"] == ("bookmark", "<Bookmark RecordId='8'/>")
    assert api.EvtCreateBookmark.call_args_list[0].args[0] == "<Bookmark RecordId='8'/>"


def test_overflow_pauses_without_advancing_and_restart_clears_buffer(tmp_path):
    from agent.os.windows.evtlog.subscription import ChannelSubscription

    api = _backend()
    api.EvtRender.side_effect = lambda handle, flag: (
        "<Event/>" if flag == api.EvtRenderEventXml else f"<Bookmark>{handle}</Bookmark>"
    )
    subscription = ChannelSubscription(
        channel="Security", event_ids=(4688,),
        bookmark_path=tmp_path / "bookmark", parser=lambda xml, channel: {"event_id": 4688},
        backend=api, capacity=1,
    )
    subscription.start()
    subscription._callback(api.EvtSubscribeActionDeliver, None, "one")
    subscription._callback(api.EvtSubscribeActionDeliver, None, "two")
    assert subscription.paused is True
    assert subscription.health_snapshot()["overflow_events"] == 1
    assert subscription.restart_from_committed() is True
    assert subscription.paused is False and subscription.drain(10) == []


def test_collector_commits_bookmark_only_after_collect_and_rolls_back_by_replay(tmp_path):
    from agent.os.windows.collectors.eventlog import EventLogCollector

    record = {
        "event_id": 4688, "record_id": 7, "timestamp": 10,
        "computer": "host", "channel": "Security", "category": "process",
        "subject": "user", "detail": {},
    }
    subscription = MagicMock()
    subscription.drain.return_value = [(record, "<Bookmark RecordId='7'/>")]
    subscription.paused = False
    collector = EventLogCollector(str(tmp_path))
    collector._subscriptions = {"Security": subscription}
    collector._streaming = True
    assert collector.collect() == [record]
    path = tmp_path / "evtlog" / "Security.bookmark"
    assert not path.exists()
    collector.commit()
    assert path.read_text(encoding="utf-8") == "<Bookmark RecordId='7'/>"

    subscription.drain.return_value = [(record, "<Bookmark RecordId='8'/>")]
    collector.collect()
    collector.rollback()
    subscription.restart_from_committed.assert_called_once_with()
    assert path.read_text(encoding="utf-8") == "<Bookmark RecordId='7'/>"
