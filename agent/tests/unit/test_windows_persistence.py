from __future__ import annotations


def _record(command: str = "one.exe", *, name: str = "Entry"):
    from agent.os.windows.collectors.persistence import _entry

    return _entry(
        "run_key", r"HKLM\Software\Run [64]", name,
        command=command, enabled=True, privileged=True,
        metadata={"view": "64"},
    )


def test_first_collection_establishes_baseline_only_after_commit(tmp_path):
    from agent.os.windows.collectors.persistence import PersistenceCollector
    from shared.schema import validate_section

    collector = PersistenceCollector(tmp_path)
    collector._snapshot = lambda: [_record()]  # type: ignore[method-assign]
    rows = collector.collect()
    assert [row["change"] for row in rows] == ["baseline"]
    assert not collector.baseline_path.exists()
    assert validate_section("persistence", rows) == []

    collector.commit()
    assert collector.baseline_path.is_file()
    assert collector.health_snapshot()["pending_commit"] is False


def test_diff_reports_added_modified_removed_and_unchanged(tmp_path):
    from agent.os.windows.collectors.persistence import PersistenceCollector

    collector = PersistenceCollector(tmp_path)
    collector._snapshot = lambda: [  # type: ignore[method-assign]
        _record("one.exe", name="Keep"),
        _record("old.exe", name="Modify"),
        _record("gone.exe", name="Remove"),
    ]
    collector.collect(); collector.commit()

    collector._snapshot = lambda: [  # type: ignore[method-assign]
        _record("one.exe", name="Keep"),
        _record("new.exe", name="Modify"),
        _record("added.exe", name="Add"),
    ]
    rows = collector.collect()
    changes = {row["name"]: row["change"] for row in rows}
    assert changes == {
        "Add": "added", "Keep": "unchanged",
        "Modify": "modified", "Remove": "removed",
    }
    removed = next(row for row in rows if row["name"] == "Remove")
    assert removed["status"] == "removed"
    modified = next(row for row in rows if row["name"] == "Modify")
    assert modified["metadata"]["previous_fingerprint"]


def test_rollback_does_not_advance_baseline(tmp_path):
    from agent.os.windows.collectors.persistence import PersistenceCollector

    collector = PersistenceCollector(tmp_path)
    collector._snapshot = lambda: [_record("old.exe")]  # type: ignore[method-assign]
    collector.collect(); collector.commit()
    baseline_before = collector.baseline_path.read_bytes()

    collector._snapshot = lambda: [_record("new.exe")]  # type: ignore[method-assign]
    assert collector.collect()[0]["change"] == "modified"
    collector.rollback()
    assert collector.baseline_path.read_bytes() == baseline_before

    # The same modification must replay after a failed durable enqueue.
    assert collector.collect()[0]["change"] == "modified"


def test_duplicate_snapshot_identities_are_deduplicated(tmp_path, monkeypatch):
    from agent.os.windows.collectors import persistence

    record = _record()
    monkeypatch.setattr(persistence, "_registry_entries", lambda: [record, dict(record)])
    monkeypatch.setattr(persistence, "_startup_entries", lambda: [])
    monkeypatch.setattr(persistence, "_service_entries", lambda: [])
    monkeypatch.setattr(persistence, "_task_entries", lambda: [])
    monkeypatch.setattr(persistence, "_wmi_entries", lambda: [])
    assert len(persistence.PersistenceCollector(tmp_path)._snapshot()) == 1
