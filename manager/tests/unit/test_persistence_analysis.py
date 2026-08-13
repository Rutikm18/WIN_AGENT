from manager.manager.persistence_analysis import analyze_persistence


def _finding(**kwargs):
    return kwargs


def test_only_baseline_changes_become_findings():
    rows = [
        {"entry_id": "a", "surface": "run_key", "name": "Base", "change": "baseline"},
        {"entry_id": "b", "surface": "service", "name": "Same", "change": "unchanged"},
        {"entry_id": "c", "surface": "run_key", "name": "New", "change": "added", "location": "HKLM"},
    ]
    findings = analyze_persistence(rows, _finding)
    assert len(findings) == 1
    assert findings[0]["item_key"] == "persistence:c:added"
    assert findings[0]["mitre"] == "T1547.001"


def test_high_risk_change_is_high_severity_and_mitre_mapped():
    findings = analyze_persistence([{
        "entry_id": "ifeo-1", "surface": "ifeo", "name": "sethc.exe",
        "change": "modified", "location": "HKLM\\...\\IFEO",
    }], _finding)
    assert findings[0]["severity"] == "high"
    assert findings[0]["score"] == 7.5
    assert findings[0]["mitre"] == "T1546.012"
    assert "modified" in findings[0]["tags"]


def test_removed_and_invalid_inputs_are_handled_safely():
    assert analyze_persistence({}, _finding) == []
    findings = analyze_persistence([
        None,
        {"entry_id": "wmi-1", "surface": "wmi_binding", "name": "Binding", "change": "removed"},
    ], _finding)
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
