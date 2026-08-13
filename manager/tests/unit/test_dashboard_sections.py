from pathlib import Path

from shared.sections import VALID_SECTION_NAMES


def test_raw_telemetry_picker_covers_every_canonical_section_and_discovers_new_ones():
    template = (
        Path(__file__).parents[2] / "dashboard" / "templates" / "index.html"
    ).read_text(encoding="utf-8")

    defaults = template.split("const DEFAULT_SECTIONS = [", 1)[1].split("];", 1)[0]
    missing = {section for section in VALID_SECTION_NAMES if f"'{section}'" not in defaults}

    assert not missing
    assert "/sections`" in template
    assert "Object.keys(summary || {})" in template
