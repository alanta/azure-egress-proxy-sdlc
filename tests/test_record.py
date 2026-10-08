import copy
import json
from pathlib import Path

import pytest

from sdlc.record import validate_record

FIXTURE = Path(__file__).parent / "fixtures" / "records" / "valid.json"


@pytest.fixture
def record():
    return json.loads(FIXTURE.read_text())


def broken(record, change):
    record = copy.deepcopy(record)
    change(record)
    return validate_record(record)


def test_valid_record_passes(record):
    assert validate_record(record) == []


@pytest.mark.parametrize(
    ("description", "change", "expected"),
    [
        (
            "missing commit",
            lambda r: r["subject"].pop("commit"),
            "'commit' is a required property",
        ),
        (
            "abbreviated commit",
            lambda r: r["subject"].update(commit="064aa09"),
            "does not match",
        ),
        (
            "unknown candidate classification",
            lambda r: r["candidates"][0].update(classification="maybe"),
            "is not one of",
        ),
        (
            "held candidate without the rule that holds it",
            lambda r: r["candidates"][1].pop("held_by"),
            "'held_by' is a required property",
        ),
        (
            "unknown parity result",
            lambda r: r["parity"]["pull_requests"][0]["updates"][0].update(result="unknown"),
            "is not one of",
        ),
        (
            "failed lookup without a reason",
            lambda r: r["inventory"][2]["lookup"].update(state="unknown"),
            "'reason' is a required property",
        ),
        (
            "end of life without a date",
            lambda r: r["lifecycle"][0].pop("end_of_life"),
            "'end_of_life' is a required property",
        ),
        (
            "wrong schema version",
            lambda r: r.update(schema_version="2"),
            "'1' was expected",
        ),
        (
            "unexpected field",
            lambda r: r.update(risk="low"),
            "Additional properties are not allowed",
        ),
    ],
)
def test_schema_rejects(record, description, change, expected):
    problems = broken(record, change)
    assert any(expected in p for p in problems), (description, problems)


@pytest.mark.parametrize(
    ("description", "change", "expected"),
    [
        (
            "candidate for an unknown dependency",
            lambda r: r["candidates"][0].update(dependency="nuget:nowhere:Nothing"),
            "unknown dependency id 'nuget:nowhere:Nothing'",
        ),
        (
            "duplicate dependency id",
            lambda r: r["inventory"].append(copy.deepcopy(r["inventory"][2])),
            "duplicate dependency id",
        ),
        (
            "outdated dependency without candidates",
            lambda r: r["inventory"][2]["lookup"].update(state="outdated"),
            "is outdated but has no candidates",
        ),
        (
            "candidates for a dependency that is current",
            lambda r: r["inventory"][0]["lookup"].update(state="current"),
            "has candidates but its lookup is 'current'",
        ),
        (
            "timestamp without a time zone",
            lambda r: r.update(scanned_at="2026-10-08T09:00:00"),
            "has no time zone",
        ),
        (
            "complete parity with an unparseable PR",
            lambda r: r["parity"]["pull_requests"][0].update(state="unparseable"),
            "true although a pull request is unparseable",
        ),
    ],
)
def test_consistency_rejects(record, description, change, expected):
    problems = broken(record, change)
    assert any(expected in p for p in problems), (description, problems)
