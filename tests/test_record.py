import copy
import json
from pathlib import Path

import pytest

from sdlc.record import validate_record

FIXTURE = Path(__file__).parent / "fixtures" / "records" / "valid.json"
AT = "2026-10-09T09:00:00+00:00"


def section(record, *alerts):
    return {
        "ref": "main",
        "commit": record["subject"]["commit"],
        "is_scanned_commit": True,
        "read_at": AT,
        "alerts": list(alerts),
    }


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
            "alerts neither read nor listed as unavailable",
            lambda r: r.update(gaps=[]),
            "no gap says why the alerts weren't read",
        ),
        (
            "alerts read and listed as unavailable",
            lambda r: r.update(dependabot_alerts=section(r)),
            "present, but a gap says the alerts weren't read",
        ),
        (
            "a vulnerability citing an alert the record doesn't have",
            lambda r: r["vulnerabilities"][0].update(dependabot_alerts=[3]),
            "alert 3 isn't matched",
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


def with_alerts(record, *alerts):
    record = copy.deepcopy(record)
    record["gaps"] = [g for g in record["gaps"] if g["subject"] != "dependabot-alerts"]
    record["dependabot_alerts"] = section(record, *alerts)
    return record


def alert(number, result, **fields):
    return {
        "number": number,
        "advisory": "GHSA-xxxx-yyyy-zzzz",
        "ecosystem": "go",
        "package": "golang.org/x/crypto",
        "manifest": "proxy/go.mod",
        "fixed_version": None,
        "result": result,
    } | fields


def test_read_alerts_replace_the_gap(record):
    matched = with_alerts(
        record, alert(3, "matched", dependency="gomod:proxy/go.mod:golang.org/x/crypto")
    )
    matched["vulnerabilities"][0]["dependabot_alerts"] = [3]
    assert validate_record(matched) == []
    assert validate_record(with_alerts(record, alert(4, "unmatched"))) == []


@pytest.mark.parametrize(
    ("description", "alerts", "cited", "expected"),
    [
        (
            "a matched alert no vulnerability lists",
            [alert(3, "matched")],
            None,
            "no vulnerability lists it",
        ),
        (
            "a vulnerability citing an unmatched alert",
            [alert(3, "unmatched")],
            [3],
            "isn't matched",
        ),
        (
            "an alert on an unknown dependency",
            [alert(3, "unmatched", dependency="gomod:nowhere:x")],
            None,
            "unknown dependency id 'gomod:nowhere:x'",
        ),
        ("an unknown alert result", [alert(3, "maybe")], None, "is not one of"),
        (
            "the same alert twice",
            [alert(3, "unmatched"), alert(3, "unmatched")],
            None,
            "duplicate alert 3",
        ),
        (
            "a match elsewhere no vulnerability lists",
            [alert(3, "matched_elsewhere")],
            None,
            "no vulnerability lists it",
        ),
    ],
)
def test_alerts_are_checked(record, description, alerts, cited, expected):
    changed = with_alerts(record, *alerts)
    if cited:
        changed["vulnerabilities"][0]["dependabot_alerts"] = cited
    problems = validate_record(changed)
    assert any(expected in p for p in problems), (description, problems)
