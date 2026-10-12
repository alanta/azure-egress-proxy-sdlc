import copy
import json
from pathlib import Path

import pytest

from sdlc.record import validate_record

FIXTURE = Path(__file__).parent / "fixtures" / "records" / "valid.json"
FIXTURE_V2 = Path(__file__).parent / "fixtures" / "records" / "valid.v2.json"
FIXTURE_V1 = Path(__file__).parent / "fixtures" / "records" / "valid.v1.json"
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
            "failed lookup without a reason",
            lambda r: r["inventory"][2]["lookup"].update(state="unknown"),
            "'reason' is a required property",
        ),
        (
            "nearing end of life without a date",
            lambda r: (
                r["lifecycle"][0].update(state="nearing_end_of_life"),
                r["lifecycle"][0].pop("end_of_life"),
            ),
            "'end_of_life' is a required property",
        ),
        (
            "end of life without a date or a reason",
            lambda r: r["lifecycle"][0].pop("end_of_life"),
            "'reason' is a required property",
        ),
        (
            "lifecycle line without its dependencies",
            lambda r: r["lifecycle"][0].pop("dependencies"),
            "'dependencies' is a required property",
        ),
        (
            "locked entry without why the scan lists it",
            lambda r: r["inventory"][2].update(origin="locked"),
            "'locked_because' is a required property",
        ),
        (
            "declared entry saying why it is locked",
            lambda r: r["inventory"][2].update(locked_because="drift"),
            "should not be valid",
        ),
        (
            "unknown reason for a locked entry",
            lambda r: r["inventory"][2].update(origin="locked", locked_because="habit"),
            "is not one of",
        ),
        (
            "wrong schema version",
            lambda r: r.update(schema_version="2"),
            "'3' was expected",
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
            "an inconsistency declared by an unknown dependency",
            lambda r: r["inconsistencies"].append(
                {
                    "dependency": "Aspire",
                    "declarations": [
                        {
                            "dependency": r["inventory"][0]["id"],
                            "location": r["inventory"][0]["location"],
                            "version": "13.5.4",
                        },
                        {
                            "dependency": "regex:.devcontainer/Dockerfile:Aspire.Cli",
                            "location": {"file": ".devcontainer/Dockerfile", "line": 4},
                            "version": "13.6.1",
                        },
                    ],
                }
            ),
            "unknown dependency id 'regex:.devcontainer/Dockerfile:Aspire.Cli'",
        ),
        (
            "an inconsistency that lists other declarations than were compared",
            lambda r: r["inconsistencies"].append(
                {
                    "dependency": "Aspire",
                    "declarations": [
                        {
                            "dependency": r["inventory"][0]["id"],
                            "location": r["inventory"][0]["location"],
                            "version": "13.5.4",
                        },
                        {
                            "dependency": r["inventory"][0]["id"],
                            "location": r["inventory"][0]["location"],
                            "version": "13.6.1",
                        },
                    ],
                }
            ),
            "its declarations aren't what $.consistency compared",
        ),
        (
            "a compared declaration that isn't in the inventory",
            lambda r: r["consistency"][0]["compared"].append("nuget:nowhere:Nothing"),
            "$.consistency[0].compared[1]: unknown dependency id 'nuget:nowhere:Nothing'",
        ),
        (
            "a lifecycle line used by an unknown dependency",
            lambda r: r["lifecycle"][0].update(
                dependencies=["gomod:nowhere:go"], locations=[{"file": "nowhere"}]
            ),
            "$.lifecycle[0].dependencies[0]: unknown dependency id 'gomod:nowhere:go'",
        ),
        (
            "a lifecycle line located elsewhere than its dependency",
            lambda r: r["lifecycle"][0].update(locations=[{"file": "go.mod", "line": 3}]),
            "$.lifecycle[0].locations[0]: not the location of 'gomod:proxy/go.mod:go'",
        ),
        (
            "a lifecycle line with more dependencies than locations",
            lambda r: r["lifecycle"][0]["dependencies"].append(r["inventory"][0]["id"]),
            "its dependencies and locations don't pair up",
        ),
        (
            "a data source fetched at a time without a time zone",
            lambda r: r["tools"][1].update(fetched_at="2026-10-08T09:00:00"),
            "$.tools[1].fetched_at: '2026-10-08T09:00:00' has no time zone",
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


def test_version_3_rejects_parity():
    record = json.loads(FIXTURE.read_text())
    record["parity"] = json.loads(FIXTURE_V1.read_text())["parity"]
    problems = validate_record(record)
    assert any("Additional properties are not allowed" in p for p in problems), problems


def test_version_1_record_still_passes_its_own_schema():
    assert validate_record(json.loads(FIXTURE_V1.read_text()), version="1") == []


def test_version_2_record_still_passes_its_own_schema():
    assert validate_record(json.loads(FIXTURE_V2.read_text()), version="2") == []


def test_version_3_rejects_version_2_record():
    problems = validate_record(json.loads(FIXTURE_V2.read_text()))
    assert any("'3' was expected" in p for p in problems), problems


def test_version_2_rejects_version_3_record():
    problems = validate_record(json.loads(FIXTURE.read_text()), version="2")
    assert any("'2' was expected" in p for p in problems), problems


def v3_record():
    return json.loads(FIXTURE.read_text())


def test_version_3_accepts_a_candidate_with_and_without_a_release_date():
    record = v3_record()
    assert "released_at" in record["candidates"][0]
    assert "released_at" not in record["candidates"][1]
    assert validate_record(record, version="3") == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("last Tuesday", "is not an ISO 8601 timestamp"),
        ("2026-13-45T00:00:00+00:00", "is not an ISO 8601 timestamp"),
        ("2026-09-10T03:16:59", "has no time zone"),
        (20260910, "is not of type 'string'"),
    ],
)
def test_version_3_rejects_a_malformed_release_date(value, expected):
    record = v3_record()
    record["candidates"][0]["released_at"] = value
    problems = validate_record(record, version="3")
    assert any(expected in p for p in problems), problems


def test_version_2_has_no_release_date():
    record = json.loads(FIXTURE_V2.read_text())
    record["candidates"][0]["released_at"] = "2026-09-10T03:16:59+00:00"
    problems = validate_record(record, version="2")
    assert any("Additional properties are not allowed" in p for p in problems), problems


def test_version_3_rejects_a_release_date_on_an_advisory_fix():
    record = v3_record()
    candidate = {k: v for k, v in record["candidates"][1].items() if k != "released_at"}
    record["candidates"].append({**candidate, "basis": "advisory_fix"})
    # Its advisory isn't in the fixture, which the semantic checks report either way.
    without = validate_record(record, version="3")
    record["candidates"][-1]["released_at"] = "2026-09-10T03:16:59+00:00"
    added = set(validate_record(record, version="3")) - set(without)
    assert len(added) == 1 and "should not be valid" in added.pop(), added


def test_version_3_accepts_a_candidate_with_and_without_a_group():
    record = v3_record()
    assert record["candidates"][0]["group"] == "microsoft"
    assert "group" not in record["candidates"][1]
    assert validate_record(record, version="3") == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [("", "should be non-empty"), (None, "is not of type 'string'")],
)
def test_version_3_rejects_a_malformed_group(value, expected):
    record = v3_record()
    record["candidates"][0]["group"] = value
    problems = validate_record(record, version="3")
    assert any(expected in p for p in problems), problems


def test_version_2_has_no_group():
    record = json.loads(FIXTURE_V2.read_text())
    record["candidates"][0]["group"] = "microsoft"
    problems = validate_record(record, version="2")
    assert any("Additional properties are not allowed" in p for p in problems), problems


def test_version_3_requires_the_selection():
    record = v3_record()
    del record["selection"]
    assert any("'selection' is a required property" in p for p in validate_record(record))


def test_versions_1_and_2_have_no_selection():
    for version, path in (("1", FIXTURE_V1), ("2", FIXTURE_V2)):
        record = json.loads(path.read_text())
        record["selection"] = v3_record()["selection"]
        problems = validate_record(record, version=version)
        assert any("Additional properties are not allowed" in p for p in problems), problems


def test_the_fixture_selection_has_every_kind_of_part():
    selection = v3_record()["selection"]
    assert [u["reasons"] for u in selection["units"]] == [["security"], ["lifecycle"], ["batch"]]
    assert {r["kind"] for r in selection["not_prepared"]} == {
        "no_route",
        "not_evaluated",
        "waiting",
    }


UNIT = ("selection", "units", 0)
TARGET = ("selection", "units", 0, "targets", 0)
REPORT = ("selection", "not_prepared", 0)


def at(record, path):
    for key in path:
        record = record[key]
    return record


@pytest.mark.parametrize(
    ("description", "path", "change", "expected"),
    [
        ("a reason that doesn't exist", UNIT, {"reasons": ["urgent"]}, "is not one of"),
        ("no reason", UNIT, {"reasons": []}, "should be non-empty"),
        ("an unknown field on a unit", UNIT, {"owner": "me"}, "Additional properties"),
        ("a breaking mark that isn't boolean", UNIT, {"breaking": "yes"}, "is not of type"),
        ("a unit without a target", UNIT, {"targets": []}, "should be non-empty"),
        ("an update type that doesn't exist", TARGET, {"update_type": "huge"}, "is not one of"),
        ("an age that isn't a number", TARGET, {"age_days": "old"}, "is not valid under"),
        ("an age on a date-less target", TARGET, {"age_days": 3}, "'unknown' was expected"),
        (
            "a malformed release date",
            TARGET,
            {"released_at": "2026-09", "age_days": 3},
            "is not an ISO",
        ),
        ("a report of a kind that doesn't exist", REPORT, {"kind": "stuck"}, "is not one of"),
        ("a report without its reason", REPORT, {"detail": ""}, "should be non-empty"),
        ("a report of the wrong reason", REPORT, {"reason": "batch"}, "'security' was expected"),
        ("an unknown field on a report", REPORT, {"owner": "me"}, "Additional properties"),
        (
            "a malformed date",
            ("selection",),
            {"date": "5 October"},
            "is not a 'date'",
        ),
        (
            "a window that is neither open nor closed",
            ("selection", "batch_window"),
            {"open": "maybe"},
            "is not of type 'boolean'",
        ),
        (
            "a negative minimum release age",
            ("selection", "defaults"),
            {"minimum_release_age_days": -1},
            "less than the minimum",
        ),
    ],
)
def test_a_malformed_selection_fails_the_schema(description, path, change, expected):
    record = v3_record()
    at(record, path).update(change)
    problems = validate_record(record)
    assert problems and any(expected in p for p in problems), (description, problems)


def test_a_unit_needs_the_evidence_of_each_of_its_reasons():
    for index, evidence in ((0, "advisories"), (1, "lifecycle"), (2, "batch_window")):
        record = v3_record()
        del record["selection"]["units"][index]["evidence"][evidence]
        assert validate_record(record), evidence
    record = v3_record()
    record["selection"]["units"][0]["evidence"]["lifecycle"] = [
        {"product": "go", "line": "1.25", "state": "end_of_life"}
    ]
    assert validate_record(record)


def test_a_report_needs_what_its_kind_is_about():
    for index, missing in ((0, "advisory"), (2, "old_enough_on")):
        record = v3_record()
        del record["selection"]["not_prepared"][index][missing]
        assert validate_record(record), missing


@pytest.mark.parametrize(
    ("description", "change", "expected"),
    [
        (
            "a target outside the inventory",
            lambda s: s["units"][0]["targets"][0].update(dependency="nuget:nowhere:Nothing"),
            "$.selection.units[0].targets[0].dependency: unknown dependency id",
        ),
        (
            "a target version that isn't a candidate",
            lambda s: s["units"][0]["targets"][0].update(version="v9.9.9"),
            "'v9.9.9' isn't an in-scope candidate",
        ),
        (
            "a target version nobody holds back but the policy does",
            lambda s: s["units"][0]["targets"][0].update(
                dependency="nuget:Directory.Packages.props:Microsoft.OpenApi", version="3.10.2"
            ),
            "isn't an in-scope candidate",
        ),
        (
            "a target that moves from the wrong version",
            lambda s: s["units"][0]["targets"][0].update(current="v0.1.0"),
            "not the current version",
        ),
        (
            "a target with the wrong update type",
            lambda s: s["units"][0]["targets"][0].update(update_type="major"),
            "not the update type of the candidate",
        ),
        (
            "two units with one name",
            lambda s: s["units"][1].update(name=s["units"][0]["name"]),
            "duplicate unit name",
        ),
        (
            "another date than the scan's",
            lambda s: s.update(date="2026-10-06"),
            "isn't the scan's date 2026-10-05",
        ),
        (
            "a report about a dependency outside the inventory",
            lambda s: s["not_prepared"][2].update(dependency="nuget:nowhere:Nothing"),
            "unknown dependency id",
        ),
        (
            "an advisory on a dependency outside the inventory",
            lambda s: s["units"][0]["evidence"]["advisories"][0].update(dependency="nowhere"),
            "unknown dependency id",
        ),
    ],
)
def test_the_selection_only_names_what_the_record_has(description, change, expected):
    record = v3_record()
    change(record["selection"])
    problems = validate_record(record)
    assert any(expected in p for p in problems), (description, problems)


def with_open_report(record, *, named=True, reported=True):
    """The fixture with a held fix on the batch unit's dependency."""
    batch = record["selection"]["units"][2]
    dep_id = batch["targets"][0]["dependency"]
    reference = {
        "kind": "fix_held",
        "dependency": dep_id,
        "advisory": "GHSA-held",
        "held_by": "Aspire stays on 13.x",
    }
    if reported:
        record["selection"]["not_prepared"].insert(
            0, reference | {"reason": "security", "detail": "Vulnerable, fix held by policy."}
        )
    if named:
        batch["evidence"]["open_security_reports"] = [reference]
    return record


def test_a_batch_unit_names_the_open_security_reports_of_its_dependencies():
    assert validate_record(with_open_report(v3_record())) == []


@pytest.mark.parametrize(
    ("description", "change", "expected"),
    [
        (
            "a named report that isn't in not_prepared",
            lambda r: with_open_report(r, reported=False),
            "open_security_reports[0]: no security report in not_prepared",
        ),
        (
            "a report its unit doesn't name",
            lambda r: with_open_report(r, named=False),
            "open_security_reports: doesn't name $.selection.not_prepared[0]",
        ),
        (
            "a named report about another dependency",
            lambda r: with_open_report(r)["selection"]["units"][2]["evidence"][
                "open_security_reports"
            ][0].update(dependency="nuget:Directory.Packages.props:Microsoft.OpenApi"),
            "open_security_reports[0]: no security report",
        ),
    ],
)
def test_open_security_reports_are_checked(description, change, expected):
    record = v3_record()
    change(record)
    problems = validate_record(record)
    assert any(expected in p for p in problems), (description, problems)


def test_only_a_batch_unit_names_open_security_reports():
    record = with_open_report(v3_record())
    reports = record["selection"]["units"][2]["evidence"].pop("open_security_reports")
    record["selection"]["units"][1]["evidence"]["open_security_reports"] = reports
    assert any("should not be valid" in p for p in validate_record(record))


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"fix_reached_by_candidate": "unknown", "fix_reached_by": []}, "should not be valid"),
        ({"fix_reached_by": []}, "should not be valid"),
    ],
)
def test_fix_reached_by_is_absent_when_reach_is_unknown_or_not_judged(change, expected):
    record = v3_record()
    # The fixture's advisory names no fixed version, so the scan judged no candidate against it.
    record["vulnerabilities"][0] |= change
    problems = validate_record(record)
    assert any(expected in p for p in problems), problems
