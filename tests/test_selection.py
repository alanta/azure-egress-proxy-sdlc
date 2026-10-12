import copy
import json
from datetime import date

import pytest

from sdlc.policy import NO_POLICY, Policy
from sdlc.selection import SelectionError, batch_window, select

TRIAL = Policy({"source": "trial", "path": "policies/trial.renovate.json5"}, "{}", "{}")
# A day outside the batch window, and one inside it.
OUTSIDE = date(2026, 10, 15)
INSIDE = date(2026, 11, 3)


class Record:
    """A scan record built up by hand, with only what the selection reads."""

    def __init__(self, policy: Policy = TRIAL):
        self.record = {
            "schema_version": "3",
            "scanned_at": "2026-10-15T09:00:00+00:00",
            "policy": policy.source,
            "inventory": [],
            "candidates": [],
            "vulnerabilities": [],
            "lifecycle": [],
            "gaps": [],
        }

    def dependency(
        self, dep_id, current, *, ecosystem="nuget", name=None, state="outdated", **lookup
    ):
        name = name or dep_id.rsplit(":", 1)[-1]
        self.record["inventory"].append(
            {
                "id": dep_id,
                "ecosystem": ecosystem,
                "name": name,
                "current": current,
                "origin": "declared",
                "location": {"file": dep_id.split(":")[1]},
                "lookup": {"state": state, **lookup},
            }
        )
        return self

    def candidate(self, dep_id, update_type, version, *, held_by=None, **fields):
        candidate = {"dependency": dep_id, "update_type": update_type, "version": version}
        if held_by:
            candidate |= {"classification": "held_by_policy", "held_by": held_by}
        else:
            candidate["classification"] = "in_scope"
        self.record["candidates"].append(candidate | fields)
        return self

    def vulnerability(self, dep_id, advisory, fixed, *, reached=True, **fields):
        affected = next(d["current"] for d in self.record["inventory"] if d["id"] == dep_id)
        vulnerability = {
            "advisory": advisory,
            "dependency": dep_id,
            "affected_version": affected,
            "fixed_version": fixed,
        }
        if fixed is not None or "last_affected" in fields:
            vulnerability["fix_reached_by_candidate"] = reached
        vulnerability |= {"source": "osv", "reachability": "unknown"} | fields
        self.record["vulnerabilities"].append(vulnerability)
        return self

    def lifecycle(self, product, line, state, dependencies, **fields):
        locations = [
            next(d["location"] for d in self.record["inventory"] if d["id"] == dep_id)
            for dep_id in dependencies
        ]
        self.record["lifecycle"].append(
            {"product": product, "line": line, "state": state}
            | fields
            | {"dependencies": list(dependencies), "locations": locations}
        )
        return self

    def select(self, today=OUTSIDE, policy=TRIAL):
        return select(copy.deepcopy(self.record), policy, today)


def test_the_same_scan_is_selected_the_same_way_twice():
    record = (
        Record()
        .dependency("nuget:Directory.Packages.props:Azure.Core", "1.62.0")
        .candidate("nuget:Directory.Packages.props:Azure.Core", "minor", "1.63.0")
    )
    first = record.select(INSIDE)
    assert record.select(INSIDE) == first
    # The selection goes into the record as it is.
    assert json.loads(json.dumps(first)) == first


def test_the_defaults_and_the_window_are_part_of_the_selection():
    selection = Record().select(OUTSIDE)
    assert selection["date"] == "2026-10-15"
    assert selection["defaults"] == {
        "batch_window": {"first_day": 1, "last_day": 7},
        "minimum_release_age_days": 7,
    }
    assert selection["batch_window"] == {"open": False, "next_opens": "2026-11-01"}
    assert selection["units"] == [] and selection["not_prepared"] == []


@pytest.mark.parametrize(
    ("today", "is_open", "next_opens"),
    [
        (date(2026, 11, 1), True, "2026-12-01"),
        (date(2026, 11, 7), True, "2026-12-01"),
        (date(2026, 11, 8), False, "2026-12-01"),
        (date(2026, 12, 31), False, "2027-01-01"),
    ],
)
def test_the_batch_window_is_the_first_seven_days_of_the_month(today, is_open, next_opens):
    assert batch_window(today) == {"open": is_open, "next_opens": next_opens}


def test_a_record_classified_with_another_policy_is_refused():
    with pytest.raises(SelectionError, match="classified with policy"):
        Record(TRIAL).select(policy=NO_POLICY)


PROPS = "nuget:Directory.Packages.props:"
GO_MOD = "gomod:proxy/go.mod:"
RUNTIME_HOLD = "NuGet packages stay on the .NET runtime's major"


def units(selection, reason=None):
    return {u["name"]: u for u in selection["units"] if reason is None or reason in u["reasons"]}


def targets(unit):
    return {t["dependency"]: t["version"] for t in unit["targets"]}


def reports(selection, kind):
    return [r for r in selection["not_prepared"] if r["kind"] == kind]


def vulnerable(dep="Serilog", current="1.2.0", fixed="1.2.3", **candidates):
    """A NuGet package with an advisory, and its candidates as update type=version."""
    record = Record().dependency(PROPS + dep, current)
    for update_type, version in candidates.items():
        record.candidate(PROPS + dep, update_type, version)
    return record.vulnerability(PROPS + dep, "GHSA-1", fixed)


def test_a_reachable_and_an_unreachable_vulnerability_both_get_a_unit():
    record = (
        Record()
        .dependency(GO_MOD + "golang.org/x/net", "v0.58.0", ecosystem="go")
        .candidate(GO_MOD + "golang.org/x/net", "minor", "v0.60.0")
        .vulnerability(GO_MOD + "golang.org/x/net", "GO-1", "v0.60.0", reachability="reachable")
        .dependency(GO_MOD + "golang.org/x/crypto", "v0.55.0", ecosystem="go")
        .candidate(GO_MOD + "golang.org/x/crypto", "minor", "v0.56.0")
        .vulnerability(
            GO_MOD + "golang.org/x/crypto", "GO-2", "v0.56.0", reachability="not_reachable"
        )
    )
    found = units(record.select(), "security")
    assert targets(found["security-go-golang.org/x/net"]) == {
        GO_MOD + "golang.org/x/net": "v0.60.0"
    }
    assert targets(found["security-go-golang.org/x/crypto"]) == {
        GO_MOD + "golang.org/x/crypto": "v0.56.0"
    }
    [advisory] = found["security-go-golang.org/x/crypto"]["evidence"]["advisories"]
    assert advisory["advisory"] == "GO-2" and advisory["reachability"] == "not_reachable"


def test_the_smallest_candidate_that_reaches_the_fix_is_the_target():
    selection = vulnerable(patch="1.2.5", minor="1.4.0").select()
    [unit] = selection["units"]
    assert unit["reasons"] == ["security"]
    assert unit["targets"] == [
        {
            "dependency": PROPS + "Serilog",
            "current": "1.2.0",
            "version": "1.2.5",
            "update_type": "patch",
            "age_days": "unknown",
        }
    ]


def test_a_patch_that_falls_short_of_the_fix_isnt_the_target():
    [unit] = vulnerable(fixed="1.3.0", patch="1.2.5", minor="1.4.0").select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "1.4.0"}


def test_a_last_affected_version_is_passed_by_a_higher_candidate_only():
    record = (
        Record()
        .dependency(PROPS + "Serilog", "1.2.0")
        .candidate(PROPS + "Serilog", "patch", "1.2.5")
        .candidate(PROPS + "Serilog", "minor", "1.4.0")
        .vulnerability(PROPS + "Serilog", "GHSA-1", None, last_affected="1.2.5")
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "1.4.0"}
    assert unit["evidence"]["advisories"][0]["last_affected"] == "1.2.5"


def test_the_highest_target_across_a_declarations_advisories_fixes_them_all():
    record = vulnerable(patch="1.2.5", minor="1.4.0").vulnerability(
        PROPS + "Serilog", "GHSA-2", "1.3.0"
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "1.4.0"}
    assert [a["advisory"] for a in unit["evidence"]["advisories"]] == ["GHSA-1", "GHSA-2"]


def test_a_new_fixing_release_is_selected_without_a_minimum_age():
    record = (
        Record()
        .dependency(PROPS + "Serilog", "1.2.0")
        .candidate(PROPS + "Serilog", "patch", "1.2.5", released_at="2026-10-14T22:00:00+00:00")
        .vulnerability(PROPS + "Serilog", "GHSA-1", "1.2.3")
    )
    [unit] = record.select(date(2026, 10, 15))["units"]
    [target] = unit["targets"]
    assert target["version"] == "1.2.5"
    assert target["released_at"] == "2026-10-14T22:00:00+00:00"
    assert target["age_days"] == 1


def test_a_standard_library_vulnerability_selects_the_go_directive():
    record = (
        Record()
        .dependency(GO_MOD + "go", "1.26.2", ecosystem="golang-version")
        .candidate(GO_MOD + "go", "patch", "1.26.9")
        .vulnerability(
            GO_MOD + "go", "GO-2026-6599", "1.26.9", source="govulncheck", reachability="reachable"
        )
    )
    [unit] = record.select()["units"]
    assert unit["name"] == "security-golang-version-go"
    assert unit["subject"] == {"ecosystem": "golang-version", "name": "go"}
    assert targets(unit) == {GO_MOD + "go": "1.26.9"}
    assert unit["evidence"]["advisories"][0]["source"] == "govulncheck"


def test_a_vulnerable_package_declared_in_two_files_is_one_unit():
    app, tests = "nuget:src/App/App.csproj:Serilog", "nuget:tests/T/T.csproj:serilog"
    record = Record()
    for dep_id in (app, tests):
        record.dependency(dep_id, "1.2.0").candidate(dep_id, "patch", "1.2.5")
        record.vulnerability(dep_id, "GHSA-1", "1.2.3")
    [unit] = record.select()["units"]
    assert targets(unit) == {app: "1.2.5", tests: "1.2.5"}
    assert [a["dependency"] for a in unit["evidence"]["advisories"]] == [app, tests]


def test_only_a_held_candidate_reaches_the_fix():
    record = (
        Record()
        .dependency(PROPS + "Microsoft.Extensions.Http", "10.0.12")
        .candidate(PROPS + "Microsoft.Extensions.Http", "major", "11.0.1", held_by=RUNTIME_HOLD)
        .vulnerability(
            PROPS + "Microsoft.Extensions.Http",
            "GHSA-1",
            "11.0.0",
            reached=False,
            fix_held_by=RUNTIME_HOLD,
        )
    )
    selection = record.select()
    assert selection["units"] == []
    [held] = reports(selection, "fix_held")
    assert held == {
        "kind": "fix_held",
        "reason": "security",
        "dependency": PROPS + "Microsoft.Extensions.Http",
        "advisory": "GHSA-1",
        "held_by": RUNTIME_HOLD,
        "detail": "Vulnerable, fix held by policy: only candidates that rule holds reach the "
        "fixed version 11.0.0.",
    }


def test_an_advisory_without_a_fixed_version_has_no_route():
    record = (
        Record()
        .dependency(GO_MOD + "golang.org/x/crypto", "v0.55.0", ecosystem="go", state="current")
        .vulnerability(GO_MOD + "golang.org/x/crypto", "GO-2026-5932", None)
    )
    selection = record.select()
    assert selection["units"] == []
    [route] = reports(selection, "no_route")
    assert route["advisory"] == "GO-2026-5932"
    assert route["detail"] == "The advisory names no fixed version."


def test_a_fix_no_candidate_reaches_has_no_route():
    record = vulnerable(fixed="2.0.0", patch="1.2.5")
    record.record["vulnerabilities"][0]["fix_reached_by_candidate"] = False
    [route] = reports(record.select(), "no_route")
    assert route["detail"] == "No candidate reaches the fixed version 2.0.0."


def test_a_failed_lookup_is_not_evaluated_with_its_reason():
    reason = "Renovate's lookup with the policy failed: rate limited."
    record = (
        Record()
        .dependency(PROPS + "Serilog", "1.2.0", state="unknown", reason=reason)
        .vulnerability(PROPS + "Serilog", "GHSA-1", "1.2.3", reached="unknown")
    )
    selection = record.select()
    assert selection["units"] == []
    [unknown] = reports(selection, "not_evaluated")
    assert unknown["dependency"] == PROPS + "Serilog" and unknown["advisory"] == "GHSA-1"
    assert unknown["detail"].endswith(f"the lookup of Serilog is unknown. {reason}")


def test_a_source_that_wasnt_read_is_not_evaluated():
    record = Record()
    record.record["gaps"] = [
        {"kind": "unavailable_source", "subject": "osv-scanner", "reason": "It failed."},
        {"kind": "unavailable_source", "subject": "govulncheck: proxy/go.mod", "reason": "Gone."},
        {"kind": "unavailable_source", "subject": "dotnet list package", "reason": "No SDK."},
    ]
    found = reports(record.select(), "not_evaluated")
    assert [(r["source"], r["detail"]) for r in found] == [
        ("govulncheck: proxy/go.mod", "Gone."),
        ("osv-scanner", "It failed."),
    ]


def test_an_alert_the_scan_didnt_match_is_not_evaluated():
    record = Record()
    record.record["dependabot_alerts"] = {
        "ref": "main",
        "commit": "e93d7062b075352f151f8e6b5a15f60913e7bd98",
        "is_scanned_commit": False,
        "read_at": "2026-10-15T09:00:00+00:00",
        "alerts": [
            {
                "number": 7,
                "advisory": "GHSA-xxxx",
                "ecosystem": "pip",
                "package": "PyJWT",
                "manifest": "mock-idp/requirements.txt",
                "fixed_version": "2.15.1",
                "result": "unmatched",
            },
            {
                "number": 8,
                "advisory": "GHSA-yyyy",
                "ecosystem": "go",
                "package": "golang.org/x/net",
                "manifest": "proxy/go.mod",
                "fixed_version": "0.60.0",
                "result": "matched",
            },
        ],
    }
    [alert] = reports(record.select(), "not_evaluated")
    assert alert["alert"] == 7 and alert["package"] == "PyJWT"
    assert "main at e93d706, not the scanned commit" in alert["detail"]
