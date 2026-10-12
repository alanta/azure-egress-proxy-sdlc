import copy
import json
import subprocess
from datetime import date

import pytest

from sdlc.policy import NO_POLICY, Policy
from sdlc.selection import NAME_LENGTH, SelectionError, batch_window, branch_name, select

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

    def vulnerability(self, dep_id, advisory, fixed, *, reached=True, reached_by=None, **fields):
        """An advisory on a dependency. When a candidate reaches its fix, every in-scope
        candidate added so far does, unless `reached_by` says which."""
        affected = next(d["current"] for d in self.record["inventory"] if d["id"] == dep_id)
        vulnerability = {
            "advisory": advisory,
            "dependency": dep_id,
            "affected_version": affected,
            "fixed_version": fixed,
        }
        if fixed is not None or "last_affected" in fields:
            vulnerability["fix_reached_by_candidate"] = reached
            if reached is True and reached_by is None:
                reached_by = [
                    c["version"]
                    for c in self.record["candidates"]
                    if c["dependency"] == dep_id
                    and c["classification"] == "in_scope"
                    and c["update_type"] != "digest"
                ]
            if reached is not True:
                reached_by = [] if reached is False else None
            if reached_by is not None:
                vulnerability["fix_reached_by"] = reached_by
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


def vulnerable(dep="Serilog", current="1.2.0", fixed="1.2.3", reached_by=None, **candidates):
    """A NuGet package with an advisory, and its candidates as update type=version."""
    record = Record().dependency(PROPS + dep, current)
    for update_type, version in candidates.items():
        record.candidate(PROPS + dep, update_type, version)
    return record.vulnerability(PROPS + dep, "GHSA-1", fixed, reached_by=reached_by)


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
    assert targets(found["security-go-golang.org-x-net"]) == {
        GO_MOD + "golang.org/x/net": "v0.60.0"
    }
    assert targets(found["security-go-golang.org-x-crypto"]) == {
        GO_MOD + "golang.org/x/crypto": "v0.56.0"
    }
    [advisory] = found["security-go-golang.org-x-crypto"]["evidence"]["advisories"]
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
    record = vulnerable(fixed="1.3.0", reached_by=["1.4.0"], patch="1.2.5", minor="1.4.0")
    [unit] = record.select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "1.4.0"}


def test_a_higher_version_affected_again_isnt_the_target():
    # The advisory affects [0, 6.0.5) and [6.1.0, 6.1.2): the scan finds only 7.0.0 outside.
    record = vulnerable(
        current="6.0.1", fixed="6.0.5", reached_by=["7.0.0"], minor="6.1.1", major="7.0.0"
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "7.0.0"}


def test_a_held_patch_is_passed_over_for_an_in_scope_minor():
    record = (
        Record()
        .dependency(PROPS + "Serilog", "1.2.0")
        .candidate(PROPS + "Serilog", "patch", "1.2.5", held_by="Patches wait")
        .candidate(PROPS + "Serilog", "minor", "1.4.0")
        .vulnerability(PROPS + "Serilog", "GHSA-1", "1.2.3")
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "1.4.0"}


def test_a_record_that_doesnt_say_which_candidate_reaches_the_fix_has_no_target():
    record = vulnerable(patch="1.2.5")
    del record.record["vulnerabilities"][0]["fix_reached_by"]
    selection = record.select()
    assert selection["units"] == []
    [unknown] = reports(selection, "not_evaluated")
    assert unknown["detail"].endswith("but not which one, so there is no target.")


def test_a_last_affected_version_is_passed_by_a_higher_candidate_only():
    record = (
        Record()
        .dependency(PROPS + "Serilog", "1.2.0")
        .candidate(PROPS + "Serilog", "patch", "1.2.5")
        .candidate(PROPS + "Serilog", "minor", "1.4.0")
        .vulnerability(
            PROPS + "Serilog", "GHSA-1", None, last_affected="1.2.5", reached_by=["1.4.0"]
        )
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "1.4.0"}
    assert unit["evidence"]["advisories"][0]["last_affected"] == "1.2.5"


def test_the_target_reaches_the_fix_of_every_advisory_on_the_declaration():
    record = vulnerable(patch="1.2.5", minor="1.4.0").vulnerability(
        PROPS + "Serilog", "GHSA-2", "1.3.0", reached_by=["1.4.0"]
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {PROPS + "Serilog": "1.4.0"}
    assert [a["advisory"] for a in unit["evidence"]["advisories"]] == ["GHSA-1", "GHSA-2"]


def test_no_single_candidate_that_fixes_every_advisory_is_reported():
    record = vulnerable(reached_by=["1.2.5"], patch="1.2.5", minor="1.4.0").vulnerability(
        PROPS + "Serilog", "GHSA-2", "1.3.0", reached_by=["1.4.0"]
    )
    selection = record.select()
    assert selection["units"] == []
    [report] = reports(selection, "no_candidate")
    assert report["advisories"] == ["GHSA-1", "GHSA-2"]
    assert report["detail"] == (
        "No single in-scope candidate reaches the fix of every advisory on it "
        "(GHSA-1: 1.2.5; GHSA-2: 1.4.0)."
    )


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
    assert route["detail"] == (
        "The record gives no fixed version for the advisory: it names none, or the scan "
        "couldn't read one from its ranges."
    )


def test_a_fix_no_candidate_reaches_has_no_candidate():
    record = (
        Record()
        .dependency(PROPS + "Serilog", "1.2.0")
        .candidate(PROPS + "Serilog", "patch", "1.2.5")
        .vulnerability(PROPS + "Serilog", "GHSA-1", "2.0.0", reached=False)
    )
    selection = record.select()
    assert reports(selection, "no_route") == []
    [missing] = reports(selection, "no_candidate")
    assert missing["detail"] == "No candidate reaches the fixed version 2.0.0."


def test_a_fix_only_digest_updates_could_reach_is_not_evaluated():
    record = (
        Record()
        .dependency(PROPS + "Serilog", "1.2.0")
        .candidate(PROPS + "Serilog", "digest", "1.2.0")
        .vulnerability(PROPS + "Serilog", "GHSA-1", "1.2.3", reached="unknown")
    )
    [unknown] = reports(record.select(), "not_evaluated")
    assert unknown["detail"].endswith(
        "its only candidates are digest updates, which the scan doesn't judge against advisories."
    )


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


GO_LINES = {
    "supported_lines": ["1.26", "1.27"],
    "source": "https://endoflife.date/api/v1/products/go",
}
SETUP_GO = "github-actions:.github/workflows/ci.yml:go"
GOLANG = "dockerfile:proxy/Dockerfile:docker.io/library/golang"


def go_line(state="nearing_end_of_life", **directive_candidates):
    """Go 1.25 in go.mod, with the directive's candidates as update type=version."""
    record = Record().dependency(GO_MOD + "go", "1.25.14", ecosystem="golang-version")
    for update_type, version in directive_candidates.items():
        record.candidate(GO_MOD + "go", update_type, version)
    return record


def test_a_line_nearing_its_end_moves_to_a_supported_line():
    record = go_line(minor="1.27.2").lifecycle(
        "go", "1.25", "nearing_end_of_life", [GO_MOD + "go"], end_of_life="2026-12-01", **GO_LINES
    )
    [unit] = record.select()["units"]
    assert unit["name"] == "lifecycle-go-1.25"
    assert unit["reasons"] == ["lifecycle"]
    assert unit["subject"] == {"product": "go", "line": "1.25"}
    assert targets(unit) == {GO_MOD + "go": "1.27.2"}
    assert unit["evidence"] == {
        "lifecycle": [
            {
                "product": "go",
                "line": "1.25",
                "state": "nearing_end_of_life",
                "end_of_life": "2026-12-01",
                "supported_lines": ["1.26", "1.27"],
                "source": "https://endoflife.date/api/v1/products/go",
            }
        ]
    }


def test_a_patch_on_the_ending_line_doesnt_leave_it():
    record = go_line(patch="1.25.15", minor="1.27.2").lifecycle(
        "go", "1.25", "nearing_end_of_life", [GO_MOD + "go"], **GO_LINES
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {GO_MOD + "go": "1.27.2"}


def test_every_declaration_of_the_line_is_in_its_unit():
    record = (
        go_line(minor="1.27.2")
        .dependency(SETUP_GO, "1.25", ecosystem="github-releases", name="go")
        .candidate(SETUP_GO, "minor", "1.27")
        .dependency(GOLANG, "1.25-alpine", ecosystem="docker")
        .candidate(GOLANG, "minor", "1.27-alpine")
        .lifecycle("go", "1.25", "end_of_life", [GOLANG, SETUP_GO, GO_MOD + "go"], **GO_LINES)
    )
    [unit] = record.select()["units"]
    assert targets(unit) == {GOLANG: "1.27-alpine", SETUP_GO: "1.27", GO_MOD + "go": "1.27.2"}


def test_a_dependency_without_a_supported_target_is_an_early_warning():
    record = (
        go_line(minor="1.27.2")
        .dependency(SETUP_GO, "1.25", ecosystem="github-releases", name="go", state="current")
        .lifecycle("go", "1.25", "nearing_end_of_life", [GO_MOD + "go", SETUP_GO], **GO_LINES)
    )
    selection = record.select()
    [unit] = selection["units"]
    assert targets(unit) == {GO_MOD + "go": "1.27.2"}
    [warning] = reports(selection, "early_warning")
    assert warning == {
        "kind": "early_warning",
        "reason": "lifecycle",
        "dependency": SETUP_GO,
        "lines": [{"product": "go", "line": "1.25"}],
        "detail": "No in-scope candidate is on another supported line of go 1.25 (1.26, 1.27).",
    }


def test_an_early_warning_names_the_rule_that_holds_the_move():
    sdk = "dockerfile:src/Portal/Dockerfile:mcr.microsoft.com/dotnet/sdk"
    hold = ".NET SDK and images stay on the .NET runtime's major"
    record = (
        Record()
        .dependency(sdk, "10.0", ecosystem="docker")
        .candidate(sdk, "major", "11.0", held_by=hold)
        .lifecycle("dotnet", "10", "nearing_end_of_life", [sdk], supported_lines=["10", "11"])
    )
    selection = record.select()
    assert selection["units"] == []
    [warning] = reports(selection, "early_warning")
    assert warning["held_by"] == hold
    assert warning["detail"] == (
        f"No in-scope candidate is on another supported line of dotnet 10 (11). 11.0 would, "
        f"but the policy holds it: {hold}."
    )


def test_an_ending_go_line_carries_the_standard_library_vulnerabilities():
    record = go_line(minor="1.27.2").lifecycle(
        "go", "1.25", "end_of_life", [GO_MOD + "go"], **GO_LINES
    )
    for advisory in ("GO-2026-6599", "GO-2026-6603"):
        record.vulnerability(GO_MOD + "go", advisory, "1.26.9", source="govulncheck")
    selection = record.select()
    [unit] = selection["units"]
    assert unit["name"] == "lifecycle-go-1.25"
    assert unit["reasons"] == ["lifecycle", "security"]
    # 1.27.2 is on a supported line and past 1.26.9.
    assert targets(unit) == {GO_MOD + "go": "1.27.2"}
    assert [a["advisory"] for a in unit["evidence"]["advisories"]] == [
        "GO-2026-6599",
        "GO-2026-6603",
    ]
    assert selection["not_prepared"] == []


def test_the_lifecycle_target_also_reaches_every_fix():
    record = (
        go_line(minor="1.26.3")
        .candidate(GO_MOD + "go", "minor", "1.27.1", basis="advisory_fix")
        .lifecycle("go", "1.25", "end_of_life", [GO_MOD + "go"], **GO_LINES)
        # 1.26.3 leaves the line, but only 1.27.1 is outside the advisory.
        .vulnerability(GO_MOD + "go", "GO-1", "1.27.1", reached_by=["1.27.1"])
    )
    [unit] = record.select()["units"]
    assert unit["reasons"] == ["lifecycle", "security"]
    assert targets(unit) == {GO_MOD + "go": "1.27.1"}


def test_without_a_candidate_that_does_both_the_fix_is_a_unit_of_its_own():
    record = (
        go_line(patch="1.25.15", minor="1.27.2")
        .lifecycle("go", "1.25", "nearing_end_of_life", [GO_MOD + "go"], **GO_LINES)
        .vulnerability(GO_MOD + "go", "GO-1", "1.25.15", reached_by=["1.25.15"])
    )
    selection = record.select()
    [unit] = selection["units"]
    assert unit["name"] == "security-golang-version-go"
    assert targets(unit) == {GO_MOD + "go": "1.25.15"}
    [warning] = reports(selection, "early_warning")
    assert warning["detail"] == (
        "No in-scope candidate both leaves go 1.25 and reaches the fix of every advisory on it, "
        "so its security fix is a unit of its own."
    )


def test_a_security_fix_stays_a_unit_when_its_line_has_no_target():
    record = (
        go_line(patch="1.25.15")
        .lifecycle("go", "1.25", "nearing_end_of_life", [GO_MOD + "go"], **GO_LINES)
        .vulnerability(GO_MOD + "go", "GO-1", "1.25.15")
    )
    selection = record.select()
    [unit] = selection["units"]
    assert unit["reasons"] == ["security"]
    assert targets(unit) == {GO_MOD + "go": "1.25.15"}
    assert [r["kind"] for r in selection["not_prepared"]] == ["early_warning"]


def test_a_failed_lookup_on_an_ending_line_is_not_evaluated():
    reason = "Renovate's lookup without the policy's holds failed: timeout."
    record = (
        Record()
        .dependency(
            GO_MOD + "go", "1.25.14", ecosystem="golang-version", state="unknown", reason=reason
        )
        .lifecycle("go", "1.25", "end_of_life", [GO_MOD + "go"], **GO_LINES)
    )
    selection = record.select()
    assert selection["units"] == []
    [unknown] = reports(selection, "not_evaluated")
    assert unknown["dependency"] == GO_MOD + "go" and unknown["reason"] == "lifecycle"
    assert unknown["detail"].endswith(f"the lookup of go is unknown. {reason}")


def test_a_candidate_whose_line_cant_be_read_is_not_evaluated():
    record = go_line(minor="1.27rc1").lifecycle(
        "go", "1.25", "end_of_life", [GO_MOD + "go"], **GO_LINES
    )
    [unknown] = reports(record.select(), "not_evaluated")
    assert unknown["detail"] == (
        "The go 1.25 line of candidate 1.27rc1 can't be read from the record."
    )


def test_a_line_of_unknown_state_is_not_evaluated():
    record = (
        Record()
        .dependency(GOLANG, "1.25-alpine", ecosystem="docker")
        .lifecycle(
            "alpine-linux",
            "alpine",
            "unknown",
            [GOLANG],
            reason="'alpine' names no release: it follows whichever one the image was last "
            "built on.",
        )
    )
    [unknown] = reports(record.select(), "not_evaluated")
    assert unknown == {
        "kind": "not_evaluated",
        "reason": "lifecycle",
        "product": "alpine-linux",
        "line": "alpine",
        "dependencies": [GOLANG],
        "detail": "'alpine' names no release: it follows whichever one the image was last "
        "built on.",
    }


ALPINE_LINES = {"supported_lines": ["3.21", "3.22"]}


def two_ending_lines(image_candidate):
    """Go 1.25 and Alpine 3.20 past their end, with an image on both and go.mod on Go."""
    return (
        go_line(minor="1.27.2")
        .dependency(GOLANG, "1.25-alpine3.20", ecosystem="docker")
        .candidate(GOLANG, "minor", image_candidate)
        .lifecycle("alpine-linux", "3.20", "end_of_life", [GOLANG], **ALPINE_LINES)
        .lifecycle("go", "1.25", "end_of_life", [GOLANG, GO_MOD + "go"], **GO_LINES)
    )


def test_a_dependency_on_two_ending_lines():
    selection = two_ending_lines("1.27-alpine3.22").select()
    [unit] = selection["units"]
    # The image stays with the other declarations of the Go toolchain.
    assert unit["name"] == "lifecycle-go-1.25"
    assert unit["reasons"] == ["lifecycle"]
    assert targets(unit) == {GOLANG: "1.27-alpine3.22", GO_MOD + "go": "1.27.2"}
    assert [(e["product"], e["line"]) for e in unit["evidence"]["lifecycle"]] == [
        ("go", "1.25"),
        ("alpine-linux", "3.20"),
    ]
    assert selection["not_prepared"] == []


def test_a_candidate_that_leaves_only_one_of_two_ending_lines_isnt_the_target():
    selection = two_ending_lines("1.27-alpine3.20").select()
    [unit] = selection["units"]
    assert targets(unit) == {GO_MOD + "go": "1.27.2"}
    [warning] = reports(selection, "early_warning")
    assert warning["dependency"] == GOLANG
    assert warning["lines"] == [{"product": "alpine-linux", "line": "3.20"}]
    assert warning["detail"] == (
        "No in-scope candidate is on another supported line of alpine-linux 3.20 (3.21, 3.22)."
    )


THIRD = date(2026, 11, 3)
DAYS_BEFORE_THIRD = {20: "2026-10-14T08:00:00+00:00", 2: "2026-11-01T08:00:00+00:00"}
AZURE_CORE = PROPS + "Azure.Core"


def outdated(dep_id=AZURE_CORE, current="1.62.0", *candidates, **fields):
    """A dependency with candidates given as (update type, version, extra fields)."""
    record = Record().dependency(dep_id, current, **fields)
    for update_type, version, extra in candidates:
        record.candidate(dep_id, update_type, version, **extra)
    return record


def test_a_scan_inside_the_window_batches_an_old_enough_candidate():
    released = DAYS_BEFORE_THIRD[20]
    record = outdated(AZURE_CORE, "1.62.0", ("minor", "1.63.0", {"released_at": released}))
    [unit] = record.select(THIRD)["units"]
    assert unit["reasons"] == ["batch"]
    assert unit["targets"] == [
        {
            "dependency": AZURE_CORE,
            "current": "1.62.0",
            "version": "1.63.0",
            "update_type": "minor",
            "released_at": released,
            "age_days": 20,
        }
    ]
    assert unit["evidence"] == {
        "batch_window": {"first_day": 1, "last_day": 7},
        "minimum_release_age_days": 7,
    }


def test_a_scan_outside_the_window_batches_nothing():
    record = outdated(AZURE_CORE, "1.62.0", ("minor", "1.63.0", {}))
    selection = record.select(date(2026, 11, 15))
    assert selection["units"] == [] and selection["not_prepared"] == []
    assert selection["batch_window"] == {"open": False, "next_opens": "2026-12-01"}


def test_a_candidate_exactly_the_minimum_age_is_old_enough():
    record = outdated(
        AZURE_CORE, "1.62.0", ("minor", "1.63.0", {"released_at": "2026-10-27T23:59:59+00:00"})
    )
    [unit] = record.select(THIRD)["units"]
    assert unit["targets"][0]["age_days"] == 7


def test_a_too_young_newest_candidate_waits_for_the_next_window():
    record = outdated(
        AZURE_CORE,
        "1.62.0",
        # The patch would be old enough, but the newest candidate decides.
        ("patch", "1.62.1", {"released_at": DAYS_BEFORE_THIRD[20]}),
        ("minor", "1.63.0", {"released_at": DAYS_BEFORE_THIRD[2]}),
    )
    selection = record.select(THIRD)
    assert selection["units"] == []
    assert selection["not_prepared"] == [
        {
            "kind": "waiting",
            "reason": "batch",
            "dependency": AZURE_CORE,
            "version": "1.63.0",
            "update_type": "minor",
            "released_at": DAYS_BEFORE_THIRD[2],
            "age_days": 2,
            "old_enough_on": "2026-11-08",
            "detail": "1.63.0 is 2 days old, younger than 7, so it waits for the next window, "
            "which opens on 2026-12-01.",
        }
    ]


def test_a_release_date_after_the_scan_waits_too():
    record = outdated(
        AZURE_CORE, "1.62.0", ("minor", "1.63.0", {"released_at": "2026-11-05T00:00:00+00:00"})
    )
    [waiting] = reports(record.select(THIRD), "waiting")
    assert waiting["age_days"] == -2


def test_a_candidate_without_a_release_date_is_batched_with_its_age_unknown():
    record = outdated(AZURE_CORE, "1.62.0", ("minor", "1.63.0", {}))
    [unit] = record.select(THIRD)["units"]
    [target] = unit["targets"]
    assert target["age_days"] == "unknown" and "released_at" not in target


def test_the_newest_in_scope_candidate_is_batched_not_a_held_one():
    record = outdated(
        PROPS + "Microsoft.OpenApi",
        "2.12.2",
        ("minor", "2.13.0", {}),
        ("major", "3.10.2", {"held_by": "Microsoft.OpenApi stays on 2.x"}),
    )
    [unit] = record.select(THIRD)["units"]
    assert targets(unit) == {PROPS + "Microsoft.OpenApi": "2.13.0"}


def test_a_dependency_with_a_security_unit_is_left_out_of_the_batch():
    record = vulnerable(patch="1.2.5", minor="1.4.0")
    selection = record.select(THIRD)
    assert [u["reasons"] for u in selection["units"]] == [["security"]]
    assert targets(selection["units"][0]) == {PROPS + "Serilog": "1.2.5"}


def test_a_dependency_with_a_lifecycle_unit_is_left_out_of_the_batch():
    record = go_line(minor="1.27.2").lifecycle(
        "go", "1.25", "end_of_life", [GO_MOD + "go"], **GO_LINES
    )
    assert [u["reasons"] for u in record.select(THIRD)["units"]] == [["lifecycle"]]


def test_two_go_modules_in_one_group_are_one_unit():
    azcore, azblob = GO_MOD + "azcore", GO_MOD + "azblob"
    record = (
        Record()
        .dependency(azcore, "v1.23.1", ecosystem="go")
        .candidate(azcore, "minor", "v1.24.0", group="gomod-minor-patch")
        .dependency(azblob, "v1.8.1", ecosystem="go")
        .candidate(azblob, "patch", "v1.8.2", group="gomod-minor-patch")
    )
    [unit] = record.select(THIRD)["units"]
    assert unit["name"] == "gomod-minor-patch"
    assert unit["subject"] == {"group": "gomod-minor-patch"}
    assert targets(unit) == {azcore: "v1.24.0", azblob: "v1.8.2"}


def test_a_major_outside_every_group_is_a_unit_of_its_own():
    record = (
        outdated(PROPS + "Serilog", "4.3.0", ("major", "5.0.0", {}))
        .dependency(AZURE_CORE, "1.62.0")
        .candidate(AZURE_CORE, "minor", "1.63.0", group="nuget-minor-patch")
    )
    found = units(record.select(THIRD))
    assert set(found) == {"nuget-serilog", "nuget-minor-patch"}
    assert targets(found["nuget-serilog"]) == {PROPS + "Serilog": "5.0.0"}
    assert found["nuget-serilog"]["subject"] == {"ecosystem": "nuget", "name": "Serilog"}


def test_an_ungrouped_package_in_two_files_is_one_unit():
    feature = "ghcr.io/devcontainers/features/docker-in-docker"
    ids = [
        f"devcontainer:.devcontainer/devcontainer.json:{feature}",
        f"devcontainer:.devcontainer/worktree/devcontainer.json:{feature}",
    ]
    record = Record()
    for dep_id in ids:
        record.dependency(dep_id, "2", ecosystem="docker", name=feature)
        record.candidate(dep_id, "major", "4")
    [unit] = record.select(THIRD)["units"]
    assert unit["name"] == "docker-ghcr.io-devcontainers-features-docker-in-docker"
    assert targets(unit) == dict.fromkeys(ids, "4")


def test_a_later_scan_with_newer_targets_keeps_the_unit_names():
    def scan(go, net, azcore):
        return (
            go_line(minor=go)
            .lifecycle("go", "1.25", "end_of_life", [GO_MOD + "go"], **GO_LINES)
            .dependency(GO_MOD + "golang.org/x/net", "v0.58.0", ecosystem="go")
            .candidate(GO_MOD + "golang.org/x/net", "minor", net)
            .vulnerability(GO_MOD + "golang.org/x/net", "GO-1", "v0.60.0")
            .dependency(GO_MOD + "azcore", "v1.23.1", ecosystem="go")
            .candidate(GO_MOD + "azcore", "patch", azcore, group="gomod-minor-patch")
            .select(THIRD)
        )

    earlier = scan("1.27.2", "v0.60.0", "v1.23.3")
    later = scan("1.27.5", "v0.62.0", "v1.23.4")
    assert [u["name"] for u in earlier["units"]] == [
        "security-go-golang.org-x-net",
        "lifecycle-go-1.25",
        "gomod-minor-patch",
    ]
    assert [u["name"] for u in later["units"]] == [u["name"] for u in earlier["units"]]
    assert [u["targets"] for u in later["units"]] != [u["targets"] for u in earlier["units"]]


def test_a_security_fix_that_needs_a_major_is_breaking():
    [unit] = vulnerable(fixed="2.0.0", reached_by=["2.0.1"], major="2.0.1").select()["units"]
    assert unit["breaking"] is True


def test_a_security_fix_in_a_patch_is_routine():
    [unit] = vulnerable(patch="1.2.5").select()["units"]
    assert unit["breaking"] is False


def test_a_batch_of_minor_and_patch_updates_is_routine():
    record = (
        outdated(AZURE_CORE, "1.62.0", ("minor", "1.63.0", {"group": "nuget-minor-patch"}))
        .dependency(PROPS + "Scalar.AspNetCore", "2.17.9")
        .candidate(PROPS + "Scalar.AspNetCore", "patch", "2.17.14", group="nuget-minor-patch")
    )
    [unit] = record.select(THIRD)["units"]
    assert unit["breaking"] is False


def test_a_batched_major_is_breaking():
    [unit] = outdated(PROPS + "Serilog", "4.3.0", ("major", "5.0.0", {})).select(THIRD)["units"]
    assert unit["breaking"] is True


def test_a_lifecycle_move_is_breaking_whatever_its_update_type():
    record = go_line(minor="1.27.2").lifecycle(
        "go", "1.25", "end_of_life", [GO_MOD + "go"], **GO_LINES
    )
    [unit] = record.select()["units"]
    assert unit["targets"][0]["update_type"] == "minor"
    assert unit["breaking"] is True


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("security-go-golang.org/x/net", "security-go-golang.org-x-net"),
        ("nuget-Microsoft.Extensions.Http", "nuget-microsoft.extensions.http"),
        ("docker-mcr.microsoft.com/dotnet/sdk", "docker-mcr.microsoft.com-dotnet-sdk"),
        ("Weekly updates: NuGet & Go", "weekly-updates-nuget-go"),
        ("..a..b..", "a-b"),
        ("-leading_and_trailing.", "leading_and_trailing"),
        ("group@{1}~^:?*[\\", "group-1"),
        ("cache.lock", "cache-lock"),
        ("nuget-x.lock", "nuget-x-lock"),
        ("Ünïcode-naïve", "n-code-na-ve"),
    ],
)
def test_names_are_safe_for_branches(text, expected):
    assert branch_name(text) == expected
    check = subprocess.run(
        ["git", "check-ref-format", "--branch", f"sdlc/{expected}"], capture_output=True
    )
    assert check.returncode == 0, check.stderr


def test_a_long_or_empty_name_stays_distinct():
    long = "docker-" + "a" * 200
    other = "docker-" + "a" * 199 + "b"
    assert len(branch_name(long)) == NAME_LENGTH
    assert branch_name(long) != branch_name(other)
    assert branch_name(long) == branch_name(long)
    assert len(branch_name("💥")) == 8


def test_units_whose_names_collide_both_get_a_suffix():
    record = (
        outdated(PROPS + "Serilog", "4.3.0", ("major", "5.0.0", {}))
        .dependency(AZURE_CORE, "1.62.0")
        .candidate(AZURE_CORE, "minor", "1.63.0", group="NuGet Serilog")
    )
    found = record.select(THIRD)["units"]
    names = [u["name"] for u in found]
    assert len(set(names)) == 2
    assert all(
        n.startswith("nuget-serilog-") and len(n) == len("nuget-serilog-") + 8 for n in names
    )
    assert all(u["name_collision"] is True for u in found)
    # The same units get the same names in every scan.
    assert [u["name"] for u in record.select(THIRD)["units"]] == names
