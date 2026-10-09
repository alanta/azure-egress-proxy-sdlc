import json
from pathlib import Path

import pytest

from sdlc.policy import (
    NO_POLICY,
    PolicyError,
    allowed,
    classify,
    load,
    match_list,
    matches,
)
from sdlc.record import validate_record
from sdlc.renovate import Inventory, match_fields, normalize

REPORTS = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy" / "renovate" / "064aa09"
AT = "2026-10-08T09:00:00+00:00"

RUNTIME_MAJORS = """
// Packages released with the .NET runtime move with it, not on their own.
{
  packageRules: [
    {
      description: "Runtime-coupled packages wait for the .NET 11 migration",
      matchDatasources: ["nuget"],
      matchPackageNames: ["Microsoft.Extensions.*", "Microsoft.AspNetCore.*"],
      matchUpdateTypes: ["major"],
      enabled: false,
    },
  ],
}
"""

HUMANIZER_CAP = """{
  packageRules: [
    {
      description: "Humanizer stays below 2.10",
      matchPackageNames: ["Humanizer.Core"],
      allowedVersions: "<2.10.0",
    },
  ],
}"""


def accept(text):
    return []


def report(*deps):
    """A Renovate report with NuGet dependencies: (name, current, {version: update type})."""
    return {
        "repositories": {
            "local": {
                "packageFiles": {
                    "nuget": [
                        {
                            "packageFile": "Directory.Packages.props",
                            "deps": [
                                {
                                    "depName": name,
                                    "packageName": name,
                                    "datasource": "nuget",
                                    "currentValue": current,
                                    "updates": [
                                        {"updateType": kind, "newValue": version}
                                        for version, kind in updates.items()
                                    ],
                                }
                                for name, current, updates in deps
                            ],
                        }
                    ]
                }
            }
        }
    }


def policy_from(tmp_path, text, name="trial.renovate.json5"):
    (tmp_path / name).write_text(text)
    return load(tmp_path / "checkout", tmp_path / name, validate=accept)


def classified(baseline, main, active):
    candidates = classify(
        normalize(baseline, looked_up_at=AT).candidates,
        normalize(main, looked_up_at=AT),
        match_fields(baseline),
        active,
    )
    return {(c["dependency"].split(":")[-1], c["version"]): c for c in candidates}


@pytest.fixture
def checkout(tmp_path):
    (tmp_path / "checkout").mkdir()
    return tmp_path / "checkout"


def test_a_platform_coupled_major_is_held_by_its_rule(tmp_path, checkout, record_from):
    active = policy_from(tmp_path, RUNTIME_MAJORS)
    found = report(
        ("Microsoft.Extensions.Http", "10.0.12", {"10.0.13": "patch", "11.0.1": "major"}),
        ("Serilog", "4.3.0", {"5.0.0": "major"}),
    )
    # A rule on update types acts after the lookup, so both runs report the same updates.
    result = classified(found, found, active)

    held = result[("Microsoft.Extensions.Http", "11.0.1")]
    assert held["classification"] == "held_by_policy"
    assert held["held_by"] == "Runtime-coupled packages wait for the .NET 11 migration"
    assert result[("Microsoft.Extensions.Http", "10.0.13")]["classification"] == "in_scope"
    assert result[("Serilog", "5.0.0")]["classification"] == "in_scope"

    inventory = normalize(found, looked_up_at=AT)
    record = record_from(Inventory(inventory.dependencies, list(result.values())))
    record["policy"] = active.source
    assert validate_record(record) == []


def test_a_major_hold_on_the_captured_report(tmp_path, checkout):
    active = policy_from(
        tmp_path,
        '{packageRules: [{description: "No majors", matchUpdateTypes: ["major"], enabled: false}]}',
    )
    captured = json.loads((REPORTS / "report-with-scan-config.json").read_text())
    result = classified(captured, captured, active)
    assert result[("Microsoft.OpenApi", "3.10.2")]["held_by"] == "No majors"
    held = {c["update_type"] for c in result.values() if c["classification"] == "held_by_policy"}
    assert held == {"major"}


def test_allowed_versions_holds_are_found_by_the_difference(tmp_path, checkout, record_from):
    active = policy_from(tmp_path, HUMANIZER_CAP)
    baseline = report(("Humanizer.Core", "2.8.26", {"2.14.1": "minor", "3.0.10": "major"}))
    # allowedVersions changes which version is the candidate, not just whether there is one.
    main = report(("Humanizer.Core", "2.8.26", {"2.9.9": "minor"}))
    result = classified(baseline, main, active)

    assert {k: (c["classification"], c.get("held_by")) for k, c in result.items()} == {
        ("Humanizer.Core", "2.14.1"): ("held_by_policy", "Humanizer stays below 2.10"),
        ("Humanizer.Core", "3.0.10"): ("held_by_policy", "Humanizer stays below 2.10"),
        ("Humanizer.Core", "2.9.9"): ("in_scope", None),
    }
    inventory = normalize(baseline, looked_up_at=AT)
    assert (
        validate_record(record_from(Inventory(inventory.dependencies, list(result.values())))) == []
    )


def test_a_candidate_renovate_held_back_for_no_known_rule_fails(tmp_path, checkout):
    active = policy_from(tmp_path, HUMANIZER_CAP)
    baseline = report(("Serilog", "4.3.0", {"5.0.0": "major"}))
    main = report(("Serilog", "4.3.0", {}))
    with pytest.raises(PolicyError, match="no hold rule in the policy matches it"):
        classified(baseline, main, active)


def test_a_disabled_dependency_renovate_still_proposes_fails(tmp_path, checkout):
    active = policy_from(
        tmp_path,
        '{packageRules: [{description: "No Serilog", matchPackageNames: ["Serilog"], '
        "enabled: false}]}",
    )
    found = report(("Serilog", "4.3.0", {"5.0.0": "major"}))
    with pytest.raises(PolicyError, match=r"still proposes 5\.0\.0"):
        classified(found, found, active)


def test_ignored_dependencies_are_held_by_ignore_deps(tmp_path, checkout):
    active = policy_from(tmp_path, '{ignoreDeps: ["Serilog"]}')
    baseline = report(
        ("Serilog", "4.3.0", {"5.0.0": "major"}), ("serilog", "1.0.0", {"1.1": "minor"})
    )
    main = report(("Serilog", "4.3.0", {}), ("serilog", "1.0.0", {"1.1": "minor"}))
    result = classified(baseline, main, active)
    assert result[("Serilog", "5.0.0")]["held_by"] == "ignoreDeps"
    # ignoreDeps compares names exactly, unlike the case-insensitive globs in rules.
    assert result[("serilog", "1.1")]["classification"] == "in_scope"


def test_lock_drift_is_classified_by_the_rules_alone(tmp_path, checkout):
    active = policy_from(tmp_path, RUNTIME_MAJORS)
    drift = [
        {"dependency": "locked:a", "update_type": "major", "version": "11.0.0"},
        {"dependency": "locked:b", "update_type": "patch", "version": "10.0.12"},
    ]
    fields = {"depName": "Microsoft.Extensions.Http", "packageName": "Microsoft.Extensions.Http"}
    fields |= {"datasource": "nuget", "manager": "nuget"}
    result = classify(drift, None, {"locked:a": fields, "locked:b": fields}, active)
    assert [c["classification"] for c in result] == ["held_by_policy", "in_scope"]


def test_without_a_policy_every_candidate_is_in_scope(checkout, record_from):
    active = load(checkout, validate=accept)
    assert active is NO_POLICY
    assert active.source == {"source": "none"}
    found = json.loads((REPORTS / "report-with-scan-config.json").read_text())
    inventory = normalize(found, looked_up_at=AT)
    result = classify(inventory.candidates, inventory, match_fields(found), active)
    assert {c["classification"] for c in result} == {"in_scope"}
    record = record_from(Inventory(inventory.dependencies, result))
    assert record["policy"] == {"source": "none"}
    assert validate_record(record) == []


def test_the_policy_in_the_revision_is_read(checkout):
    (checkout / ".github").mkdir()
    (checkout / ".github" / "renovate.json5").write_text(HUMANIZER_CAP)
    active = load(checkout, validate=accept)
    assert active.source == {"source": "subject", "path": ".github/renovate.json5"}
    assert [h.name for h in active.holds] == ["Humanizer stays below 2.10"]


def test_a_trial_policy_replaces_the_revisions_and_is_named(tmp_path, checkout, record_from):
    (checkout / ".github").mkdir()
    (checkout / ".github" / "renovate.json5").write_text("{}")
    active = policy_from(tmp_path, RUNTIME_MAJORS)
    assert active.source == {"source": "trial", "path": str(tmp_path / "trial.renovate.json5")}
    assert active.content == RUNTIME_MAJORS
    record = record_from(Inventory([], []))
    record["policy"] = active.source
    assert validate_record(record) == []


def test_the_baseline_drops_holds_and_keeps_everything_else(tmp_path, checkout):
    active = policy_from(
        tmp_path,
        """{
          ignoreDeps: ["Serilog"],
          customManagers: [{customType: "regex", managerFilePatterns: ["x"], matchStrings: ["y"]}],
          packageRules: [
            {description: "Group minors", matchUpdateTypes: ["minor"], groupName: "minors"},
            {description: "Cap", matchPackageNames: ["Humanizer.Core"], allowedVersions: "<3"},
            {description: "No majors", matchUpdateTypes: ["major"], enabled: false},
          ],
        }""",
    )
    baseline = json.loads(active.baseline)
    assert "ignoreDeps" not in baseline
    assert baseline["customManagers"][0]["matchStrings"] == ["y"]
    assert [r["description"] for r in baseline["packageRules"]] == ["Group minors"]
    assert [h.name for h in active.holds] == ["Cap", "No majors"]


def test_a_policy_without_holds_needs_one_run(tmp_path, checkout):
    active = policy_from(tmp_path, "{separateMajorMinor: true}")
    assert active.baseline == active.content


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("{packageRules: [", "can't be parsed"),
        ("[]", "is not an object"),
        (
            '{packageRules: [{matchPackageNames: ["Serilog"], enabled: false}]}',
            "has no description",
        ),
        (
            '{packageRules: [{description: "x", matchFileNames: ["a"], enabled: false}]}',
            "holds updates with matchFileNames",
        ),
        (
            '{packageRules: [{description: "x", excludePackageNames: ["a"], enabled: false}]}',
            "holds updates with excludePackageNames",
        ),
        (
            '{packageRules: [{description: "x", matchPackageNames: ["/(?<n>a)/"], '
            "enabled: false}]}",
            "can't evaluate",
        ),
        (
            '{packageRules: [{description: "x", matchPackageNames: ["+(a|b)"], enabled: false}]}',
            "extended glob",
        ),
        ('{packageRules: [{matchPackageNames: ["a"], enabled: true}]}', "enabled: true"),
        (
            '{packageRules: [{description: "x", matchPackageNames: ["!(a|b)"], enabled: false}]}',
            "extended glob",
        ),
        # Renovate turns these into rules of its own, which the scan wouldn't see.
        ('{packageRules: [{matchPackageNames: ["X"], major: {enabled: false}}]}', "major"),
        ("{major: {enabled: false}}", "configures major updates directly"),
        ("{lockFileMaintenance: {enabled: true}}", "configures lockFileMaintenance"),
        # Presets bring in rules the scan never reads.
        ('{extends: ["config:recommended"]}', "uses extends"),
        (
            '{packageRules: [{matchPackageNames: ["X"], extends: [":disableMajorUpdates"]}]}',
            "uses extends",
        ),
        # Hold rules may only contain what the scan understands.
        (
            '{packageRules: [{description: "x", matchPackageNames: ["X"], enabled: false, '
            'groupName: "g"}]}',
            "holds updates with groupName",
        ),
        (
            '{packageRules: [{matchPackageNames: ["X"], overridePackageName: "Y"}]}',
            "overridePackageName",
        ),
        # Renovate also matches `bump`, on a flag its report doesn't carry.
        (
            '{packageRules: [{description: "x", matchUpdateTypes: "bump", enabled: false}]}',
            "can't evaluate 'bump'",
        ),
        (
            '{packageRules: [{description: "x", matchUpdateTypes: ["!major"], enabled: false}]}',
            "can't evaluate '!major'",
        ),
    ],
)
def test_an_invalid_policy_fails(tmp_path, checkout, text, error):
    with pytest.raises(PolicyError, match=error):
        policy_from(tmp_path, text)


def test_a_policy_renovate_rejects_fails(tmp_path, checkout):
    (tmp_path / "trial.json5").write_text("{ignoreDep: ['x']}")
    with pytest.raises(PolicyError, match=r"Renovate rejects .*Invalid configuration option"):
        load(
            checkout,
            tmp_path / "trial.json5",
            validate=lambda text: ["Invalid configuration option: ignoreDep"],
        )


def test_renovate_configuration_elsewhere_in_the_revision_fails(checkout):
    (checkout / "renovate.json").write_text("{}")
    with pytest.raises(PolicyError, match=r"configuration in renovate\.json;"):
        load(checkout, validate=accept)


def test_a_missing_trial_policy_fails(tmp_path, checkout):
    with pytest.raises(PolicyError, match="doesn't exist"):
        load(checkout, tmp_path / "nope.json5", validate=accept)


@pytest.mark.parametrize(
    ("value", "patterns", "expected"),
    [
        # Plain names and globs ignore case.
        ("Microsoft.OpenApi", ["microsoft.openapi"], True),
        ("Microsoft.Extensions.Http", ["Microsoft.Extensions.*"], True),
        ("Microsoft.Extensions", ["Microsoft.Extensions.*"], False),
        ("Microsoft.Extensions.Http", ["Microsoft.Extension?.Http"], True),
        ("Serilog", ["{Serilog,Humanizer}*"], True),
        ("Serilog.Sinks.Console", ["Serilog[!.]*"], False),
        # A single * stays within a path segment; ** crosses them.
        ("mcr.microsoft.com/dotnet/sdk", ["mcr.microsoft.com/dotnet/*"], True),
        ("mcr.microsoft.com/dotnet/sdk/x", ["mcr.microsoft.com/dotnet/*"], False),
        ("mcr.microsoft.com/dotnet/sdk/x", ["mcr.microsoft.com/**"], True),
        ("anything/at/all", ["*"], True),
        # Regexes search, and are case-sensitive unless marked /i.
        ("Microsoft.OpenApi", ["/^Microsoft\\./"], True),
        ("Microsoft.OpenApi", ["/^microsoft/"], False),
        ("Microsoft.OpenApi", ["/^microsoft/i"], True),
        ("Microsoft.OpenApi", ["/Open/"], True),
        # Negations must all hold; positives need one match, if there are any.
        ("Microsoft.OpenApi", ["Microsoft.*", "!Microsoft.OpenApi"], False),
        ("Microsoft.Extensions.Http", ["Microsoft.*", "!microsoft.openapi"], True),
        ("Serilog", ["!/^Microsoft/"], True),
        ("Microsoft.OpenApi", ["!/^Microsoft/"], False),
        ("Serilog", [], False),
    ],
)
def test_patterns_match_as_renovate_matches_them(value, patterns, expected):
    assert match_list(value, patterns) is expected


def test_a_rule_matches_only_when_every_matcher_does():
    dep = {"depName": "PyJWT", "packageName": "PyJWT", "datasource": "pypi", "manager": "regex"}
    assert matches({"matchManagers": ["custom.regex"], "matchDatasources": ["pypi"]}, dep)
    assert not matches({"matchManagers": ["regex"]}, dep)
    assert not matches({"matchManagers": ["custom.regex"], "matchDatasources": ["nuget"]}, dep)
    # Before an update is known, a rule on update types doesn't match.
    assert not matches({"matchUpdateTypes": ["major"]}, dep)
    assert matches({"matchUpdateTypes": ["major"]}, {**dep, "updateType": "major"})
    assert not matches({"matchDepNames": ["PyJWT"]}, {**dep, "depName": None})


def test_hold_rules_are_named_by_a_description_list(tmp_path, checkout):
    active = policy_from(
        tmp_path,
        '{packageRules: [{description: ["Held", "for now"], matchDepNames: ["a"], '
        "enabled: false}]}",
    )
    assert [h.name for h in active.holds] == ["Held for now"]


def test_a_single_string_matcher_counts_as_a_list(tmp_path, checkout):
    active = policy_from(
        tmp_path,
        '{packageRules: [{description: "No Serilog majors", matchDatasources: "nuget", '
        'matchPackageNames: "Serilog", matchUpdateTypes: "major", enabled: false}]}',
    )
    found = report(("Serilog", "4.3.0", {"4.4.0": "minor", "5.0.0": "major"}))
    result = classified(found, found, active)
    assert result[("Serilog", "5.0.0")]["held_by"] == "No Serilog majors"
    assert result[("Serilog", "4.4.0")]["classification"] == "in_scope"


def test_a_failed_lookup_under_the_policy_is_not_mistaken_for_a_hold(tmp_path, checkout):
    active = policy_from(tmp_path, HUMANIZER_CAP)
    baseline = report(("Humanizer.Core", "2.8.26", {"2.14.1": "minor"}))
    main = report(("Humanizer.Core", "2.8.26", {}))
    dep = main["repositories"]["local"]["packageFiles"]["nuget"][0]["deps"][0]
    dep["skipReason"] = "rate-limited"
    with pytest.raises(PolicyError, match=r"lookup of .*Humanizer\.Core with the policy ended"):
        classified(baseline, main, active)


@pytest.mark.parametrize(
    ("version", "allowed_versions", "expected"),
    [
        ("11.0.0", "<11.0.0", "held_by_policy"),
        ("10.0.12", "<11.0.0", "in_scope"),
        ("10.0.12", ">=10 <11", "in_scope"),
        ("10.0.12", "/^10\\./", "in_scope"),
        ("11.0.0", "/^10\\./", "held_by_policy"),
    ],
)
def test_lock_drift_honours_allowed_versions(
    tmp_path, checkout, version, allowed_versions, expected
):
    text = (
        '{packageRules: [{description: "Stay on 10", matchPackageNames: ["Microsoft.*"], '
        f"allowedVersions: {json.dumps(allowed_versions)}}}]}}"
    )
    active = policy_from(tmp_path, text)
    fields = {"depName": "Microsoft.Extensions.Http", "packageName": "Microsoft.Extensions.Http"}
    candidate = {"dependency": "locked:a", "update_type": "patch", "version": version}
    (result,) = classify([candidate], None, {"locked:a": fields}, active)
    assert result["classification"] == expected


@pytest.mark.parametrize(
    ("version", "allowed_versions", "expected"),
    [
        ("2.9.9", "<2.10", True),
        ("2.10.0", "<2.10", False),
        ("2.10", "=2.10.0", True),
        ("3.0.0", ">2.10.0 <=3", True),
        ("3.0.1", ">2.10.0 <=3", False),
        ("3.0.1", "!/^3\\./", False),
    ],
)
def test_allowed_versions_comparators(version, allowed_versions, expected):
    assert allowed(version, allowed_versions) is expected


@pytest.mark.parametrize(
    ("version", "allowed_versions"),
    [("11.0.0", "[10,11)"), ("11.0.0", "10.x"), ("11.0.0-rc.1", "<11"), ("11.0.0", "11")],
)
def test_allowed_versions_the_scan_cant_evaluate_fail(version, allowed_versions):
    with pytest.raises(PolicyError, match="can't evaluate allowedVersions"):
        allowed(version, allowed_versions)


def test_renovate_configuration_in_package_json_fails(checkout):
    (checkout / "package.json").write_text('{"name": "x", "renovate": {"extends": []}}')
    with pytest.raises(PolicyError, match=r"configuration in package\.json"):
        load(checkout, validate=accept)


def test_a_package_json_without_renovate_configuration_is_fine(checkout):
    (checkout / "package.json").write_text('{"name": "x"}')
    assert load(checkout, validate=accept) is NO_POLICY


def test_an_unreadable_trial_policy_fails(tmp_path, checkout):
    (tmp_path / "trial.json5").write_bytes(b"\xff\xfe{")
    with pytest.raises(PolicyError, match="can't be read"):
        load(checkout, tmp_path / "trial.json5", validate=accept)
