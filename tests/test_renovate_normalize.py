import json
from pathlib import Path

import json5
import pytest

from sdlc.record import validate_record
from sdlc.renovate import RenovateError, normalize, scan_config

REPORTS = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy" / "renovate" / "064aa09"
GO_DIRECTIVES = Path(__file__).parents[1] / "fixtures" / "renovate-go-directive"
AT = "2026-10-08T09:00:00+00:00"


def load(name):
    return json.loads((REPORTS / name).read_text())


def by_name(inventory, name):
    return [d for d in inventory.dependencies if d["name"] == name]


def candidates_for(inventory, dep_id):
    return {
        c["update_type"]: c["version"] for c in inventory.candidates if c["dependency"] == dep_id
    }


@pytest.fixture(scope="module")
def scanned():
    return normalize(load("report-with-scan-config.json"), looked_up_at=AT)


@pytest.fixture(scope="module")
def without_token():
    return normalize(load("report-without-token.json"), looked_up_at=AT)


def test_every_dependency_in_the_report_is_in_the_inventory(scanned):
    report = load("report-with-scan-config.json")
    total = sum(
        len(entry["deps"])
        for entries in report["repositories"]["local"]["packageFiles"].values()
        for entry in entries
    )
    assert len(scanned.dependencies) == total == 225


@pytest.mark.parametrize("name", ["report-with-scan-config.json", "report-without-token.json"])
def test_normalized_reports_make_valid_records(name, record_from):
    assert validate_record(record_from(normalize(load(name), looked_up_at=AT))) == []


def test_outdated_dependency_gets_its_candidate_and_lookup_details(scanned):
    (aspire,) = by_name(scanned, "Aspire.AppHost.Sdk")
    assert aspire["current"] == "13.5.4"
    assert aspire["location"] == {"file": "src/AppHost/AppHost.csproj"}
    assert aspire["lookup"] == {"state": "outdated", "datasource": "nuget", "looked_up_at": AT}
    assert candidates_for(scanned, aspire["id"]) == {"minor": "13.6.1"}


def test_majors_are_candidates_too(scanned):
    central, referenced = sorted(
        by_name(scanned, "Microsoft.OpenApi"), key=lambda d: d["location"]["file"]
    )
    assert central["location"]["file"] == "Directory.Packages.props"
    assert candidates_for(scanned, central["id"]) == {"major": "3.10.2"}
    # The project's PackageReference has no version of its own; the central one governs it.
    assert referenced["lookup"]["state"] == "skipped"


def test_custom_managers_feed_the_inventory(scanned):
    (pyjwt,) = by_name(scanned, "PyJWT")
    assert pyjwt["ecosystem"] == "pypi"
    assert candidates_for(scanned, pyjwt["id"]) == {"patch": "2.15.1"}
    (cli,) = by_name(scanned, "Aspire.Cli")
    assert candidates_for(scanned, cli["id"]) == {"minor": "13.6.1"}


def test_current_dependency_has_no_candidates(scanned):
    vmss = by_name(scanned, "avm/res/compute/virtual-machine-scale-set")
    assert [d["lookup"]["state"] for d in vmss] == ["current"]
    assert candidates_for(scanned, vmss[0]["id"]) == {}


def test_untrackable_value_is_skipped_with_a_reason(scanned):
    (distroless,) = by_name(scanned, "gcr.io/distroless/static-debian12")
    assert distroless["lookup"]["state"] == "skipped"
    assert "isn't a version" in distroless["lookup"]["reason"]
    assert "looked_up_at" not in distroless["lookup"]


def test_lookups_without_a_token_are_unknown_not_current(without_token):
    checkouts = by_name(without_token, "actions/checkout")
    assert checkouts
    assert {d["lookup"]["state"] for d in checkouts} == {"unknown"}
    assert all("GitHub token" in d["lookup"]["reason"] for d in checkouts)
    assert not [
        c for c in without_token.candidates if c["dependency"] in {d["id"] for d in checkouts}
    ]


def test_repeated_dependencies_get_distinct_ids(scanned):
    ids = [d["id"] for d in scanned.dependencies]
    assert len(ids) == len(set(ids))
    checkouts = [
        i for i in ids if i.startswith("github-actions:.github/workflows/ci.yml:actions/checkout")
    ]
    assert checkouts[1:] == [f"{checkouts[0]}#{n}" for n in range(2, len(checkouts) + 1)]


def synthetic(dep):
    return {
        "repositories": {
            "local": {"packageFiles": {"nuget": [{"packageFile": "a.csproj", "deps": [dep]}]}}
        }
    }


def test_lookup_warning_without_updates_is_unknown():
    dep = {
        "depName": "X",
        "currentValue": "1.0.0",
        "datasource": "nuget",
        "warnings": [{"message": "Failed to look up nuget package X"}],
    }
    (entry,) = normalize(synthetic(dep), looked_up_at=AT).dependencies
    assert entry["lookup"]["state"] == "unknown"
    assert entry["lookup"]["reason"] == "Failed to look up nuget package X"


def test_unhandled_update_type_is_unknown_not_dropped():
    dep = {
        "depName": "X",
        "currentValue": "1.0.0",
        "datasource": "nuget",
        "updates": [{"updateType": "replacement", "newValue": "Y"}],
    }
    inventory = normalize(synthetic(dep), looked_up_at=AT)
    assert inventory.dependencies[0]["lookup"]["state"] == "unknown"
    assert "replacement" in inventory.dependencies[0]["lookup"]["reason"]
    assert inventory.candidates == []


def test_pinning_suggestions_are_not_candidates():
    dep = {
        "depName": "X",
        "currentValue": "1.0.0",
        "datasource": "nuget",
        "updates": [{"updateType": "pinDigest", "newDigest": "sha256:0"}],
    }
    inventory = normalize(synthetic(dep), looked_up_at=AT)
    assert inventory.dependencies[0]["lookup"]["state"] == "current"
    assert inventory.candidates == []


def test_lines_come_from_the_checkout(tmp_path):
    (tmp_path / "ci.yml").write_text(
        "a\n  uses: actions/checkout@v7\nb\n  uses: actions/checkout@v7\n"
    )
    deps = [
        {
            "depName": "actions/checkout",
            "currentValue": "v7",
            "replaceString": "actions/checkout@v7",
        }
    ] * 2
    report = {
        "repositories": {
            "local": {"packageFiles": {"github-actions": [{"packageFile": "ci.yml", "deps": deps}]}}
        }
    }
    inventory = normalize(report, looked_up_at=AT, checkout=tmp_path)
    assert [d["location"].get("line") for d in inventory.dependencies] == [2, 4]


def test_a_report_without_exactly_one_repository_is_rejected():
    with pytest.raises(RenovateError, match="expected one repository"):
        normalize({"repositories": {}}, looked_up_at=AT)


def test_a_name_on_exactly_one_line_locates_entries_without_replace_text(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text(
        '<Project>\n  <PackageVersion Include="Azure.Core" Version="1.62.0" />\n</Project>\n'
    )
    deps = [{"depName": "Azure.Core", "currentValue": "1.62.0"}]
    report = {
        "repositories": {
            "local": {
                "packageFiles": {
                    "nuget": [{"packageFile": "Directory.Packages.props", "deps": deps}]
                }
            }
        }
    }
    inventory = normalize(report, looked_up_at=AT, checkout=tmp_path)
    assert inventory.dependencies[0]["location"] == {"file": "Directory.Packages.props", "line": 2}


def report_with(*entries):
    """A report with these (manager, file, dependency) entries."""
    files: dict[str, dict[str, dict]] = {}
    for manager, file, dep in entries:
        files.setdefault(manager, {}).setdefault(file, {"packageFile": file, "deps": []})
        files[manager][file]["deps"].append(dep)
    package_files = {m: list(by_file.values()) for m, by_file in files.items()}
    return {"repositories": {"local": {"packageFiles": package_files}}}


def test_declarations_without_replace_text_get_the_line_that_declares_them(tmp_path):
    (tmp_path / "go.mod").write_text("module m\n\ngo 1.25.0\n\ntoolchain go1.25.14\n")
    (tmp_path / "ci.yml").write_text(
        "steps:\n"
        "  - uses: actions/setup-go@v6\n"
        "    with:\n"
        "      # go-version: '1.25'\n"
        "      go-version: '1.25'\n"
        "  - uses: actions/setup-python@v6\n"
        "    with:\n"
        "      python-version: 3.12.x\n"
        "  - uses: actions/setup-dotnet@v5\n"
        "    with:\n"
        "      dotnet-version: 10.0.x\n"
    )
    (tmp_path / "global.json").write_text('{\n  "sdk": {\n    "version": "10.0.100"\n  }\n}\n')
    (tmp_path / "AppHost.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n\n'
        '  <Sdk Name="Aspire.AppHost.Sdk" Version="13.5.4" />\n'
    )
    go = {"depName": "go", "datasource": "golang-version"}
    setup = {"datasource": "github-releases", "depType": "uses-with"}
    dotnet = {"depName": "dotnet-sdk", "datasource": "dotnet-version"}
    report = report_with(
        ("gomod", "go.mod", go | {"depType": "golang", "currentValue": "1.25.0"}),
        ("gomod", "go.mod", go | {"depType": "toolchain", "currentValue": "go1.25.14"}),
        ("github-actions", "ci.yml", setup | {"depName": "go", "packageName": "actions/go-versions",
                                              "currentValue": "1.25"}),
        ("github-actions", "ci.yml", setup | {"depName": "python",
                                              "packageName": "actions/python-versions",
                                              "currentValue": "3.12.x"}),
        ("github-actions", "ci.yml", dotnet | {"depType": "uses-with", "currentValue": "10.0.x"}),
        ("nuget", "global.json", dotnet | {"depType": "dotnet-sdk", "currentValue": "10.0.100"}),
        ("nuget", "AppHost.csproj", {"depName": "Aspire.AppHost.Sdk", "datasource": "nuget",
                                     "depType": "msbuild-sdk", "currentValue": "13.5.4"}),
    )  # fmt: skip
    inventory = normalize(report, looked_up_at=AT, checkout=tmp_path)
    assert {d["id"]: d["location"].get("line") for d in inventory.dependencies} == {
        "gomod:go.mod:go": 3,
        "gomod:go.mod:go#2": 5,
        "github-actions:ci.yml:go": 5,  # not the commented-out line
        "github-actions:ci.yml:python": 8,
        "github-actions:ci.yml:dotnet-sdk": 11,
        "nuget:global.json:dotnet-sdk": 3,
        "nuget:AppHost.csproj:Aspire.AppHost.Sdk": 3,
    }


def test_scan_config_bumps_the_go_directive():
    # go-mod-directive versioning reads `go 1.25.14` as a minimum every newer Go satisfies,
    # so without bump Renovate proposes nothing and the directive looks current.
    config = json5.loads(scan_config().read_text())
    assert {
        "matchManagers": ["gomod"],
        "matchDepTypes": ["golang"],
        "rangeStrategy": "bump",
    }.items() <= next(r for r in config["packageRules"] if "rangeStrategy" in r).items()


def test_go_directives_get_newer_go_releases_as_candidates(record_from):
    report = json.loads((GO_DIRECTIVES / "report.json").read_text())
    inventory = normalize(report, looked_up_at=AT)
    lookups = {d["id"]: (d["current"], d["lookup"]["state"]) for d in inventory.dependencies}
    assert lookups == {
        "gomod:a/go.mod:go": ("1.25.14", "outdated"),
        "gomod:b/go.mod:go": ("1.25.0", "outdated"),
        "gomod:b/go.mod:go#2": ("1.25.14", "outdated"),  # the toolchain directive
    }
    # 1.25.14 is the newest 1.25, so its only candidate is the newest minor.
    assert candidates_for(inventory, "gomod:a/go.mod:go") == {"minor": "1.27.2"}
    assert candidates_for(inventory, "gomod:b/go.mod:go") == {"patch": "1.25.14", "minor": "1.27.2"}
    assert candidates_for(inventory, "gomod:b/go.mod:go#2") == {"minor": "1.27.2"}
    assert validate_record(record_from(inventory)) == []
