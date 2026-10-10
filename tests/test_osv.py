import json
import subprocess
from pathlib import Path

import pytest

from sdlc import osv
from sdlc.native import lock_drift, parse_dotnet
from sdlc.policy import classify, load
from sdlc.record import validate_record
from sdlc.renovate import Inventory, indirect, normalize

FIXTURES = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy"
AT = "2026-10-09T09:00:00+00:00"
CRYPTO = "gomod:proxy/go.mod:golang.org/x/crypto"


@pytest.fixture(scope="module")
def report():
    path = FIXTURES / "renovate" / "064aa09" / "report-with-scan-config.json"
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def inventory(report):
    return normalize(report, looked_up_at=AT)


@pytest.fixture(scope="module")
def scanned():
    return json.loads((FIXTURES / "osv" / "064aa09" / "osv-scanner.json").read_text())


def merged(inventory, found):
    """The inventory as the scan continues with it."""
    updated = {d["id"]: d for d in found.updated}
    return Inventory(
        [updated.get(d["id"], d) for d in inventory.dependencies] + found.dependencies,
        inventory.candidates + found.candidates,
    )


def find(output, inventory, report, checkout=None, **options):
    return osv.findings(
        output,
        inventory.dependencies,
        inventory.candidates,
        indirect=indirect(report),
        checkout=checkout,
        **options,
    )


def advisory(vuln_id, name, ecosystem, *ranges, aliases=()):
    return {
        "id": vuln_id,
        "aliases": list(aliases),
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": events} for events in ranges],
            }
        ],
    }


def output_for(file, name, version, *vulnerabilities, ecosystem="NuGet"):
    return {
        "results": [
            {
                "source": {"path": f"/src/{file}", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": name, "version": version, "ecosystem": ecosystem},
                        "vulnerabilities": list(vulnerabilities),
                        "groups": [{"ids": [v["id"]]} for v in vulnerabilities],
                    }
                ],
            }
        ]
    }


def test_x_crypto_advisories_refer_to_renovates_indirect_entry(scanned, inventory, report):
    found = find(scanned, inventory, report)

    (crypto,) = [d for d in found.updated if d["id"] == CRYPTO]
    (before,) = [d for d in inventory.dependencies if d["id"] == CRYPTO]
    assert before["lookup"]["state"] == "skipped"
    # Same entry, now with the lookup that goes with its fix candidate.
    assert {k: v for k, v in crypto.items() if k != "lookup"} == {
        k: v for k, v in before.items() if k != "lookup"
    }
    assert crypto["origin"] == "declared"
    assert crypto["current"] == "v0.55.0"
    # No registry was asked: the lookup says so and claims no lookup time.
    assert crypto["lookup"] == {
        "state": "outdated",
        "basis": "advisory_fix",
        "reason": "Not looked up in a registry: lock-file-only dependencies and indirect "
        "modules aren't. Its candidate is the fixed version its advisories name, which may not "
        "be the newest.",
        "datasource": "go",
    }
    (candidate,) = [c for c in found.candidates if c["dependency"] == CRYPTO]
    assert candidate["version"] == "v0.56.0"
    assert candidate["basis"] == "advisory_fix"

    advisories = {v["advisory"]: v for v in found.vulnerabilities if v["dependency"] == CRYPTO}
    assert set(advisories) == {"GO-2026-5932", "GO-2026-6354", "GO-2026-6355"}
    # openpgp is unmaintained: there is no fix to reach.
    assert advisories["GO-2026-5932"]["fixed_version"] is None
    assert "fix_reached_by_candidate" not in advisories["GO-2026-5932"]
    for ssh in ("GO-2026-6354", "GO-2026-6355"):
        assert advisories[ssh]["fixed_version"] == "v0.56.0"
        assert advisories[ssh]["fix_reached_by_candidate"] is True
    assert advisories["GO-2026-6354"]["aliases"] == ["CVE-2026-78662"]
    assert {v["source"] for v in found.vulnerabilities} == {"osv"}
    assert {v["reachability"] for v in found.vulnerabilities} == {"unknown"}


def test_an_indirect_module_already_listed_gets_no_second_entry(scanned, inventory, report):
    found = find(scanned, inventory, report)
    assert found.dependencies == []
    assert [d["name"] for d in found.updated] == ["golang.org/x/crypto", "golang.org/x/net"]
    assert {v["dependency"] for v in found.vulnerabilities} == {
        CRYPTO,
        "gomod:proxy/go.mod:golang.org/x/net",
    }
    assert len({d["id"] for d in merged(inventory, found).dependencies}) == len(
        inventory.dependencies
    )


def test_findings_make_a_valid_record(scanned, inventory, report, record_from):
    found = find(scanned, inventory, report)
    record = record_from(merged(inventory, found))
    record["vulnerabilities"] = found.vulnerabilities
    record["gaps"] += found.gaps
    assert validate_record(record) == []


def test_a_fixed_version_without_an_answer_on_reaching_it_is_invalid(
    scanned, inventory, report, record_from
):
    found = find(scanned, inventory, report)
    record = record_from(merged(inventory, found))
    record["vulnerabilities"] = [
        {k: v for k, v in found.vulnerabilities[1].items() if k != "fix_reached_by_candidate"}
    ]
    assert any("fix_reached_by_candidate" in p for p in validate_record(record))


def test_a_finding_on_a_declared_version_refers_to_it(inventory, report):
    output = output_for(
        "src/Portal/packages.lock.json",
        "Azure.Core",
        "1.62.0",
        advisory("GHSA-reach", "Azure.Core", "NuGet", [{"introduced": "0"}, {"fixed": "1.63.0"}]),
        advisory("GHSA-beyond", "Azure.Core", "NuGet", [{"introduced": "0"}, {"fixed": "1.64.0"}]),
    )
    # The same package in a second lock file is still the one central version.
    output["results"].append({**output["results"][0], "source": {"path": "/src/src/x.json"}})
    found = find(output, inventory, report)

    assert found.dependencies == []
    assert found.candidates == []
    reach = {v["advisory"]: v["fix_reached_by_candidate"] for v in found.vulnerabilities}
    # Renovate's candidate for the central version is 1.63.0.
    assert reach == {"GHSA-reach": True, "GHSA-beyond": False}
    assert {v["dependency"] for v in found.vulnerabilities} == {
        "nuget:Directory.Packages.props:Azure.Core"
    }


def test_a_finding_on_a_drifted_lock_file_refers_to_the_drift_entry(inventory, report):
    listing = json.loads((FIXTURES / "native" / "064aa09" / "dotnet-list-package.json").read_text())
    drifted, drift_candidates = lock_drift(
        parse_dotnet(listing, Path("/src")), inventory.dependencies, looked_up_at=AT
    )
    with_drift = Inventory(
        inventory.dependencies + drifted, inventory.candidates + drift_candidates
    )
    output = output_for(
        "src/EgressProxy.Client/packages.lock.json",
        "Azure.Core",
        "1.53.0",
        advisory("GHSA-old", "Azure.Core", "NuGet", [{"introduced": "0"}, {"fixed": "1.60.0"}]),
    )
    found = find(output, with_drift, report)
    assert found.dependencies == []
    (vulnerability,) = found.vulnerabilities
    assert (
        vulnerability["dependency"] == "locked:src/EgressProxy.Client/packages.lock.json:Azure.Core"
    )
    # The drift candidate, the declared 1.62.0, is past the fix.
    assert vulnerability["fix_reached_by_candidate"] is True


def test_an_undeclared_transitive_package_gets_one_locked_entry_per_lock_file(inventory, report):
    vuln = advisory("GHSA-t", "Some.Transitive", "NuGet", [{"introduced": "0"}, {"fixed": "2.0.1"}])
    output = output_for("src/Portal/packages.lock.json", "Some.Transitive", "2.0.0", vuln)
    output["results"][0]["packages"] *= 2  # listed twice, as for two target frameworks
    found = find(output, inventory, report)
    (entry,) = found.dependencies
    assert entry["id"] == "locked:src/Portal/packages.lock.json:Some.Transitive"
    assert entry["locked_because"] == "vulnerability"
    assert found.candidates == [
        {
            "dependency": entry["id"],
            "update_type": "patch",
            "version": "2.0.1",
            "classification": "in_scope",
            "basis": "advisory_fix",
        }
    ]
    assert entry["lookup"]["basis"] == "advisory_fix"
    assert len(found.vulnerabilities) == 1


def holding_x_minors(tmp_path):
    (tmp_path / "trial.json5").write_text(
        '{packageRules: [{description: "x/ modules wait", matchPackageNames: '
        '["golang.org/x/**"], matchUpdateTypes: ["minor"], enabled: false}]}'
    )
    active = load(tmp_path, tmp_path / "trial.json5", validate=lambda text: [])
    return lambda candidates, fields: classify(candidates, None, fields, active)


def test_added_candidates_are_classified_by_the_policy(scanned, inventory, report, tmp_path):
    found = find(scanned, inventory, report, classify=holding_x_minors(tmp_path))
    assert {c["classification"] for c in found.candidates} == {"held_by_policy"}
    assert {c["held_by"] for c in found.candidates} == {"x/ modules wait"}


def test_a_fix_only_a_held_candidate_reaches_is_not_reached(
    scanned, inventory, report, tmp_path, record_from
):
    found = find(scanned, inventory, report, classify=holding_x_minors(tmp_path))
    (ssh,) = [v for v in found.vulnerabilities if v["advisory"] == "GO-2026-6354"]
    assert ssh["fix_reached_by_candidate"] is False
    assert ssh["fix_held_by"] == "x/ modules wait"
    record = record_from(merged(inventory, found))
    record["vulnerabilities"] = found.vulnerabilities
    assert validate_record(record) == []


def test_a_held_renovate_candidate_does_not_reach_the_fix(inventory, report):
    held = [
        {**c, "classification": "held_by_policy", "held_by": "Azure waits"}
        if c["dependency"] == "nuget:Directory.Packages.props:Azure.Core"
        else c
        for c in inventory.candidates
    ]
    output = output_for(
        "src/Portal/packages.lock.json",
        "Azure.Core",
        "1.62.0",
        advisory("GHSA-reach", "Azure.Core", "NuGet", [{"introduced": "0"}, {"fixed": "1.63.0"}]),
    )
    (vulnerability,) = find(output, Inventory(inventory.dependencies, held), report).vulnerabilities
    assert (vulnerability["fix_reached_by_candidate"], vulnerability["fix_held_by"]) == (
        False,
        "Azure waits",
    )


def test_the_report_says_when_only_held_candidates_reach_the_fix(
    scanned, inventory, report, tmp_path, record_from
):
    from sdlc.report import render

    found = find(scanned, inventory, report, classify=holding_x_minors(tmp_path))
    record = record_from(merged(inventory, found))
    record["vulnerabilities"] = found.vulnerabilities
    record["gaps"] += found.gaps
    assert validate_record(record) == []
    assert (
        "| GO-2026-6354 (CVE-2026-78662) | golang.org/x/crypto v0.55.0 | proxy/go.mod | unknown "
        "| fixed in v0.56.0 | no, only candidates held by x/ modules wait | osv |"
    ) in render(record)


def go_entry(lookup, *candidate_versions):
    dep_id = "gomod:proxy/go.mod:golang.org/x/crypto"
    entry = {
        "id": dep_id,
        "ecosystem": "go",
        "name": "golang.org/x/crypto",
        "current": "v0.55.0",
        "origin": "declared",
        "location": {"file": "proxy/go.mod"},
        "lookup": lookup,
    }
    candidates = [
        {"dependency": dep_id, "update_type": "minor", "version": v, "classification": "in_scope"}
        for v in candidate_versions
    ]
    return entry, candidates


CRYPTO_FIX = advisory(
    "GO-2", "golang.org/x/crypto", "Go", [{"introduced": "0"}, {"fixed": "0.56.0"}]
)


def test_an_indirect_module_renovate_looked_up_keeps_its_lookup(report):
    looked_up = {"state": "outdated", "datasource": "go", "looked_up_at": AT}
    entry, candidates = go_entry(looked_up, "v0.57.0")
    output = output_for("proxy/go.mod", "golang.org/x/crypto", "0.55.0", CRYPTO_FIX, ecosystem="Go")
    found = osv.findings(output, [entry], candidates, indirect={entry["id"]})
    assert (found.dependencies, found.updated, found.candidates) == ([], [], [])
    (vulnerability,) = found.vulnerabilities
    assert vulnerability["dependency"] == entry["id"]
    assert vulnerability["fix_reached_by_candidate"] is True
    assert entry["lookup"] == looked_up


def test_an_indirect_module_renovate_looked_up_gets_the_fix_its_candidates_miss(report):
    entry, candidates = go_entry(
        {"state": "outdated", "datasource": "go", "looked_up_at": AT}, "v0.55.1"
    )
    output = output_for("proxy/go.mod", "golang.org/x/crypto", "0.55.0", CRYPTO_FIX, ecosystem="Go")
    found = osv.findings(output, [entry], candidates, indirect={entry["id"]})
    assert found.updated == []
    assert [c["version"] for c in found.candidates] == ["v0.56.0"]
    # Renovate's lookup stands; only the added fix says it came from the advisory.
    assert [c["basis"] for c in found.candidates] == ["advisory_fix"]
    assert "basis" not in entry["lookup"]
    assert found.vulnerabilities[0]["fix_reached_by_candidate"] is True


def advisory_fix_record(record_from, inventory, report, scanned):
    found = find(scanned, inventory, report)
    record = record_from(merged(inventory, found))
    record["vulnerabilities"] = found.vulnerabilities
    return record


def test_a_candidate_from_an_advisory_must_be_a_fixed_version_it_names(
    scanned, inventory, report, record_from
):
    record = advisory_fix_record(record_from, inventory, report, scanned)
    assert validate_record(record) == []
    (candidate,) = [c for c in record["candidates"] if c["dependency"] == CRYPTO]
    candidate["version"] = "v0.57.0"
    assert validate_record(record) == [
        f"$.candidates[{record['candidates'].index(candidate)}]: no advisory on {CRYPTO!r} "
        "names 'v0.57.0' as fixed"
    ]


def test_an_entry_not_looked_up_has_only_candidates_from_advisories(
    scanned, inventory, report, record_from
):
    record = advisory_fix_record(record_from, inventory, report, scanned)
    (candidate,) = [c for c in record["candidates"] if c["dependency"] == CRYPTO]
    del candidate["basis"]
    assert validate_record(record) == [
        f"$.candidates[{record['candidates'].index(candidate)}]: {CRYPTO!r} wasn't looked up, "
        "so its candidates come from advisories, yet this one doesn't say so"
    ]


def test_a_lookup_from_advisories_claims_no_lookup_time(scanned, inventory, report, record_from):
    record = advisory_fix_record(record_from, inventory, report, scanned)
    (entry,) = [d for d in record["inventory"] if d["id"] == CRYPTO]
    entry["lookup"]["looked_up_at"] = AT
    assert validate_record(record) != []


def test_versions_match_at_any_precision(report):
    entry = {
        "id": "nuget:Directory.Packages.props:Pkg",
        "ecosystem": "nuget",
        "name": "Pkg",
        "current": "2.1",
        "origin": "declared",
        "location": {"file": "Directory.Packages.props"},
        "lookup": {"state": "current", "datasource": "nuget", "looked_up_at": AT},
    }
    output = output_for(
        "src/A/packages.lock.json",
        "Pkg",
        "2.1.0",
        advisory("GHSA-p", "Pkg", "NuGet", [{"introduced": "0"}, {"fixed": "2.2.0"}]),
    )
    found = osv.findings(output, [entry], [], indirect=set())
    assert found.dependencies == []
    assert found.vulnerabilities[0]["dependency"] == entry["id"]


def test_a_lock_file_missing_from_the_output_is_a_gap(scanned, inventory, report):
    files = [(r["source"]["path"]).removeprefix("/src/") for r in scanned["results"]] + [
        "src/New/packages.lock.json"
    ]
    found = find(scanned, inventory, report, scanned=files)
    gaps = [g for g in found.gaps if g["subject"] == "src/New/packages.lock.json"]
    assert [g["kind"] for g in gaps] == ["unavailable_source"]
    # Every lock file OSV-Scanner was given at 064aa09 is in its output.
    assert len(found.gaps) == 11


def test_packages_without_a_resolved_version_are_unknown(scanned, inventory, report):
    found = find(scanned, inventory, report)
    # Without the checkout, the project references in the lock files can't be told apart.
    assert len(found.gaps) == 10
    assert {g["kind"] for g in found.gaps} == {"unavailable_source"}
    assert "src/Portal/packages.lock.json: servicedefaults" in {g["subject"] for g in found.gaps}
    assert all("unknown" in g["reason"] for g in found.gaps)


def test_the_subjects_own_projects_are_not_unknown(inventory, report, tmp_path):
    lock = tmp_path / "src" / "Portal" / "packages.lock.json"
    lock.parent.mkdir(parents=True)
    lock.write_text(
        json.dumps({"dependencies": {"net10.0": {"ServiceDefaults": {"type": "Project"}}}})
    )
    output = output_for("src/Portal/packages.lock.json", "servicedefaults", "")
    output["results"][0]["packages"].append(
        {"package": {"name": "Unresolved.Package", "version": "", "ecosystem": "NuGet"}}
    )
    found = find(output, inventory, report, checkout=tmp_path)
    assert [g["subject"] for g in found.gaps] == [
        "src/Portal/packages.lock.json: Unresolved.Package"
    ]


def test_a_failed_lookup_leaves_reaching_the_fix_unknown(report):
    inventory = Inventory(
        [
            {
                "id": "nuget:Directory.Packages.props:Pkg",
                "ecosystem": "nuget",
                "name": "Pkg",
                "current": "1.0.0",
                "origin": "declared",
                "location": {"file": "Directory.Packages.props"},
                "lookup": {"state": "unknown", "reason": "rate limited"},
            }
        ],
        [],
    )
    output = output_for(
        "src/A/packages.lock.json",
        "Pkg",
        "1.0.0",
        advisory("GHSA-x", "Pkg", "NuGet", [{"introduced": "0"}, {"fixed": "1.0.1"}]),
    )
    (vulnerability,) = find(output, inventory, report).vulnerabilities
    assert vulnerability["fix_reached_by_candidate"] == "unknown"


def test_a_locked_go_module_is_found_on_its_go_mod_line(tmp_path):
    go_mod = tmp_path / "proxy" / "go.mod"
    go_mod.parent.mkdir()
    go_mod.write_text(
        "module example\n\nrequire (\n\tgolang.org/x/net v0.58.0 // indirect\n)\n"
        "require golang.org/x/crypto v0.55.0 // indirect\n"
    )
    vuln = advisory("GO-1", "golang.org/x/crypto", "Go", [{"introduced": "0"}])
    output = output_for("proxy/go.mod", "golang.org/x/crypto", "0.55.0", vuln, ecosystem="Go")
    found = osv.findings(output, [], [], indirect=set(), checkout=tmp_path)
    (entry,) = found.dependencies
    assert entry["location"] == {"file": "proxy/go.mod", "line": 6}
    assert entry["lookup"]["state"] == "skipped"
    assert found.candidates == []


@pytest.mark.parametrize(
    ("version", "events", "expected"),
    [
        ("1.5.0", [{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}], False),
        ("2.1.0", [{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}], True),
        ("1.2.3", [{"introduced": "1.0.0"}, {"last_affected": "1.2.3"}], True),
        ("1.2.4", [{"introduced": "1.0.0"}, {"last_affected": "1.2.3"}], False),
        ("2.0.0-preview.1", [{"introduced": "0"}, {"fixed": "2.0.0"}], True),
        ("v0.56.0", [{"introduced": "0"}, {"fixed": "0.56.0"}], False),
        ("not-a-version", [{"introduced": "0"}], None),
    ],
)
def test_affected_follows_osv_range_semantics(version, events, expected):
    records = [advisory("X", "Pkg", "NuGet", events)]
    assert osv.affected(version, records, "NuGet", "Pkg") is expected


def test_a_commit_range_cant_be_evaluated():
    record = advisory("X", "Pkg", "Go")
    record["affected"][0]["ranges"] = [{"type": "GIT", "events": [{"introduced": "abc"}]}]
    assert osv.affected("1.0.0", [record], "Go", "Pkg") is None


def test_fixes_for_other_packages_in_the_advisory_are_ignored(scanned):
    # The x/net advisories also name the Go standard library, fixed in 1.26.9.
    (net,) = [
        p
        for r in scanned["results"]
        for p in r["packages"]
        if p["package"]["name"] == "golang.org/x/net" and p.get("vulnerabilities")
    ]
    records = net["vulnerabilities"][:1]
    assert osv.fix("0.58.0", records, "Go", "golang.org/x/net") == ("0.60.0", None)


def test_a_fix_every_entry_of_the_group_agrees_on_is_taken():
    early = advisory("GHSA-a", "Pkg", "NuGet", [{"introduced": "0"}, {"fixed": "1.0.1"}])
    late = advisory("CVE-a", "Pkg", "NuGet", [{"introduced": "0"}, {"fixed": "1.0.2"}])
    assert osv.fix("1.0.0", [early, late], "NuGet", "Pkg") == ("1.0.2", None)


def test_no_fix_when_an_entry_of_the_group_says_there_is_none():
    fixed = advisory("GHSA-a", "Pkg", "NuGet", [{"introduced": "0"}, {"fixed": "1.0.1"}])
    unfixed = advisory("CVE-a", "Pkg", "NuGet", [{"introduced": "0"}])
    assert osv.fix("1.0.0", [fixed, unfixed], "NuGet", "Pkg") == (None, None)


def test_the_fix_comes_from_the_range_containing_the_version():
    record = advisory(
        "X",
        "Pkg",
        "NuGet",
        [{"introduced": "1.0.0"}, {"last_affected": "1.9.0"}],
        [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}],
    )
    assert osv.fix("1.5.0", [record], "NuGet", "Pkg") == (None, "1.9.0")
    assert osv.fix("2.0.3", [record], "NuGet", "Pkg") == ("2.1.0", None)


def test_a_last_affected_version_is_judged_against_candidates(record_from):
    entry = {
        "id": "nuget:Directory.Packages.props:Pkg",
        "ecosystem": "nuget",
        "name": "Pkg",
        "current": "1.2.0",
        "origin": "declared",
        "location": {"file": "Directory.Packages.props"},
        "lookup": {"state": "outdated", "datasource": "nuget", "looked_up_at": AT},
    }
    candidate = {
        "dependency": entry["id"],
        "update_type": "patch",
        "version": "1.2.4",
        "classification": "in_scope",
    }
    output = output_for(
        "src/A/packages.lock.json",
        "Pkg",
        "1.2.0",
        advisory("GHSA-l", "Pkg", "NuGet", [{"introduced": "0"}, {"last_affected": "1.2.3"}]),
    )
    found = osv.findings(output, [entry], [candidate], indirect=set())
    (vulnerability,) = found.vulnerabilities
    assert vulnerability["fixed_version"] is None
    assert vulnerability["last_affected"] == "1.2.3"
    assert vulnerability["fix_reached_by_candidate"] is True
    record = record_from(Inventory([entry], [candidate]))
    record["vulnerabilities"] = found.vulnerabilities
    assert validate_record(record) == []


class FakeRun:
    def __init__(self, returncode, stdout="", stderr=""):
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        self.commands = []
        self.configs = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        for arg in command:
            if arg.endswith(":/config:ro,Z"):
                config = Path(arg.removesuffix(":/config:ro,Z")) / "osv-scanner.toml"
                self.configs.append(config.read_text())
        return self.result


def test_advisories_found_is_not_a_failure(monkeypatch, tmp_path):
    fake = FakeRun(1, json.dumps({"results": []}))
    monkeypatch.setattr(subprocess, "run", fake)
    assert osv.run(tmp_path, ["proxy/go.mod"]) == {"results": []}
    (command,) = fake.commands
    assert osv.IMAGE in command
    assert command[-2:] == ["--lockfile", "/src/proxy/go.mod"]
    assert f"{tmp_path}:/src:ro,Z" in command


def test_the_subjects_osv_scanner_config_is_overridden(monkeypatch, tmp_path):
    (tmp_path / "osv-scanner.toml").write_text('[[IgnoredVulns]]\nid = "GO-2026-5932"\n')
    fake = FakeRun(1, json.dumps({"results": []}))
    monkeypatch.setattr(subprocess, "run", fake)
    osv.run(tmp_path, ["proxy/go.mod"])
    (command,) = fake.commands
    assert "--config=/config/osv-scanner.toml" in command
    # The scan's own configuration, empty, not the subject's.
    assert fake.configs == [""]


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [(127, ""), (128, ""), (0, "not json"), (1, "[]")],
)
def test_a_failed_run_is_an_error(monkeypatch, tmp_path, returncode, stdout):
    monkeypatch.setattr(subprocess, "run", FakeRun(returncode, stdout, "no route to osv.dev"))
    with pytest.raises(osv.OsvError):
        osv.run(tmp_path, ["proxy/go.mod"])


def test_no_lock_files_means_nothing_to_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", FakeRun(127))
    assert osv.run(tmp_path, []) == {"results": []}


def test_the_tool_entry_is_pinned_by_digest():
    entry = osv.tool_entry()
    assert entry["name"] == "osv-scanner"
    assert "@sha256:" in entry["image"]
    assert entry["version"] in entry["image"]
