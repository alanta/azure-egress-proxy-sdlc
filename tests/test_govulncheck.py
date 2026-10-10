import gzip
import json
import subprocess
from pathlib import Path

import pytest

from sdlc import govulncheck, osv
from sdlc.native import GO_IMAGE
from sdlc.record import validate_record
from sdlc.renovate import Inventory, go_toolchains, indirect, normalize

FIXTURES = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy"
AT = "2026-10-09T09:00:00+00:00"
GO_MOD = "proxy/go.mod"
GO_DIRECTIVE = "gomod:proxy/go.mod:go"
CRYPTO = "gomod:proxy/go.mod:golang.org/x/crypto"
NET = "gomod:proxy/go.mod:golang.org/x/net"


@pytest.fixture(scope="module")
def report():
    path = FIXTURES / "renovate" / "064aa09" / "report-with-scan-config.json"
    return json.loads(path.read_text())


@pytest.fixture(scope="module")
def scanned(report):
    """OSV-Scanner's findings at 064aa09, and the inventory as the scan continues with it."""
    inventory = normalize(report, looked_up_at=AT)
    output = json.loads((FIXTURES / "osv" / "064aa09" / "osv-scanner.json").read_text())
    found = osv.findings(
        output,
        inventory.dependencies,
        inventory.candidates,
        indirect=indirect(report),
    )
    updated = {d["id"]: d for d in found.updated}
    merged = Inventory(
        [updated.get(d["id"], d) for d in inventory.dependencies] + found.dependencies,
        inventory.candidates + found.candidates,
    )
    return found, merged


@pytest.fixture(scope="module")
def run_064aa09():
    with gzip.open(FIXTURES / "govulncheck" / "064aa09" / "govulncheck.json.gz") as f:
        text = f.read().decode()
    return govulncheck.Run(GO_MOD, "go1.25.14", govulncheck.parse(text, "go1.25.14"))


def apply(runs, vulnerabilities, inventory, report, **options):
    return govulncheck.apply(
        runs,
        vulnerabilities,
        inventory.dependencies,
        inventory.candidates,
        toolchains=go_toolchains(report),
        indirect=indirect(report),
        **options,
    )


@pytest.mark.parametrize(
    ("go_mod", "expected"),
    [
        ("module m\n\ngo 1.25.14\n", "go1.25.14"),
        # A language version names its first release from Go 1.21 on.
        ("module m\ngo 1.25\n", "go1.25.0"),
        ("module m\ngo 1.20\n", "go1.20"),
        ("module m\ngo 1.25.14\ntoolchain go1.26.3\n", "go1.26.3"),
        ("module m\ngo 1.25.14 // the minimum\ntoolchain go1.26.3 // what CI uses\n", "go1.26.3"),
        ("module m\ngo 1.25.14\ntoolchain default\n", "go1.25.14"),
        ("module m\n", None),
    ],
)
def test_the_toolchain_comes_from_go_mod(go_mod, expected):
    assert govulncheck.toolchain(go_mod) == expected


def test_renovate_names_the_directive_that_sets_the_toolchain(report):
    assert go_toolchains(report) == {GO_MOD: GO_DIRECTIVE}
    gomod = {
        "packageFile": "go.mod",
        "deps": [
            {"depName": "go", "depType": "golang", "currentValue": "1.25.14"},
            {"depName": "go", "depType": "toolchain", "currentValue": "1.26.3"},
        ],
    }
    with_toolchain = {"repositories": {"local": {"packageFiles": {"gomod": [gomod]}}}}
    assert go_toolchains(with_toolchain) == {"go.mod": "gomod:go.mod:go#2"}
    # `toolchain default` sets no toolchain, as govulncheck.toolchain() reads it too.
    gomod["deps"][1]["currentValue"] = "default"
    assert go_toolchains(with_toolchain) == {"go.mod": "gomod:go.mod:go"}


def test_x_net_is_reachable_and_x_crypto_is_not(scanned, run_064aa09, report):
    found, inventory = scanned
    result = apply([run_064aa09], found.vulnerabilities, inventory, report)
    reach = {
        (v["dependency"], v["advisory"]): v["reachability"]
        for v in result.vulnerabilities
        if v["source"] == "osv"
    }
    assert reach == {
        (CRYPTO, "GO-2026-5932"): "not_reachable",
        (CRYPTO, "GO-2026-6354"): "not_reachable",
        (CRYPTO, "GO-2026-6355"): "not_reachable",
        (NET, "GO-2026-6603"): "reachable",
        (NET, "GO-2026-6610"): "reachable",
        (NET, "GO-2026-6611"): "reachable",
        (NET, "GO-2026-6612"): "reachable",
        (NET, "GO-2026-6617"): "reachable",
    }
    # The version match is OSV-Scanner's, unchanged.
    osv_only = [v for v in result.vulnerabilities if v["source"] == "osv"]
    for before, after in zip(found.vulnerabilities, osv_only, strict=True):
        assert {k: v for k, v in after.items() if k != "reachability"} == {
            k: v for k, v in before.items() if k != "reachability"
        }
    assert result.gaps == []


def test_standard_library_advisories_refer_to_the_go_directive(scanned, run_064aa09, report):
    found, inventory = scanned
    result = apply([run_064aa09], found.vulnerabilities, inventory, report)
    stdlib = {v["advisory"]: v for v in result.vulnerabilities if v["source"] == "govulncheck"}
    assert len(stdlib) == 13
    assert {v["dependency"] for v in stdlib.values()} == {GO_DIRECTIVE}
    assert {v["affected_version"] for v in stdlib.values()} == {"1.25.14"}
    # Go 1.25 gets no more fixes, so the fix is on the next line. This report predates the
    # scan config's bump rule for the go directive: Renovate proposed no newer one, so nothing
    # reaches it.
    assert {v["fixed_version"] for v in stdlib.values()} == {"1.26.9"}
    assert {v["fix_reached_by_candidate"] for v in stdlib.values()} == {False}
    # Module level only, or an imported package without a call to the vulnerable function.
    not_reachable = {"GO-2026-6599", "GO-2026-6600", "GO-2026-6604", "GO-2026-6609"}
    assert {a for a, v in stdlib.items() if v["reachability"] == "not_reachable"} == not_reachable
    assert {a for a, v in stdlib.items() if v["reachability"] == "reachable"} == (
        set(stdlib) - not_reachable
    )
    # The x/net advisories that also cover the standard library are recorded on both.
    assert "GO-2026-6603" in stdlib
    assert stdlib["GO-2026-6603"]["aliases"] == ["CVE-2026-78659"]


def test_a_newer_go_directive_reaches_the_standard_library_fixes(scanned, run_064aa09, report):
    # What the bump rule makes Renovate propose for `go 1.25.14`
    # (fixtures/renovate-go-directive): the newest minor, past the 1.26.9 fix.
    found, inventory = scanned
    outdated = {"state": "outdated", "datasource": "golang-version", "looked_up_at": AT}
    candidate = {
        "dependency": GO_DIRECTIVE,
        "update_type": "minor",
        "version": "1.27.2",
        "classification": "in_scope",
    }
    bumped = Inventory(
        [
            d | {"lookup": outdated} if d["id"] == GO_DIRECTIVE else d
            for d in inventory.dependencies
        ],
        [*inventory.candidates, candidate],
    )
    result = apply([run_064aa09], found.vulnerabilities, bumped, report)
    stdlib = [v for v in result.vulnerabilities if v["source"] == "govulncheck"]
    assert len(stdlib) == 13
    assert {v["fix_reached_by_candidate"] for v in stdlib} == {True}


def test_the_result_makes_a_valid_record(scanned, run_064aa09, report, record_from):
    found, inventory = scanned
    result = apply([run_064aa09], found.vulnerabilities, inventory, report)
    record = record_from(inventory)
    record["vulnerabilities"] = result.vulnerabilities
    record["tools"] += govulncheck.tool_entries([run_064aa09])
    assert validate_record(record) == []


def nuget_vulnerability(**fields):
    entry = {
        "id": "nuget:Directory.Packages.props:Azure.Identity",
        "ecosystem": "nuget",
        "name": "Azure.Identity",
        "current": "1.10.0",
        "origin": "declared",
        "location": {"file": "Directory.Packages.props"},
        "lookup": {"state": "current", "datasource": "nuget", "looked_up_at": AT},
    }
    vulnerability = {
        "advisory": "GHSA-1",
        "dependency": entry["id"],
        "affected_version": "1.10.0",
        "fixed_version": None,
        "source": "osv",
        "reachability": "unknown",
    } | fields
    return entry, vulnerability


def test_non_go_advisories_stay_unknown(scanned, run_064aa09, report):
    found, inventory = scanned
    # Even one sharing a CVE with a Go advisory govulncheck found reachable.
    entry, nuget = nuget_vulnerability(aliases=["CVE-2026-78659"])
    inventory = Inventory([*inventory.dependencies, entry], inventory.candidates)
    result = apply([run_064aa09], [*found.vulnerabilities, nuget], inventory, report)
    (after,) = [v for v in result.vulnerabilities if v["dependency"] == entry["id"]]
    assert after["reachability"] == "unknown"


def test_a_go_advisory_govulncheck_has_no_finding_for_stays_unknown(scanned, run_064aa09, report):
    found, inventory = scanned
    other = dict(found.vulnerabilities[0], advisory="GHSA-only-on-osv-dev", aliases=[])
    result = apply([run_064aa09], [other], inventory, report)
    (after,) = [v for v in result.vulnerabilities if v["source"] == "osv"]
    assert after["reachability"] == "unknown"


def test_a_failed_run_is_a_gap_and_leaves_reachability_unknown(scanned, report):
    found, inventory = scanned
    failed = govulncheck.Run(GO_MOD, "go1.25.14", None, "go: downloading go1.25.14: timeout")
    result = apply([failed], found.vulnerabilities, inventory, report)
    assert result.vulnerabilities == found.vulnerabilities
    assert {v["reachability"] for v in result.vulnerabilities} == {"unknown"}
    (gap,) = result.gaps
    assert gap["kind"] == "unavailable_source"
    assert gap["subject"] == "govulncheck: proxy/go.mod"
    assert "timeout" in gap["reason"]
    assert govulncheck.tool_entries([failed]) == [
        {"name": "govulncheck", "version": govulncheck.VERSION, "image": GO_IMAGE}
    ]


def test_the_tool_entries_name_the_toolchain_and_database_used(run_064aa09):
    assert govulncheck.tool_entries([run_064aa09]) == [
        {"name": "govulncheck", "version": "v1.8.0", "image": GO_IMAGE},
        {
            "name": "go toolchain for govulncheck (proxy/go.mod, linux/amd64, linux/arm64)",
            "version": "go1.25.14",
        },
        {"name": "govulncheck database https://vuln.go.dev", "version": "2026-10-08T22:31:09Z"},
    ]


class FakeRun:
    def __init__(self, returncode, stdout="", stderr=""):
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, "podman version 4.9.3", "")
        return self.result


def test_govulncheck_runs_read_only_with_the_declared_toolchain(monkeypatch, tmp_path):
    fake = FakeRun(0, "{}")
    monkeypatch.setattr(subprocess, "run", fake)
    assert govulncheck.run(tmp_path, GO_MOD, "go1.25.14") == "{}"
    command = fake.commands[-1]
    assert GO_IMAGE in command
    assert f"{tmp_path}:/src:ro,Z" in command
    assert command[command.index("--workdir") + 1] == "/src/proxy"
    for env in (
        "GOTOOLCHAIN=go1.25.14",
        "GOFLAGS=-mod=readonly",
        "GOWORK=off",
        "GOOS=linux",
        "CGO_ENABLED=0",
    ):
        assert env in command
    script = command[-1]
    # Built once, for the container, then run per platform.
    assert script.count("go install golang.org/x/vuln/cmd/govulncheck@v1.8.0") == 1
    assert "GOTOOLCHAIN=local" in script
    assert "for arch in amd64 arm64; do" in script
    assert "GOARCH=$arch /tmp/go/bin/govulncheck -format json ./..." in script


def test_vendored_sources_are_analysed(monkeypatch, tmp_path):
    (tmp_path / "proxy" / "vendor").mkdir(parents=True)
    (tmp_path / "proxy" / "vendor" / "modules.txt").write_text("# example.com/lib v1.2.0\n")
    fake = FakeRun(0, "{}")
    monkeypatch.setattr(subprocess, "run", fake)
    govulncheck.run(tmp_path, GO_MOD, "go1.25.14")
    assert "GOFLAGS=-mod=vendor" in fake.commands[-1]


def test_the_fixture_has_both_platforms(run_064aa09):
    assert list(run_064aa09.platforms) == ["linux/amd64", "linux/arm64"]


def platform_stream(platform, *messages):
    config = {"config": {"go_version": "go1.25.14"}}
    return "\n".join(json.dumps(m) for m in ({"sdlc_platform": platform}, config, *messages))


def test_a_missing_platform_is_an_error():
    with pytest.raises(govulncheck.GovulncheckError, match="not \\['linux/amd64'"):
        govulncheck.parse(platform_stream("linux/amd64"), "go1.25.14")


def finding(vuln_id, module, version, *, package=None, function=None):
    frame = {"module": module, "version": version}
    if package:
        frame["package"] = package
    if function:
        frame["function"] = function
    return {"finding": {"osv": vuln_id, "trace": [frame]}}


def test_the_most_precise_level_on_any_platform_counts(scanned, report):
    found, inventory = scanned
    amd64 = platform_stream(
        "linux/amd64", finding("GO-2026-6354", "golang.org/x/crypto", "v0.55.0")
    )
    # Say a call into x/crypto/ssh only exists in an arm64-only file.
    arm64 = platform_stream(
        "linux/arm64",
        finding(
            "GO-2026-6354",
            "golang.org/x/crypto",
            "v0.55.0",
            package="golang.org/x/crypto/ssh",
            function="Dial",
        ),
    )
    platforms = govulncheck.parse(amd64 + "\n" + arm64, "go1.25.14")
    result = apply(
        [govulncheck.Run(GO_MOD, "go1.25.14", platforms)], found.vulnerabilities, inventory, report
    )
    (ssh,) = [v for v in result.vulnerabilities if v["advisory"] == "GO-2026-6354"]
    assert ssh["reachability"] == "reachable"


def test_an_advisory_on_a_module_outside_the_inventory_gets_a_locked_entry(
    scanned, report, record_from, tmp_path
):
    found, inventory = scanned
    record = {
        "id": "GO-2026-9999",
        "aliases": ["CVE-2026-9999"],
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "example.com/lib"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}],
            }
        ],
    }
    stream = "\n".join(
        [
            platform_stream("linux/amd64", {"osv": record}),
            platform_stream(
                "linux/arm64",
                finding("GO-2026-9999", "example.com/lib", "v1.2.0", package="example.com/lib"),
            ),
        ]
    )
    run = govulncheck.Run(GO_MOD, "go1.25.14", govulncheck.parse(stream, "go1.25.14"))
    held = []

    def classify(candidates, fields):
        held.append(fields)
        return candidates

    result = apply([run], found.vulnerabilities, inventory, report, classify=classify)
    (entry,) = result.dependencies
    assert entry["id"] == "locked:proxy/go.mod:example.com/lib"
    assert (entry["origin"], entry["current"]) == ("locked", "v1.2.0")
    (candidate,) = result.candidates
    assert (candidate["dependency"], candidate["version"]) == (entry["id"], "v1.3.0")
    assert held and entry["id"] in held[0]
    (added,) = [v for v in result.vulnerabilities if v["advisory"] == "GO-2026-9999"]
    assert added == {
        "advisory": "GO-2026-9999",
        "aliases": ["CVE-2026-9999"],
        "dependency": entry["id"],
        "affected_version": "v1.2.0",
        "fixed_version": "v1.3.0",
        "fix_reached_by_candidate": True,
        "source": "govulncheck",
        "reachability": "not_reachable",
    }
    full = Inventory(
        inventory.dependencies + result.dependencies, inventory.candidates + result.candidates
    )
    record = record_from(full)
    record["vulnerabilities"] = result.vulnerabilities
    assert validate_record(record) == []


def test_a_failing_govulncheck_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", FakeRun(1, "", "go: errors parsing go.mod"))
    with pytest.raises(govulncheck.GovulncheckError, match=r"parsing go\.mod"):
        govulncheck.run(tmp_path, GO_MOD, "go1.25.14")


def test_a_toolchain_that_isnt_a_go_release_is_not_run(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", FakeRun(0))
    with pytest.raises(govulncheck.GovulncheckError, match="isn't a Go release"):
        govulncheck.run(tmp_path, GO_MOD, "go1.25; rm -rf /")


@pytest.mark.parametrize(
    "output",
    ["not json", '{"config": {"go_version": "go1.27.1"}}', '{"progress": {}}'],
)
def test_output_from_another_toolchain_or_not_json_is_an_error(output):
    with pytest.raises(govulncheck.GovulncheckError):
        govulncheck.parse(output, "go1.25.14")


def test_scan_keeps_a_failure_per_module(monkeypatch, tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "go.mod").write_text("module a\n")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "go.mod").write_text("module b\ngo 1.25.14\n")
    monkeypatch.setattr(govulncheck, "go_mods", lambda path: ["a/go.mod", "b/go.mod"])

    def broken(checkout, go_mod, name):
        raise govulncheck.GovulncheckError("no network")

    monkeypatch.setattr(govulncheck, "run", broken)
    runs = govulncheck.scan(tmp_path)
    assert [(r.go_mod, r.toolchain, r.platforms, r.error) for r in runs] == [
        ("a/go.mod", None, None, "go.mod declares no Go version"),
        ("b/go.mod", "go1.25.14", None, "no network"),
    ]
