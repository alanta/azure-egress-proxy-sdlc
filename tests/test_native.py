import json
from pathlib import Path

import pytest

from sdlc.native import NativeUpdate, cross_check, parse_dotnet, parse_go
from sdlc.renovate import normalize

FIXTURES = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy"
NATIVE = FIXTURES / "native" / "064aa09"
AT = "2026-10-08T09:00:00+00:00"


@pytest.fixture(scope="module")
def dotnet():
    listing = json.loads((NATIVE / "dotnet-list-package.json").read_text())
    return parse_dotnet(listing, Path("/src"))


@pytest.fixture(scope="module")
def go():
    return parse_go((NATIVE / "go-list-m-u.json").read_text(), "proxy/go.mod")


@pytest.fixture(scope="module")
def scanned():
    report = FIXTURES / "renovate" / "064aa09" / "report-with-scan-config.json"
    return normalize(json.loads(report.read_text()), looked_up_at=AT)


def find(updates, name, location=None):
    return [u for u in updates if u.name == name and (location is None or u.location == location)]


def test_dotnet_reports_direct_and_transitive_packages(dotnet):
    (core,) = {u for u in find(dotnet, "Azure.Core") if u.direct}
    assert (core.current, core.latest) == ("1.62.0", "1.63.0")
    # PR #77's case: AppHost locks 10.0.11 transitively although 10.0.12 is declared centrally.
    (http,) = find(dotnet, "Microsoft.Extensions.Http", "src/AppHost/AppHost.csproj")
    assert (http.current, http.latest, http.direct) == ("10.0.11", "10.0.12", False)


def test_go_reports_direct_and_indirect_modules(go):
    (azcore,) = find(go, "github.com/Azure/azure-sdk-for-go/sdk/azcore")
    assert (azcore.current, azcore.latest, azcore.direct) == ("v1.23.1", "v1.23.3", True)
    (crypto,) = find(go, "golang.org/x/crypto")
    assert (crypto.current, crypto.latest, crypto.direct) == ("v0.55.0", "v0.57.0", False)


def test_renovate_and_the_package_managers_agree_on_the_snapshot(dotnet, go, scanned):
    assert cross_check(dotnet + go, scanned.dependencies, scanned.candidates) == []


def test_a_direct_update_the_scan_lacks_is_a_disagreement(dotnet, scanned):
    core_ids = {d["id"] for d in scanned.dependencies if d["name"] == "Azure.Core"}
    without_core = [c for c in scanned.candidates if c["dependency"] not in core_ids]
    (disagreement,) = cross_check(dotnet, scanned.dependencies, without_core)
    assert disagreement["name"] == "Azure.Core"
    assert disagreement["native_latest"] == "1.63.0"
    assert disagreement["scan_candidates"] == []


def test_transitive_updates_are_not_cross_checked(scanned):
    transitive = NativeUpdate("dotnet", "Some.Transitive", "1.0.0", "2.0.0", False, "a.csproj")
    assert cross_check([transitive], scanned.dependencies, scanned.candidates) == []


def test_lock_drift_lists_locked_entries_older_than_declared(dotnet, scanned):
    from sdlc.native import lock_drift

    entries, candidates = lock_drift(dotnet, scanned.dependencies, looked_up_at=AT)
    drift = {
        (e["location"]["file"], e["name"]): (e["current"], c["version"], c["update_type"])
        for e, c in zip(entries, candidates, strict=True)
    }
    assert drift == {
        ("src/AppHost/packages.lock.json", "Microsoft.Extensions.Http"): (
            "10.0.11",
            "10.0.12",
            "patch",
        ),
        ("src/AppHost/packages.lock.json", "OpenTelemetry.Exporter.OpenTelemetryProtocol"): (
            "1.15.3",
            "1.19.1",
            "minor",
        ),
        ("src/AppHost/packages.lock.json", "OpenTelemetry.Extensions.Hosting"): (
            "1.15.3",
            "1.19.1",
            "minor",
        ),
        ("src/ControlPlane/packages.lock.json", "System.IdentityModel.Tokens.Jwt"): (
            "8.19.2",
            "8.23.0",
            "minor",
        ),
        ("src/EgressProxy.Client.Tests/packages.lock.json", "Azure.Core"): (
            "1.53.0",
            "1.62.0",
            "minor",
        ),
        ("src/EgressProxy.Client/packages.lock.json", "Azure.Core"): ("1.53.0", "1.62.0", "minor"),
        ("src/AppHost/AllowlistSeeder/packages.lock.json", "Azure.Core"): (
            "1.55.0",
            "1.62.0",
            "minor",
        ),
    }
    assert all(e["origin"] == "locked" for e in entries)


def test_lock_drift_entries_make_a_valid_record(dotnet, scanned, record_from):
    from sdlc.native import lock_drift
    from sdlc.record import validate_record

    entries, candidates = lock_drift(dotnet, scanned.dependencies, looked_up_at=AT)
    inventory = type(scanned)(scanned.dependencies + entries, scanned.candidates + candidates)
    assert validate_record(record_from(inventory)) == []


def test_up_to_date_and_undeclared_transitive_packages_are_not_drift(scanned):
    from sdlc.native import lock_drift

    native = [
        NativeUpdate("dotnet", "Azure.Core", "1.62.0", "1.63.0", False, "src/A/A.csproj"),
        NativeUpdate("dotnet", "Not.Declared", "1.0.0", "2.0.0", False, "src/A/A.csproj"),
        NativeUpdate("go", "golang.org/x/crypto", "v0.55.0", "v0.57.0", False, "proxy/go.mod"),
    ]
    assert lock_drift(native, scanned.dependencies, looked_up_at=AT) == ([], [])


def test_go_mods_skips_what_the_go_command_ignores(tmp_path):
    from sdlc.native import go_mods

    for directory in ("proxy", "tools/lint", "proxy/testdata/x", "vendor/y", "_old", ".hidden"):
        (tmp_path / directory).mkdir(parents=True)
        (tmp_path / directory / "go.mod").write_text("module m\n")
    assert go_mods(tmp_path) == ["proxy/go.mod", "tools/lint/go.mod"]
