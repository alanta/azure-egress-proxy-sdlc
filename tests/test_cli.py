import pytest

from sdlc.cli import main


def test_no_command_prints_usage_and_fails(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main([])
    assert exit_info.value.code == 2
    assert "usage: sdlc" in capsys.readouterr().err


def test_scan_help_describes_the_command(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--help"])
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "--repo" in out
    assert "Read-only" in out


def test_scan_requires_a_repository(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["scan"])
    assert exit_info.value.code == 2
    assert "--repo" in capsys.readouterr().err


def test_scan_of_an_unknown_ref_fails_without_a_record(monkeypatch, capsys):
    from sdlc import cli
    from sdlc.subject import SubjectError

    def unknown(repository, ref):
        raise SubjectError(f"{repository} has no branch or tag named {ref!r}")

    monkeypatch.setattr(cli, "resolve", unknown)
    assert main(["scan", "--repo", "alanta/demo", "--ref", "nope"]) == 1
    assert "no branch or tag named 'nope'; no record written" in capsys.readouterr().err


@pytest.fixture
def offline_scan(monkeypatch, tmp_path):
    """Run `scan` against an empty checkout, with Renovate and the native queries faked."""
    from contextlib import contextmanager

    from sdlc import cli, coverage, native, osv, renovate
    from sdlc.subject import Revision

    @contextmanager
    def fake_checkout(revision):
        (tmp_path / "checkout").mkdir()
        yield tmp_path / "checkout"

    def nuget(*updates):
        dep = {
            "depName": "Microsoft.Extensions.Http",
            "packageName": "Microsoft.Extensions.Http",
            "datasource": "nuget",
            "currentValue": "10.0.12",
            "updates": [{"updateType": t, "newValue": v} for v, t in updates],
        }
        files = {"nuget": [{"packageFile": "Directory.Packages.props", "deps": [dep]}]}
        return {"repositories": {"local": {"packageFiles": files}}}

    runs = []

    def fake_run(path, *, policy=None, token=None):
        runs.append(policy)
        return nuget(("10.0.13", "patch"), ("11.0.1", "major"))

    monkeypatch.setattr(cli, "resolve", lambda repo, ref: Revision(repo, ref, "a" * 40))
    monkeypatch.setattr(cli, "checkout", fake_checkout)
    monkeypatch.setattr(renovate, "run", fake_run)
    monkeypatch.setattr(renovate, "validate", lambda text: [])
    monkeypatch.setattr(coverage, "gaps", lambda path, report: [])
    monkeypatch.setattr(native, "dotnet_updates", lambda path: [])
    monkeypatch.setattr(native, "go_updates", lambda path: [])
    monkeypatch.setattr(osv, "lock_files", lambda path: [])
    monkeypatch.setattr(osv, "run", lambda path, files: {"results": []})
    return runs


def test_scan_names_the_trial_policy_and_what_it_holds(offline_scan, tmp_path, capsys):
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text(
        '{packageRules: [{description: "Runtime majors wait", '
        'matchPackageNames: ["Microsoft.Extensions.*"], matchUpdateTypes: ["major"], '
        "enabled: false}]}"
    )
    main(["scan", "--repo", "alanta/demo", "--trial-policy", str(trial)])
    out = capsys.readouterr().out
    assert f"policy: trial file {trial}" in out
    assert "1 candidates in scope, 1 held by policy" in out
    assert "held: nuget:Directory.Packages.props:Microsoft.Extensions.Http major 11.0.1: " in out
    assert "Runtime majors wait" in out
    # With and without the hold.
    assert len(offline_scan) == 2


def test_scan_without_a_policy_says_so(offline_scan, capsys):
    main(["scan", "--repo", "alanta/demo"])
    out = capsys.readouterr().out
    assert "policy: none found, so every candidate is in scope" in out
    assert "2 candidates in scope, 0 held by policy" in out
    assert offline_scan == [None]


def test_scan_with_an_invalid_policy_fails_before_renovate_runs(offline_scan, tmp_path, capsys):
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text('{packageRules: [{matchPackageNames: ["x"], enabled: false}]}')
    assert main(["scan", "--repo", "alanta/demo", "--trial-policy", str(trial)]) == 1
    err = capsys.readouterr().err
    assert "has no description to name it by; no record written" in err
    assert offline_scan == []


def test_scan_without_osv_scanner_reports_vulnerabilities_as_unknown(
    offline_scan, monkeypatch, capsys
):
    from sdlc import osv

    def broken(path, files):
        raise osv.OsvError("OSV-Scanner failed (127): could not reach api.osv.dev")

    monkeypatch.setattr(osv, "run", broken)
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    out = capsys.readouterr().out
    assert "gap: osv-scanner: OSV-Scanner failed (127): could not reach api.osv.dev" in out
    assert "vulnerabilities: unknown" in out
    assert "advisories" not in out
