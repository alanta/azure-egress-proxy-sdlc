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

    from sdlc import cli, coverage, govulncheck, native, osv, renovate
    from sdlc.subject import Revision

    @contextmanager
    def fake_checkout(revision):
        (tmp_path / "checkout").mkdir(exist_ok=True)
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

    monkeypatch.setattr(cli, "resolve", lambda repo, ref: Revision(repo, ref, "a" * 40, branch=ref))
    monkeypatch.setattr(cli, "checkout", fake_checkout)
    monkeypatch.setattr(renovate, "run", fake_run)
    monkeypatch.setattr(renovate, "validate", lambda text: [])
    monkeypatch.setattr(coverage, "gaps", lambda path, report: [])
    monkeypatch.setattr(native, "dotnet_updates", lambda path: [])
    monkeypatch.setattr(native, "go_updates", lambda path: [])
    monkeypatch.setattr(osv, "lock_files", lambda path: [])
    monkeypatch.setattr(osv, "run", lambda path, files: {"results": []})
    monkeypatch.setattr(govulncheck, "scan", lambda path: [])
    # Without a token the alerts aren't requested, so the scan stays offline.
    monkeypatch.delenv("SDLC_GITHUB_TOKEN", raising=False)
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


def test_scan_without_govulncheck_reports_a_gap_and_carries_on(offline_scan, monkeypatch, capsys):
    from sdlc import govulncheck

    failed = govulncheck.Run("proxy/go.mod", "go1.25.14", None, "toolchain download failed")
    monkeypatch.setattr(govulncheck, "scan", lambda path: [failed])
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    captured = capsys.readouterr()
    assert "gap: govulncheck: proxy/go.mod: govulncheck didn't run" in captured.out
    assert "toolchain download failed" in captured.out
    assert "reachability: 0 reachable, 0 not reachable, 0 unknown" in captured.out
    assert "no record written" in captured.err


def test_scan_without_a_token_lists_the_alerts_as_unavailable(offline_scan, capsys):
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    captured = capsys.readouterr()
    assert "gap: dependabot-alerts: No token in SDLC_GITHUB_TOKEN" in captured.out
    assert "Dependabot alerts: unavailable (see its gap), so nothing is known from them" in (
        captured.out
    )
    assert "no record written" in captured.err


@pytest.mark.parametrize(
    ("head", "about"),
    [
        (
            "b" * 40,
            "main at bbbbbbb, NOT the scanned commit aaaaaaa: a difference may be the "
            "branch's, not the scan's",
        ),
        ("a" * 40, "main at aaaaaaa, the scanned commit"),
    ],
)
def test_scan_compares_the_alerts_and_says_which_commit_they_describe(
    offline_scan, monkeypatch, capsys, head, about
):
    from sdlc import dependabot, osv

    package = {"ecosystem": "nuget", "name": "Microsoft.Extensions.Http"}

    def alert(number, ghsa, fixed):
        return {
            "number": number,
            "dependency": {"package": package, "manifest_path": "Directory.Packages.props"},
            "security_advisory": {"ghsa_id": ghsa, "cve_id": None, "identifiers": []},
            "security_vulnerability": {
                "vulnerable_version_range": "< 10.0.13",
                "first_patched_version": {"identifier": fixed},
            },
        }

    def read(repository, token):
        assert token == "a-token"  # noqa: S105 - the fake set below
        return dependabot.Alerts(
            "main",
            head,
            "2026-10-09T09:00:00+00:00",
            [alert(7, "GHSA-1", "10.0.13"), alert(8, "GHSA-2", None)],
        )

    vulnerable = {
        "package": {
            "ecosystem": "NuGet",
            "name": "Microsoft.Extensions.Http",
            "version": "10.0.12",
        },
        "vulnerabilities": [
            {
                "id": "GHSA-1",
                "affected": [
                    {
                        "package": {"ecosystem": "NuGet", "name": "Microsoft.Extensions.Http"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "10.0.13"}],
                            }
                        ],
                    }
                ],
            }
        ],
    }
    output = {
        "results": [{"source": {"path": "/src/x/packages.lock.json"}, "packages": [vulnerable]}]
    }
    monkeypatch.setenv("SDLC_GITHUB_TOKEN", "a-token")
    monkeypatch.setattr(dependabot, "read", read)
    monkeypatch.setattr(osv, "lock_files", lambda path: ["x/packages.lock.json"])
    monkeypatch.setattr(osv, "run", lambda path, files: output)
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    out = capsys.readouterr().out
    assert "GHSA-1 (osv, unknown, Dependabot alert #7): fixed in 10.0.13" in out
    assert (
        f"Dependabot alerts: 2 open on {about} (read at 2026-10-09T09:00:00+00:00); "
        "1 match the scan's advisories in the same file, 0 only in another file, 1 don't; "
        "0 of the scan's 1 advisories have no open alert"
    ) in out
    assert (
        "unmatched alert #8: GHSA-2 on Microsoft.Extensions.Http (Directory.Packages.props), "
        "no fixed version"
    ) in out
    assert "gap: dependabot-alerts" not in out


def test_a_lookup_failing_in_one_run_makes_it_unknown_and_the_scan_carries_on(
    offline_scan, monkeypatch, tmp_path, capsys
):
    from sdlc import renovate

    def fake_run(path, *, policy=None, token=None):
        dep = {
            "depName": "Microsoft.Extensions.Http",
            "packageName": "Microsoft.Extensions.Http",
            "datasource": "nuget",
            "currentValue": "10.0.12",
            "updates": [{"updateType": "patch", "newValue": "10.0.13"}],
        }
        if "Runtime majors wait" in (policy or ""):  # the run with the policy's holds
            dep |= {"updates": [], "warnings": [{"message": "Failed to look up: no-result"}]}
        files = {"nuget": [{"packageFile": "Directory.Packages.props", "deps": [dep]}]}
        return {"repositories": {"local": {"packageFiles": files}}}

    monkeypatch.setattr(renovate, "run", fake_run)
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text(
        '{packageRules: [{description: "Runtime majors wait", '
        'matchPackageNames: ["Microsoft.Extensions.*"], matchUpdateTypes: ["major"], '
        "enabled: false}]}"
    )
    assert main(["scan", "--repo", "alanta/demo", "--trial-policy", str(trial)]) == 1
    captured = capsys.readouterr()
    assert "1 dependencies (1 unknown), 0 update candidates" in captured.out
    assert "the scan stops here for now; no record written" in captured.err
    assert "can't be classified; no record written" not in captured.err


def test_scan_prints_an_inconsistent_go_toolchain(offline_scan, monkeypatch, tmp_path, capsys):
    from sdlc import renovate

    def fake_run(path, *, policy=None, token=None):
        (path / "go.mod").write_text("module example.com/m\n\ngo 1.25.14\n")
        files = {
            "gomod": [
                {
                    "packageFile": "go.mod",
                    "deps": [
                        {
                            "depName": "go",
                            "datasource": "golang-version",
                            "depType": "golang",
                            "currentValue": "1.25.14",
                        }
                    ],
                }
            ],
            "dockerfile": [
                {
                    "packageFile": "Dockerfile",
                    "deps": [
                        {
                            "depName": "golang",
                            "datasource": "docker",
                            "currentValue": "1.27-alpine",
                        }
                    ],
                }
            ],
        }
        return {"repositories": {"local": {"packageFiles": files}}}

    monkeypatch.setattr(renovate, "run", fake_run)
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    captured = capsys.readouterr()
    assert "consistency: 1 of 3 logical dependencies declared inconsistently" in captured.out
    assert "  inconsistent: Go toolchain\n" in captured.out
    assert "    Dockerfile: golang 1.27-alpine declares 1.27\n" in captured.out
    assert "    go.mod:3: go 1.25.14 declares 1.25.14\n" in captured.out
    assert "the scan stops here for now; no record written" in captured.err


def lifecycle_scan(monkeypatch, answer):
    """A scan of a go.mod on Go 1.25.14, with endoflife.date answered by `answer`."""
    from sdlc import lifecycle, renovate

    dep = {
        "depName": "go",
        "datasource": "golang-version",
        "depType": "golang",
        "currentValue": "1.25.14",
    }
    report = {
        "repositories": {
            "local": {"packageFiles": {"gomod": [{"packageFile": "go.mod", "deps": [dep]}]}}
        }
    }
    monkeypatch.setattr(renovate, "run", lambda path, *, policy=None, token=None: report)
    monkeypatch.setattr(lifecycle._OPENER, "open", answer)
    return main(["scan", "--repo", "alanta/demo"])


def test_scan_prints_the_lines_past_their_end_of_life(offline_scan, monkeypatch, capsys):
    from pathlib import Path

    go = Path(__file__).parents[1] / "fixtures" / "endoflife" / "go.json"

    class Answer:
        status = 200

        def read(self):
            return go.read_bytes()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    assert lifecycle_scan(monkeypatch, lambda request, timeout: Answer()) == 1
    captured = capsys.readouterr()
    assert "lifecycle (https://endoflife.date/api/v1: go, fetched at " in captured.out
    assert "1 end of life, 0 nearing end of life" in captured.out
    assert "end of life: go 1.25: ended 2026-08-19; supported: 1.26, 1.27 (go.mod)" in (
        captured.out
    )
    assert "no record written" in captured.err


def test_scan_with_endoflife_date_unreachable_reports_unknown(offline_scan, monkeypatch, capsys):
    import urllib.error

    def unreachable(request, timeout):
        raise urllib.error.URLError("Name or service not known")

    assert lifecycle_scan(monkeypatch, unreachable) == 1
    out = capsys.readouterr().out
    reason = "endoflife.date couldn't be reached: Name or service not known."
    assert f"gap: endoflife.date: {reason}" in out
    assert f"unknown: go 1.25: {reason} (go.mod)" in out
    assert "lifecycle (nothing read from endoflife.date)" in out


def test_scan_without_a_token_says_nothing_is_known_about_dependabot_s_prs(offline_scan, capsys):
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    out = capsys.readouterr().out
    assert "gap: dependabot-prs: No token in SDLC_GITHUB_TOKEN" in out
    assert "Dependabot PRs: unavailable (see its gap), so nothing is known about them" in out
    assert "scan only: unknown, without Dependabot's PRs" in out


def test_scan_compares_dependabot_s_updates_and_lists_unparseable_prs(
    offline_scan, monkeypatch, capsys, tmp_path
):
    import json
    from pathlib import Path

    from sdlc import dependabot_prs, renovate

    prs = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy" / "prs"

    def parsed(n, with_diff=True):
        files = json.loads((prs / str(n) / "files.json").read_text())
        return dependabot_prs.parse(
            json.loads((prs / str(n) / "pr.json").read_text()),
            json.loads((prs / str(n) / "commits.json").read_text()),
            (lambda: files) if with_diff else None,
        )

    def report(path, *, policy=None, token=None):
        python = {
            "depName": "python",
            "datasource": "docker",
            "currentValue": "3.12-alpine",
            "updates": [{"updateType": "minor", "newValue": "3.14-alpine"}],
        }
        http = {
            "depName": "Microsoft.Extensions.Http",
            "datasource": "nuget",
            "currentValue": "10.0.12",
            "updates": [{"updateType": "patch", "newValue": "10.0.13"}],
        }
        files = {
            "dockerfile": [{"packageFile": "mock-idp/Dockerfile", "deps": [python]}],
            "nuget": [{"packageFile": "Directory.Packages.props", "deps": [http]}],
        }
        return {"repositories": {"local": {"packageFiles": files}}}

    # AppHost's lock file resolves the declared 10.0.12 by now, not #77's 10.0.11.
    lock = tmp_path / "checkout" / "src" / "AppHost" / "packages.lock.json"
    lock.parent.mkdir(parents=True)
    resolved = {"Microsoft.Extensions.Http": {"type": "Transitive", "resolved": "10.0.12"}}
    lock.write_text(json.dumps({"version": 1, "dependencies": {"net10.0": resolved}}))
    found = [parsed(76), parsed(77), parsed(99, with_diff=False)]
    monkeypatch.setattr(renovate, "run", report)
    monkeypatch.setattr(
        dependabot_prs,
        "read",
        lambda repository, token: dependabot_prs.PullRequests("2026-10-09T09:00:00+00:00", found),
    )
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    out, err = capsys.readouterr()
    assert (
        "Dependabot PRs: 3 open (read at 2026-10-09T09:00:00+00:00); 2 parsed, proposing 3 "
        "updates; 1 unparseable, so the comparison with them is incomplete"
    ) in out
    assert "): 1 matched, 0 held by policy, 1 missed, 1 stale; incomplete\n" in out
    assert "  #76 at deddfe4 on main, current: docker: bump the docker-minor-patch group" in out
    assert (
        "    matched: python 3.12-alpine -> 3.14-alpine (minor, derived) docker /mock-idp "
        "group docker-minor-patch: scan has 3.14-alpine\n"
    ) in out
    assert (
        "    missed: library/golang 1.25-alpine -> 1.27-alpine (minor, derived) docker /proxy "
        "group docker-minor-patch: library/golang is not in the inventory in proxy/Dockerfile\n"
    ) in out
    assert "  #77 at cc93b67 on main, stale: nuget: Bump Microsoft.Extensions.Http" in out
    assert (
        "    stale: Microsoft.Extensions.Http 10.0.11 -> 10.0.12 (patch) nuget group microsoft: "
        "src/AppHost/packages.lock.json has 10.0.12, not 10.0.11\n"
    ) in out
    assert "  unparseable #99 at 7aea495: its diff wasn't read\n" in out
    assert "  incomplete: #99 is unparseable: its diff wasn't read\n" in out
    # #77 changes only the lock file, so the central 10.0.13 is the scan's alone; the
    # Dockerfile's python is matched.
    assert "scan only: 1 entry with in-scope candidates" in out
    assert "  nuget: 1 entry: Microsoft.Extensions.Http\n" in out
    assert "no record written" in err


def test_scan_lists_what_only_the_scan_proposes(offline_scan, monkeypatch, capsys):
    from sdlc import dependabot_prs

    monkeypatch.setattr(
        dependabot_prs,
        "read",
        lambda repository, token: dependabot_prs.PullRequests("2026-10-09T09:00:00+00:00", []),
    )
    main(["scan", "--repo", "alanta/demo"])
    out = capsys.readouterr().out
    assert "Dependabot PRs: 0 open (read at 2026-10-09T09:00:00+00:00)" in out
    assert "): 0 matched, 0 held by policy, 0 missed, 0 stale\n" in out
    assert "scan only: 1 entry with in-scope candidates that no open Dependabot PR proposes" in out
    assert "  nuget: 1 entry: Microsoft.Extensions.Http\n" in out
