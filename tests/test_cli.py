import json
import subprocess
from pathlib import Path

import pytest

from sdlc.cli import main
from sdlc.coverage import gaps as coverage_gaps
from sdlc.record import validate_record
from sdlc.report import text


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

    from sdlc import cli, coverage, govulncheck, lifecycle, native, osv, renovate
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
    # The fake checkout isn't a git repository, and coverage lists the files git tracks.
    monkeypatch.setattr(coverage, "gaps", lambda path, report: [])
    monkeypatch.setattr(native, "dotnet_updates", lambda path: [])
    monkeypatch.setattr(native, "go_updates", lambda path: [])
    monkeypatch.setattr(osv, "lock_files", lambda path: [])
    monkeypatch.setattr(osv, "run", lambda path, files: {"results": []})
    monkeypatch.setattr(govulncheck, "scan", lambda path: [])
    # Without a token the alerts aren't requested, so the scan stays offline.
    monkeypatch.delenv("SDLC_GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(lifecycle._OPENER, "open", endoflife)
    # The outputs go to the default runs/, here.
    monkeypatch.chdir(tmp_path)
    return runs


FIXTURES = Path(__file__).parents[1] / "fixtures"


class _Answer:
    status = 200

    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def checked_out(root, *files):
    """Empty files in the fake checkout: what a parity comparison needs to know they exist."""
    for file in files:
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()


def endoflife(request, timeout):
    """endoflife.date as captured, so no scan in these tests reaches it."""
    product = request.full_url.rsplit("/", 1)[1]
    return _Answer((FIXTURES / "endoflife" / f"{product}.json").read_bytes())


def written(tmp_path):
    """The record and report of the one scan written to the default run directory."""
    [directory] = (tmp_path / "runs").glob("*/*/*/*")
    assert directory.relative_to(tmp_path / "runs").parts[:3] == ("alanta", "demo", "a" * 40)
    record = json.loads((directory / "record.json").read_text())
    assert validate_record(record) == []
    return record, (directory / "report.md").read_text()


def test_scan_names_the_trial_policy_and_what_it_holds(offline_scan, tmp_path, capsys):
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text(
        '{packageRules: [{description: "Runtime majors wait", '
        'matchPackageNames: ["Microsoft.Extensions.*"], matchUpdateTypes: ["major"], '
        "enabled: false}]}"
    )
    assert main(["scan", "--repo", "alanta/demo", "--trial-policy", str(trial)]) == 0
    out = capsys.readouterr().out
    assert f"policy: trial file {trial}" in out
    assert "2 update candidates (1 in scope, 1 held by policy)" in out
    record, report = written(tmp_path)
    assert record["policy"] == {"source": "trial", "path": str(trial)}
    assert [c for c in record["candidates"] if c["classification"] == "held_by_policy"] == [
        {
            "dependency": "nuget:Directory.Packages.props:Microsoft.Extensions.Http",
            "update_type": "major",
            "version": "11.0.1",
            "classification": "held_by_policy",
            "held_by": "Runtime majors wait",
        }
    ]
    assert f"| Update policy | trial file {text(str(trial))}, supplied for this scan |" in report
    assert (
        "| Microsoft.Extensions.Http | Directory.Packages.props | 10.0.12 | major | 11.0.1 | "
        "Runtime majors wait |"
    ) in report
    # With and without the hold.
    assert len(offline_scan) == 2


def test_scan_without_a_policy_says_so(offline_scan, tmp_path, capsys):
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    out = capsys.readouterr().out
    assert "policy: none found, so every candidate is in scope" in out
    assert "2 update candidates (2 in scope, 0 held by policy)" in out
    record, report = written(tmp_path)
    assert record["policy"] == {"source": "none"}
    assert "| Update policy | none found, so every candidate is in scope |" in report
    assert offline_scan == [None]


def test_scan_with_an_invalid_policy_fails_before_renovate_runs(offline_scan, tmp_path, capsys):
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text('{packageRules: [{matchPackageNames: ["x"], enabled: false}]}')
    assert main(["scan", "--repo", "alanta/demo", "--trial-policy", str(trial)]) == 1
    err = capsys.readouterr().err
    assert "has no description to name it by; no record written" in err
    assert offline_scan == []
    assert not (tmp_path / "runs").exists()


def test_scan_without_osv_scanner_reports_vulnerabilities_as_unknown(
    offline_scan, monkeypatch, tmp_path, capsys
):
    from sdlc import osv

    def broken(path, files):
        raise osv.OsvError("OSV-Scanner failed (127): could not reach api.osv.dev")

    monkeypatch.setattr(osv, "run", broken)
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    assert "vulnerabilities: unknown, OSV-Scanner didn't run" in capsys.readouterr().out
    record, report = written(tmp_path)
    reason = "OSV-Scanner failed (127): could not reach api.osv.dev"
    assert {"kind": "unavailable_source", "subject": "osv-scanner", "reason": reason} in (
        record["gaps"]
    )
    assert f"## Vulnerabilities\n\n**Unknown.** OSV-Scanner didn't run: {reason}" in report
    assert "- **Reachable vulnerabilities:** unknown, OSV-Scanner didn't run" in report
    assert "vulnerabilities unknown" in report
    assert "0 advisories" not in report


def test_a_malformed_lock_file_is_unparseable_and_the_scan_carries_on(
    offline_scan, monkeypatch, tmp_path, capsys
):
    from sdlc import coverage

    checkout = tmp_path / "checkout"
    lock = checkout / "src" / "A" / "packages.lock.json"
    lock.parent.mkdir(parents=True)
    malformed = '{"version": 1, "dependencies": {'
    lock.write_text(malformed)
    # A git repository, so the real coverage check can list the files the checkout tracks.
    subprocess.run(["git", "init", "--quiet"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    monkeypatch.setattr(coverage, "gaps", coverage_gaps)

    assert main(["scan", "--repo", "alanta/demo"]) == 0
    assert "2 update candidates (2 in scope, 0 held by policy)" in capsys.readouterr().out
    record, report = written(tmp_path)
    with pytest.raises(json.JSONDecodeError) as error:
        json.loads(malformed)
    reason = f"Not valid JSON: {error.value}."
    assert {
        "kind": "unparseable_source",
        "subject": "src/A/packages.lock.json",
        "reason": reason,
    } in record["gaps"]
    assert f"| unparseable source | src/A/packages.lock.json | {text(reason)} |" in report
    # The rest of the scan went on: Renovate's entry, its candidates and the other sections.
    assert [d["name"] for d in record["inventory"]] == ["Microsoft.Extensions.Http"]
    assert len(record["candidates"]) == 2
    assert all(heading in report for heading in ("## Vulnerabilities", "## Parity with Dependabot"))


def test_scan_without_govulncheck_reports_a_gap_and_carries_on(offline_scan, monkeypatch, tmp_path):
    from sdlc import govulncheck

    failed = govulncheck.Run("proxy/go.mod", "go1.25.14", None, "toolchain download failed")
    monkeypatch.setattr(govulncheck, "scan", lambda path: [failed])
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    record, report = written(tmp_path)
    [gap] = [g for g in record["gaps"] if g["subject"] == "govulncheck: proxy/go.mod"]
    assert gap["reason"].endswith("toolchain download failed")
    assert "| unavailable source | govulncheck: proxy/go.mod | govulncheck didn't run" in report
    assert "Reachability, from govulncheck for Go: 0 reachable, 0 unknown, 0 not reachable." in (
        report
    )


def test_scan_without_a_token_lists_the_alerts_as_unavailable(offline_scan, tmp_path):
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    record, report = written(tmp_path)
    assert "dependabot_alerts" not in record
    [gap] = [g for g in record["gaps"] if g["subject"] == "dependabot-alerts"]
    assert gap["reason"].startswith("No token in SDLC_GITHUB_TOKEN")
    assert (
        f"### Dependabot alerts\n\n**Unavailable:** {text(gap['reason'])} Nothing is known"
    ) in report


@pytest.mark.parametrize(
    ("head", "about"),
    [
        (
            "b" * 40,
            "Read at 2026-10-09T09:00:00+00:00. They describe the default branch as Dependabot "
            "last analysed it: main at bbbbbbb, **not** the scanned commit aaaaaaa: a "
            "difference between them and the scan may be the branch's, not a miss of the scan.",
        ),
        (
            "a" * 40,
            "Read at 2026-10-09T09:00:00+00:00. They describe the default branch as Dependabot "
            "last analysed it: main at aaaaaaa, the scanned commit.",
        ),
    ],
)
def test_scan_compares_the_alerts_and_says_which_commit_they_describe(
    offline_scan, monkeypatch, tmp_path, head, about
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
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    record, report = written(tmp_path)
    assert [v["dependabot_alerts"] for v in record["vulnerabilities"]] == [[7]]
    assert (
        "| GHSA-1 | Microsoft.Extensions.Http 10.0.12 | Directory.Packages.props | unknown | "
        "fixed in 10.0.13 | yes | osv | #7 |"
    ) in report
    assert about in report
    assert (
        "2 open alerts: 1 match the scan's advisories in the same file, 0 only in another "
        "file, 1 don't. 0 of the scan's 1 advisory have no open alert."
    ) in report
    assert (
        "| #8 | GHSA-2 | Microsoft.Extensions.Http | Directory.Packages.props | "
        "no fixed version | unmatched |"
    ) in report
    assert all(g["subject"] != "dependabot-alerts" for g in record["gaps"])


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
    assert main(["scan", "--repo", "alanta/demo", "--trial-policy", str(trial)]) == 0
    captured = capsys.readouterr()
    assert "1 dependencies (1 unknown), 0 update candidates" in captured.out
    assert "can't be classified; no record written" not in captured.err
    record, report = written(tmp_path)
    assert record["inventory"][0]["lookup"]["state"] == "unknown"
    assert "| unknown | Microsoft.Extensions.Http | Directory.Packages.props | 10.0.12 |" in report
    assert "  - 1 lookup failed, listed under Not looked up\n" in report


def test_scan_reports_an_inconsistent_go_toolchain(offline_scan, monkeypatch, tmp_path, capsys):
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
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    assert "inconsistent declarations: 1" in capsys.readouterr().out
    record, report = written(tmp_path)
    assert [i["dependency"] for i in record["inconsistencies"]] == ["Go toolchain"]
    assert "- **Inconsistent declarations:** 1 of 3 logical dependencies: Go toolchain\n" in report
    assert "| Dockerfile | golang 1.27-alpine | 1.27 |\n" in report
    assert "| go.mod:3 | go 1.25.14 | 1.25.14 |\n" in report
    assert (
        "| Go toolchain | inconsistent | golang 1.27-alpine (Dockerfile), go 1.25.14 (go.mod:3)"
        in (report)
    )


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


def test_scan_reports_the_lines_past_their_end_of_life(offline_scan, monkeypatch, tmp_path):
    assert lifecycle_scan(monkeypatch, endoflife) == 0
    record, report = written(tmp_path)
    assert [t["url"] for t in record["tools"] if t["name"] == "endoflife.date"] == [
        "https://endoflife.date/api/v1/products/go"
    ]
    assert "From endoflife.date, read at " in report
    assert (
        "- **End of life:** 1 line in use:\n"
        "  - go 1.25: ended 2026-08-19; still supported: 1.26, 1.27 (go.mod)\n"
    ) in report
    assert "| end of life | go | 1.25 | 2026-08-19 | 1.26, 1.27 | go.mod |" in report


def test_scan_with_endoflife_date_unreachable_reports_unknown(offline_scan, monkeypatch, tmp_path):
    import urllib.error

    def unreachable(request, timeout):
        raise urllib.error.URLError("Name or service not known")

    assert lifecycle_scan(monkeypatch, unreachable) == 0
    record, report = written(tmp_path)
    reason = "endoflife.date couldn't be reached: Name or service not known."
    assert {"kind": "unavailable_source", "subject": "endoflife.date", "reason": reason} in (
        record["gaps"]
    )
    assert "Nothing was read from endoflife.date." in report
    assert f"| unknown | go | 1.25 | unknown: {reason} |  | go.mod |" in report
    assert "- **End of life:** none found, but 1 line is unknown\n" in report


def test_scan_without_a_token_says_nothing_is_known_about_dependabot_s_prs(
    offline_scan, tmp_path, capsys
):
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    assert "parity with Dependabot: unknown, its PRs weren't read" in capsys.readouterr().out
    record, report = written(tmp_path)
    [gap] = [g for g in record["gaps"] if g["subject"] == "dependabot-prs"]
    assert gap["reason"].startswith("No token in SDLC_GITHUB_TOKEN")
    assert (
        f"## Parity with Dependabot\n\n**Unknown.** Dependabot's open PRs couldn't be read: "
        f"{text(gap['reason'])} Nothing is compared, and nothing is listed as scan-only."
    ) in report
    assert "- **Missed Dependabot updates:** unknown, Dependabot's PRs weren't read" in report
    assert "### Scan only" not in report


def test_scan_compares_dependabot_s_updates_and_lists_unparseable_prs(
    offline_scan, monkeypatch, capsys, tmp_path
):
    from sdlc import dependabot_prs, renovate

    prs = FIXTURES / "azure-egress-proxy" / "prs"

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

    # The checkout has the files the PRs change, as the revision they were made for does.
    checked_out(tmp_path / "checkout", "mock-idp/Dockerfile", "proxy/Dockerfile")
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
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    assert (
        "parity with Dependabot: 1 matched, 0 held by policy, 1 missed, 1 stale, 1 scan only; "
        "incomplete"
    ) in capsys.readouterr().out
    record, report = written(tmp_path)
    assert [pr["state"] for pr in record["parity"]["pull_requests"]] == [
        "current",
        "stale",
        "unparseable",
    ]
    assert (
        "3 open Dependabot PRs, read at 2026-10-09T09:00:00+00:00; the scan's lookups ran at "
    ) in report
    assert "3 proposed updates: 1 missed, 1 stale, 0 held by policy, 1 matched." in report
    assert (
        "**The comparison is incomplete:**\n- #99 is unparseable: its diff wasn't read\n"
    ) in report
    assert (
        "### #76: docker: bump the docker-minor-patch group across 2 directories with 2 updates"
        "\n\nAt deddfe4 on main, **current**.\n"
    ) in report
    assert (
        "| matched | python | 3.12-alpine | 3.14-alpine | minor, derived | docker /mock-idp "
        "group docker-minor-patch | scan has 3.14-alpine |"
    ) in report
    assert (
        "| missed | library/golang | 1.25-alpine | 1.27-alpine | minor, derived | docker /proxy "
        "group docker-minor-patch | library/golang is not in the inventory in proxy/Dockerfile |"
    ) in report
    assert "- **Missed Dependabot updates:** 1 (the comparison is incomplete):\n" in report
    assert "At cc93b67 on main, **stale**: the revision no longer has what it updates" in report
    assert (
        "| stale | Microsoft.Extensions.Http | 10.0.11 | 10.0.12 | patch | nuget group microsoft "
        "| src/AppHost/packages.lock.json has 10.0.12, not 10.0.11 |"
    ) in report
    assert "At 7aea495 on main, **unparseable**: its diff wasn't read\n" in report
    # #77 changes only the lock file, so the central 10.0.13 is the scan's alone; the
    # Dockerfile's python is matched.
    assert "1 entry with in-scope candidates that no open Dependabot PR proposes." in report
    assert (
        "| nuget | Microsoft.Extensions.Http | Directory.Packages.props | 10.0.12 | 10.0.13 |"
    ) in report


def test_scan_lists_what_only_the_scan_proposes(offline_scan, monkeypatch, tmp_path, capsys):
    from sdlc import dependabot_prs

    monkeypatch.setattr(
        dependabot_prs,
        "read",
        lambda repository, token: dependabot_prs.PullRequests("2026-10-09T09:00:00+00:00", []),
    )
    assert main(["scan", "--repo", "alanta/demo"]) == 0
    assert (
        "parity with Dependabot: 0 matched, 0 held by policy, 0 missed, 0 stale, 1 scan only\n"
    ) in capsys.readouterr().out
    record, report = written(tmp_path)
    assert record["parity"]["scan_only"] == [
        "nuget:Directory.Packages.props:Microsoft.Extensions.Http"
    ]
    assert "0 open Dependabot PRs, read at 2026-10-09T09:00:00+00:00" in report
    assert "0 proposed updates: 0 missed, 0 stale, 0 held by policy, 0 matched." in report
    assert "- **Missed Dependabot updates:** none\n" in report
    assert "1 entry with in-scope candidates that no open Dependabot PR proposes." in report
    assert (
        "| nuget | Microsoft.Extensions.Http | Directory.Packages.props | 10.0.12 | "
        "10.0.13, 11.0.1 |"
    ) in report


def test_a_record_failing_its_schema_fails_the_scan_without_a_report(
    offline_scan, monkeypatch, tmp_path, capsys
):
    from sdlc import native

    # A cross-check from a tool the schema doesn't know.
    disagreement = {
        "source": "maven",
        "name": "x",
        "location": "pom.xml",
        "current": "1",
        "native_latest": "2",
        "scan_candidates": [],
    }
    monkeypatch.setattr(native, "cross_check", lambda *args: [disagreement])
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    out, err = capsys.readouterr()
    assert "error: the record fails its schema, so no report was written:" in err
    assert "$.cross_checks[0].source: 'maven' is not one of ['dotnet', 'go']" in err
    assert "the invalid record is kept as runs/alanta/demo/" in err
    assert "report:" not in out
    assert not list(tmp_path.rglob("report.md"))
    assert not list(tmp_path.rglob("record.json"))
    [kept] = tmp_path.rglob("*.invalid.json")
    # Beside where the run directory would be, never in one.
    assert kept.parent.name == "a" * 40
    assert not [p for p in kept.parent.iterdir() if p.is_dir()]
    assert json.loads(kept.read_text())["cross_checks"] == [disagreement]


def test_an_offline_scan_of_064aa09_writes_a_record_and_a_report_from_it(
    offline_scan, monkeypatch, tmp_path, capsys
):
    """The whole scan on the evidence captured at 064aa09, with its tools and APIs faked."""
    import gzip

    from sdlc import cli, dependabot, dependabot_prs, govulncheck, native, osv, renovate
    from sdlc.subject import Revision

    evidence = FIXTURES / "azure-egress-proxy"
    commit = "064aa099ecf7ffea9664b89df29f7d89d6859358"

    def read(*path):
        return (evidence.joinpath(*path)).read_text()

    report = json.loads(read("renovate", "064aa09", "report-with-scan-config.json"))
    scanned = json.loads(read("osv", "064aa09", "osv-scanner.json"))
    with gzip.open(evidence / "govulncheck" / "064aa09" / "govulncheck.json.gz") as f:
        run = govulncheck.Run(
            "proxy/go.mod", "go1.25.14", govulncheck.parse(f.read().decode(), "go1.25.14")
        )

    def pull(number):
        def part(name):
            return json.loads(read("prs", str(number), name))

        # 064aa09 has every file the PRs open then change.
        checked_out(tmp_path / "checkout", *(f["filename"] for f in part("files.json")))

        return dependabot_prs.parse(
            part("pr.json"), part("commits.json"), lambda: part("files.json")
        )

    monkeypatch.setenv("SDLC_GITHUB_TOKEN", "a-token")
    monkeypatch.setattr(cli, "resolve", lambda repo, ref: Revision(repo, ref, commit, branch=ref))
    monkeypatch.setattr(renovate, "run", lambda path, *, policy=None, token=None: report)
    monkeypatch.setattr(
        native,
        "dotnet_updates",
        lambda path: native.parse_dotnet(
            json.loads(read("native", "064aa09", "dotnet-list-package.json")), Path("/src")
        ),
    )
    monkeypatch.setattr(
        native,
        "go_updates",
        lambda path: native.parse_go(read("native", "064aa09", "go-list-m-u.json"), "proxy/go.mod"),
    )
    monkeypatch.setattr(
        osv,
        "lock_files",
        lambda path: [r["source"]["path"].removeprefix("/src/") for r in scanned["results"]],
    )
    monkeypatch.setattr(osv, "run", lambda path, files: scanned)
    monkeypatch.setattr(govulncheck, "scan", lambda path: [run])
    alerts = json.loads(read("dependabot-alerts", "open.json"))
    monkeypatch.setattr(
        dependabot,
        "read",
        lambda repository, token: dependabot.Alerts(
            "main", "e93d7062b075352f151f8e6b5a15f60913e7bd98", "2026-10-09T09:00:00+00:00", alerts
        ),
    )
    monkeypatch.setattr(
        dependabot_prs,
        "read",
        lambda repository, token: dependabot_prs.PullRequests(
            "2026-10-07T18:42:07+00:00", [pull(n) for n in (75, 76, 77, 98, 99)]
        ),
    )

    assert main(["scan", "--repo", "alanta/azure-egress-proxy"]) == 0
    out = capsys.readouterr().out
    [directory] = (tmp_path / "runs").glob("*/*/*/*")
    assert directory.relative_to(tmp_path / "runs").parts[:3] == (
        "alanta",
        "azure-egress-proxy",
        commit,
    )
    assert f"record: runs/alanta/azure-egress-proxy/{commit}/" in out
    record = json.loads((directory / "record.json").read_text())
    assert validate_record(record) == []
    rendered = (directory / "report.md").read_text()

    # Everything the record lists shows in the report.
    for dep in record["inventory"]:
        assert f"| {text(dep['name'])} |" in rendered, dep["id"]
    for v in record["vulnerabilities"]:
        assert f"| {text(v['advisory'])}" in rendered
    for gap in record["gaps"]:
        assert f"| {text(gap['subject'])} | {text(gap['reason'])} |" in rendered
    for pr in record["parity"]["pull_requests"]:
        assert f"### #{pr['number']}: {text(pr['title'])}" in rendered

    # What a maintainer of 064aa09 needs to see first.
    summary = rendered.split("\n## Summary\n", 1)[1].split("\n## ", 1)[0]
    assert "- **End of life:**" in summary and "  - go 1.25: ended " in summary
    assert "- **Reachable vulnerabilities:**" in summary
    assert "- **Missed Dependabot updates:** none\n" in summary
    # Every update of the five PRs open then is matched, #77 by AppHost's lock drift.
    assert "11 proposed updates: 0 missed, 0 stale, 0 held by policy, 11 matched." in rendered
    assert (
        "| Microsoft.Extensions.Http | src/AppHost/packages.lock.json | 10.0.11 | patch | 10.0.12 |"
    ) in rendered
    # The alerts describe main at e93d706, not the scanned commit.
    assert "main at e93d706, **not** the scanned commit 064aa09" in rendered
    assert "| govulncheck | v1.8.0 |" in rendered
    assert "| osv-scanner | 2.6.0 |" in rendered


def test_out_chooses_where_the_run_directories_go(offline_scan, tmp_path, capsys):
    assert main(["scan", "--repo", "alanta/demo", "--out", str(tmp_path / "elsewhere")]) == 0
    [directory] = (tmp_path / "elsewhere").glob("alanta/demo/*/*")
    assert sorted(p.name for p in directory.iterdir()) == ["record.json", "report.md"]
    assert f"report: {directory / 'report.md'}" in capsys.readouterr().out
    assert not (tmp_path / "runs").exists()


def test_a_report_that_fails_to_render_keeps_the_valid_record_and_fails(
    offline_scan, monkeypatch, tmp_path, capsys
):
    from sdlc import report

    def broken(record):
        raise KeyError("a renderer bug")

    monkeypatch.setattr(report, "render", broken)
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    out, err = capsys.readouterr()
    assert "error: rendering the report failed: KeyError('a renderer bug'); no report" in err
    assert "Traceback" in err
    assert "the valid record is kept as runs/alanta/demo/" in err
    assert "report:" not in out
    assert not list(tmp_path.rglob("report.md")) and not list(tmp_path.rglob("record.json"))
    [kept] = tmp_path.rglob("*.unrendered.json")
    assert validate_record(json.loads(kept.read_text())) == []


def test_validation_problems_are_printed_even_when_the_record_cant_be_kept(
    offline_scan, monkeypatch, tmp_path, capsys
):
    from sdlc import native

    disagreement = {
        "source": "maven",
        "name": "x",
        "location": "pom.xml",
        "current": "1",
        "native_latest": "2",
        "scan_candidates": [],
    }
    monkeypatch.setattr(native, "cross_check", lambda *args: [disagreement])
    (tmp_path / "runs").write_text("a file where the runs should go")
    assert main(["scan", "--repo", "alanta/demo"]) == 1
    err = capsys.readouterr().err
    assert "$.cross_checks[0].source: 'maven' is not one of ['dotnet', 'go']" in err
    assert "the invalid record couldn't be kept either: " in err
