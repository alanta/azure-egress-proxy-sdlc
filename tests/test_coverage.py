import subprocess

import pytest
from jsonschema import Draft202012Validator

from sdlc.coverage import gaps
from sdlc.record import schema

FILES = {
    "image/egress-proxy.pkr.hcl": 'packer { required_plugins { azure = { version = "2.3.0" } } }',
    "infra/assets/cloud-init.yaml": "packages:\n  - curl\n",
    "src/Portal/Portal.csproj": "<Project />\n",
    "src/Portal/packages.lock.json": '{"version": 1, "dependencies": {',
    "src/SampleApp/SampleApp.csproj": "<Project />\n",
    "src/SampleApp/packages.lock.json": '{"version": 1, "dependencies": {}}',
    "proxy/go.mod": "module x\n",
    "proxy/go.sum": "golang.org/x/net v0.1.0 h1:abc=\ngarbage\n",
    "mock-idp/Dockerfile": (
        "FROM python:3.12-alpine\n"
        'RUN pip install --no-cache-dir "PyJWT[crypto]==2.15.0"\n'
        "RUN pip install requests\n"
    ),
    ".github/workflows/ci.yml": (
        "steps:\n  - run: go install golang.org/x/vuln/cmd/govulncheck@latest\n"
    ),
}

REPORT = {
    "repositories": {
        "local": {
            "packageFiles": {
                "nuget": [
                    {
                        "packageFile": "src/Portal/Portal.csproj",
                        "lockFiles": ["src/Portal/packages.lock.json"],
                        "deps": [],
                    }
                ],
                "dockerfile": [{"packageFile": "mock-idp/Dockerfile", "deps": []}],
                "gomod": [{"packageFile": "proxy/go.mod", "deps": []}],
                "github-actions": [{"packageFile": ".github/workflows/ci.yml", "deps": []}],
            },
            "problems": [],
        }
    }
}


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def checkout(tmp_path):
    for name, text in FILES.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git(tmp_path, "init", "--quiet")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "--quiet", "-m", "fixture")
    return tmp_path


@pytest.fixture
def found(checkout):
    return {(g["kind"], g["subject"]): g["reason"] for g in gaps(checkout, REPORT)}


def test_file_types_without_an_adapter_are_unsupported(found):
    assert "Packer template" in found[("unsupported_source", "image/egress-proxy.pkr.hcl")]
    assert "cloud-init" in found[("unsupported_source", "infra/assets/cloud-init.yaml")]


def test_malformed_lock_files_are_unparseable_even_though_renovate_is_silent(found):
    assert "Not valid JSON" in found[("unparseable_source", "src/Portal/packages.lock.json")]
    assert "Line 2" in found[("unparseable_source", "proxy/go.sum")]


def test_a_project_renovate_reports_nothing_for_is_not_a_gap(found):
    assert not [key for key in found if key[1].startswith("src/SampleApp/")]


def test_unpinned_installs_are_reported_by_line_and_pinned_ones_are_not(found):
    unpinned = found[("unsupported_source", "mock-idp/Dockerfile:3")]
    assert "pip install without a pinned version" in unpinned
    assert ("unsupported_source", "mock-idp/Dockerfile:2") not in found
    assert "go install @latest" in found[("unsupported_source", ".github/workflows/ci.yml:2")]


def test_renovate_problems_become_unparseable_sources(checkout):
    problem = {"level": 40, "message": "Parse error", "file": "x.json"}
    report = {"repositories": {"local": {"packageFiles": {}, "problems": [problem]}}}
    expected = {"kind": "unparseable_source", "subject": "x.json", "reason": "Parse error"}
    assert expected in gaps(checkout, report)


def test_found_gaps_fit_the_record_schema(checkout):
    gap_schema = {**schema()["$defs"]["gap"], "$defs": schema()["$defs"]}
    for gap in gaps(checkout, REPORT):
        Draft202012Validator(gap_schema).validate(gap)
