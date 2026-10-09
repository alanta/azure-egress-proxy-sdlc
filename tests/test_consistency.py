import copy
import json
import re
from pathlib import Path

import pytest

from sdlc import consistency
from sdlc.record import validate_record
from sdlc.renovate import normalize

FIXTURES = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy"
AT = "2026-10-09T09:00:00+00:00"
GOLANG = "dockerfile:proxy/Dockerfile:docker.io/library/golang"


@pytest.fixture(scope="module")
def report_064aa09():
    path = FIXTURES / "renovate" / "064aa09" / "report-with-scan-config.json"
    return json.loads(path.read_text())


def check(report, checkout=None):
    inventory = normalize(report, looked_up_at=AT, checkout=checkout)
    result = consistency.check(report, inventory.dependencies)
    return inventory, result


def report_of(*deps):
    """A Renovate report with these (manager, file, dependency) entries."""
    files: dict[str, dict[str, dict]] = {}
    for manager, file, dep in deps:
        files.setdefault(manager, {}).setdefault(file, {"packageFile": file, "deps": []})
        files[manager][file]["deps"].append(dep)
    package_files = {m: list(by_file.values()) for m, by_file in files.items()}
    return {"repositories": {"local": {"packageFiles": package_files}}}


def go_mod(value, dep_type="golang"):
    return (
        "gomod",
        "go.mod",
        {
            "depName": "go",
            "datasource": "golang-version",
            "depType": dep_type,
            "currentValue": value,
        },
    )


def setup_go(value, file=".github/workflows/ci.yml"):
    dep = {
        "depName": "go",
        "packageName": "actions/go-versions",
        "datasource": "github-releases",
        "depType": "uses-with",
        "currentValue": value,
    }
    return ("github-actions", file, dep)


def image(name, tag, file="Dockerfile", digest=None):
    dep = {
        "depName": name,
        "datasource": "docker",
        "currentValue": tag,
        "replaceString": f"{name}:{tag}",
    }
    if digest:
        dep["currentDigest"] = digest
    return ("dockerfile", file, dep)


def nuget(name, value, manager="nuget", file="src/AppHost/AppHost.csproj"):
    return (manager, file, {"depName": name, "datasource": "nuget", "currentValue": value})


def setup_dotnet(value, file=".github/workflows/ci.yml"):
    dep = {"depName": "dotnet-sdk", "datasource": "dotnet-version", "currentValue": value}
    return ("github-actions", file, dep)


def counts(result):
    return {alias: len(ids) for alias, ids in result.compared.items()}


def versions(result, alias):
    [found] = [i for i in result.inconsistencies if i["dependency"] == alias]
    return [d["version"] for d in found["declarations"]]


def test_064aa09_declares_everything_consistently(report_064aa09):
    _, result = check(report_064aa09)
    assert result.inconsistencies == []
    assert result.gaps == []
    # go.mod, setup-go in ci.yml and release.yml, and the proxy's build image; setup-dotnet,
    # six SDK and ASP.NET images and the devcontainer image; the AppHost SDK and the
    # devcontainer's CLI.
    assert counts(result) == {"Go toolchain": 4, ".NET": 8, "Aspire": 2}
    assert (
        "dockerfile:.devcontainer/Dockerfile:mcr.microsoft.com/devcontainers/dotnet"
        in (result.compared[".NET"])
    )


def test_pr_76_flags_the_build_image_against_go_mod_and_setup_go(report_064aa09, record_from):
    # No Renovate report was captured at PR #76's head, so its diff is applied to 064aa09's.
    diff = (FIXTURES / "prs" / "76" / "diff.patch").read_text()
    [before] = re.findall(r"^-FROM .*golang:(\S+)", diff, re.MULTILINE)
    [after] = re.findall(r"^\+FROM .*golang:(\S+)", diff, re.MULTILINE)
    assert (before, after) == ("1.25-alpine", "1.27-alpine")
    report = copy.deepcopy(report_064aa09)
    [dockerfile] = [
        f
        for f in report["repositories"]["local"]["packageFiles"]["dockerfile"]
        if f["packageFile"] == "proxy/Dockerfile"
    ]
    [golang] = [d for d in dockerfile["deps"] if d["depName"] == "docker.io/library/golang"]
    golang["currentValue"] = after
    golang["replaceString"] = golang["replaceString"].replace(before, after)

    inventory, result = check(report)

    assert [i["dependency"] for i in result.inconsistencies] == ["Go toolchain"]
    [flagged] = result.inconsistencies
    assert [(d["dependency"], d["version"]) for d in flagged["declarations"]] == [
        (GOLANG, "1.27"),
        ("github-actions:.github/workflows/ci.yml:go", "1.25"),
        ("github-actions:.github/workflows/release.yml:go", "1.25"),
        ("gomod:proxy/go.mod:go", "1.25.14"),
    ]
    record = record_from(inventory)
    record["consistency"] = [
        {"dependency": alias, "compared": ids} for alias, ids in result.compared.items()
    ]
    record["inconsistencies"] = result.inconsistencies
    assert validate_record(record) == []
    # A declaration placed in another file than its inventory entry is caught.
    record["inconsistencies"][0]["declarations"][0]["location"] = {"file": "go.mod"}
    assert validate_record(record) == [
        f"$.inconsistencies[0].declarations[0].location: not the file of {GOLANG!r}"
    ]


@pytest.mark.parametrize(
    ("a", "b", "agree"),
    [
        ("1.25", "1.25.14", True),
        ("1.25.14", "1.25", True),
        ("1.25", "1.27", False),
        ("1.25.3", "1.25.14", False),
        ("1", "1.27.2", True),
    ],
)
def test_versions_agree_at_their_common_precision(a, b, agree):
    parts = [tuple(int(p) for p in v.split(".")) for v in (a, b)]
    assert consistency.agree(*parts) is agree


@pytest.mark.parametrize(
    ("declared", "flagged"),
    [
        ("1.25", False),
        ("1.25.x", False),
        ("1.25.14", False),
        ("1.25.3", True),
        ("1.27", True),
    ],
)
def test_setup_go_against_go_mod(declared, flagged):
    _, result = check(report_of(go_mod("1.25.14"), setup_go(declared)))
    assert bool(result.inconsistencies) is flagged


@pytest.mark.parametrize(
    ("tag", "version"),
    [
        ("1.27-alpine", "1.27"),
        ("1.27.1-bookworm", "1.27.1"),
        ("1.27-alpine3.22", "1.27"),
        ("1.27", "1.27"),
    ],
)
def test_the_version_is_read_from_an_image_tag(tag, version):
    _, result = check(
        report_of(go_mod("1.25.14"), image("golang", tag, digest="sha256:" + "a" * 64))
    )
    assert versions(result, "Go toolchain") == [version, "1.25.14"]


@pytest.mark.parametrize(
    ("current", "reason"),
    [
        ("latest", "declares 'latest', which isn't one version"),
        ("alpine", "declares 'alpine', which isn't one version"),
        ("1.27rc1-alpine", "declares '1.27rc1-alpine', which isn't one version"),
    ],
)
def test_a_tag_without_a_version_is_skipped_never_agreeing(current, reason):
    _, result = check(report_of(go_mod("1.25.14"), image("golang", current)))
    assert result.inconsistencies == []
    assert counts(result)["Go toolchain"] == 1
    assert result.gaps == [
        {
            "kind": "unparseable_source",
            "subject": "Dockerfile",
            "reason": f"Go toolchain: golang {reason}, so the consistency check skips it.",
        }
    ]


def test_an_image_pinned_by_digest_only_is_skipped():
    dep = {"depName": "golang", "datasource": "docker", "currentDigest": "sha256:" + "a" * 64}
    _, result = check(report_of(go_mod("1.25.14"), ("dockerfile", "Dockerfile", dep)))
    assert counts(result)["Go toolchain"] == 1
    assert "pinned by digest only" in result.gaps[0]["reason"]


def test_a_range_in_setup_go_is_skipped():
    _, result = check(report_of(go_mod("1.25.14"), setup_go("^1.27")))
    assert result.inconsistencies == []
    assert result.gaps[0]["reason"] == (
        "Go toolchain: go declares '^1.27', which isn't one version, "
        "so the consistency check skips it."
    )


def test_the_toolchain_directive_speaks_for_its_go_mod():
    _, result = check(report_of(go_mod("1.24"), go_mod("1.25.3", "toolchain"), setup_go("1.25")))
    assert result.inconsistencies == []
    assert counts(result)["Go toolchain"] == 2

    _, result = check(report_of(go_mod("1.25"), go_mod("1.27.0", "toolchain"), setup_go("1.25")))
    assert versions(result, "Go toolchain") == ["1.25", "1.27.0"]


@pytest.mark.parametrize(
    ("sdk", "runtime", "flagged"),
    [
        ("10.0.x", "10.0-alpine", False),
        ("10.0.100", "10.0.5-noble-chiseled", False),
        ("10.0.1xx", "10.0", False),
        ("10.0.x", "11.0-alpine", True),
        ("11.0.100", "10.0", True),
    ],
)
def test_the_dotnet_sdk_and_runtime_compare_at_major_minor(sdk, runtime, flagged):
    _, result = check(
        report_of(
            setup_dotnet(sdk),
            image("mcr.microsoft.com/dotnet/aspnet", runtime),
            image("mcr.microsoft.com/dotnet/aspire-dashboard", "9.5"),
        )
    )
    assert bool(result.inconsistencies) is flagged
    assert counts(result)[".NET"] == 2


def test_aspire_sdk_and_cli_compare_at_full_precision():
    _, result = check(
        report_of(
            nuget("Aspire.AppHost.Sdk", "13.5.4"),
            nuget("Aspire.Cli", "13.6.1", manager="regex", file=".devcontainer/Dockerfile"),
        )
    )
    assert versions(result, "Aspire") == ["13.5.4", "13.6.1"]


def test_declarations_get_their_lines_from_the_checkout(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/m\n\ngo 1.25.14\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: actions/setup-go@v7\n        with:\n"
        "          go-version: '1.25'\n  b:\n    steps:\n      - uses: actions/setup-go@v7\n"
        "        with:\n          go-version: '1.25'\n"
    )
    (tmp_path / "Dockerfile").write_text("FROM golang:1.27-alpine AS build\n")
    _, result = check(
        report_of(
            go_mod("1.25.14"),
            setup_go("1.25"),
            setup_go("1.25"),
            image("golang", "1.27-alpine"),
        ),
        checkout=tmp_path,
    )
    [flagged] = result.inconsistencies
    assert [d["location"] for d in flagged["declarations"]] == [
        {"file": "Dockerfile", "line": 1},
        {"file": ".github/workflows/ci.yml", "line": 6},
        {"file": ".github/workflows/ci.yml", "line": 11},
        {"file": "go.mod", "line": 3},
    ]


@pytest.mark.parametrize(
    "declaration",
    [
        image("golang", "1-alpine"),
        image("mirror.gcr.io/library/golang", "1"),
        setup_go("1.x"),
        setup_go("1"),
    ],
)
def test_a_major_only_version_floats_and_is_skipped(declaration):
    _, result = check(report_of(go_mod("1.25.14"), declaration))
    assert result.inconsistencies == []
    assert counts(result)["Go toolchain"] == 1
    [gap] = result.gaps
    assert gap["kind"] == "unparseable_source"
    assert (
        "which floats to the newest release, so the consistency check skips it" in (gap["reason"])
    )


@pytest.mark.parametrize(
    "name",
    [
        "golang",
        "docker.io/library/golang",
        "mirror.gcr.io/library/golang",
        "public.ecr.aws/docker/library/golang",
    ],
)
def test_golang_images_count_from_docker_hub_and_its_mirrors(name):
    _, result = check(report_of(go_mod("1.25.14"), image(name, "1.27-alpine")))
    assert versions(result, "Go toolchain") == ["1.27", "1.25.14"]


@pytest.mark.parametrize(
    ("first", "second", "flagged"),
    [
        # Feature bands: the third part of an SDK version is its band and patch.
        (setup_dotnet("10.0.4xx"), setup_dotnet("10.0.401"), False),
        (setup_dotnet("10.0.1xx"), setup_dotnet("10.0.401"), True),
        (setup_dotnet("10.0.401"), setup_dotnet("10.0.403"), True),
        (setup_dotnet("10.0.x"), setup_dotnet("10.0.401"), False),
        (image("mcr.microsoft.com/dotnet/sdk", "10.0.100-noble"), setup_dotnet("10.0.1xx"), False),
        (image("mcr.microsoft.com/dotnet/sdk", "10.0.100"), setup_dotnet("10.0.401"), True),
        # Against a runtime, only major.minor counts.
        (setup_dotnet("10.0.401"), image("mcr.microsoft.com/dotnet/aspnet", "10.0.5"), False),
        (setup_dotnet("10.0.401"), image("mcr.microsoft.com/dotnet/runtime", "10.1"), True),
        (
            image("mcr.microsoft.com/dotnet/sdk", "10.0.100"),
            image("mcr.microsoft.com/devcontainers/dotnet", "2.2.3-10.0-noble"),
            False,
        ),
        (
            setup_dotnet("11.0.x"),
            image("mcr.microsoft.com/devcontainers/dotnet", "2.2.3-10.0-noble"),
            True,
        ),
    ],
)
def test_dotnet_sdks_compare_by_feature_band_and_with_runtimes_at_major_minor(
    first, second, flagged
):
    _, result = check(report_of(first, second))
    assert counts(result)[".NET"] == 2
    assert bool(result.inconsistencies) is flagged


def test_the_devcontainer_image_declares_its_dotnet_line():
    _, result = check(
        report_of(
            setup_dotnet("11.0.x"),
            image("mcr.microsoft.com/devcontainers/dotnet", "2.2.3-10.0-noble"),
        )
    )
    assert versions(result, ".NET") == ["10.0", "11.0"]


@pytest.mark.parametrize("tag", ["2.2", "2", "10.0", "2.2.3-10.0"])
def test_a_devcontainer_tag_without_a_dotnet_line_is_a_gap(tag):
    _, result = check(
        report_of(setup_dotnet("10.0.x"), image("mcr.microsoft.com/devcontainers/dotnet", tag))
    )
    assert len(result.compared[".NET"]) == 1  # setup-dotnet only
    [gap] = result.gaps
    assert gap["reason"] == (
        f".NET: mcr.microsoft.com/devcontainers/dotnet declares {tag!r}, which isn't an image "
        "version, a .NET line and an OS, such as 2.2.3-10.0-noble, so the consistency check "
        "skips it."
    )


def test_an_image_tag_with_a_variable_is_a_gap():
    # What Renovate 44 reports for `FROM golang:${GO_VERSION}-alpine` without a default.
    dep = {
        "datasource": "docker",
        "depType": "stage",
        "skipReason": "contains-variable",
        "replaceString": "golang:${GO_VERSION}-alpine",
    }
    _, result = check(report_of(go_mod("1.25.14"), ("dockerfile", "Dockerfile", dep)))
    assert counts(result)["Go toolchain"] == 1
    assert result.gaps == [
        {
            "kind": "unparseable_source",
            "subject": "Dockerfile",
            "reason": "Go toolchain: golang declares '${GO_VERSION}-alpine', a variable the "
            "scan can't resolve, so the consistency check skips it.",
        }
    ]


def test_a_workflow_expression_in_setup_go_is_a_gap():
    _, result = check(report_of(go_mod("1.25.14"), setup_go("${{ env.GO }}")))
    assert "a variable the scan can't resolve" in result.gaps[0]["reason"]


def test_an_alias_nothing_declares_is_listed_as_compared_nowhere():
    _, result = check(report_of(go_mod("1.25.14"), setup_go("1.25")))
    assert result.compared == {
        "Go toolchain": ["github-actions:.github/workflows/ci.yml:go", "gomod:go.mod:go"],
        ".NET": [],
        "Aspire": [],
    }


def test_a_commented_out_go_version_isnt_its_line(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: actions/setup-go@v7\n        with:\n"
        "          # go-version: '1.27'\n          go-version: '1.27'\n"
    )
    _, result = check(report_of(go_mod("1.25.14"), setup_go("1.27")), checkout=tmp_path)
    [declaration] = [d for d in result.inconsistencies[0]["declarations"] if d["version"] == "1.27"]
    assert declaration["location"]["line"] == 7


def test_the_toolchain_directive_gets_its_own_line_when_go_has_the_same_value(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/m\n\ngo 1.25.14\n\ntoolchain go1.25.14\n")
    _, result = check(
        report_of(go_mod("1.25.14"), go_mod("1.25.14", "toolchain"), setup_go("1.27")),
        checkout=tmp_path,
    )
    [declaration] = [
        d for d in result.inconsistencies[0]["declarations"] if d["dependency"].startswith("gomod")
    ]
    assert declaration == {
        "dependency": "gomod:go.mod:go#2",
        "location": {"file": "go.mod", "line": 5},
        "version": "1.25.14",
    }
