import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sdlc import lifecycle
from sdlc.dependabot import Response
from sdlc.record import validate_record
from sdlc.renovate import normalize

FIXTURES = Path(__file__).parents[1] / "fixtures"
ENDOFLIFE = FIXTURES / "endoflife"  # captured 2026-10-09, see its manifest.json
AT = "2026-10-09T09:00:00+00:00"
SCANNED_AT = datetime.fromisoformat(AT)
FETCHED_AT = datetime(2026, 10, 9, 9, 5, tzinfo=UTC)


def served(url):
    """endoflife.date as captured."""
    assert url.startswith(f"{lifecycle.API}/products/")
    return Response(200, {}, (ENDOFLIFE / f"{url.rsplit('/', 1)[1]}.json").read_bytes())


def check(report, *, get=served, scanned_at=SCANNED_AT):
    inventory = normalize(report, looked_up_at=AT)
    result = lifecycle.check(
        report, inventory.dependencies, scanned_at=scanned_at, get=get, now=lambda: FETCHED_AT
    )
    return inventory, result


def line(result, product, version=None):
    found = [
        entry
        for entry in result.lifecycle
        if entry["product"] == product and (version is None or entry["line"] == version)
    ]
    assert len(found) == 1, (product, version, result.lifecycle)
    return found[0]


def report_of(*deps):
    """A Renovate report with these (manager, file, dependency) entries."""
    files: dict[str, dict[str, dict]] = {}
    for manager, file, dep in deps:
        files.setdefault(manager, {}).setdefault(file, {"packageFile": file, "deps": []})
        files[manager][file]["deps"].append(dep)
    package_files = {m: list(by_file.values()) for m, by_file in files.items()}
    return {"repositories": {"local": {"packageFiles": package_files}}}


def image(name, tag, file="Dockerfile", manager="dockerfile", **extra):
    dep = {"depName": name, "datasource": "docker", "currentValue": tag, **extra}
    dep["replaceString"] = f"{name}:{tag}"
    return (manager, file, dep)


def setup(tool, value):
    """A setup action's version, such as setup-python's python-version."""
    dep = {"depName": tool, "packageName": f"actions/{tool}-versions"}
    dep |= {"datasource": "github-releases", "depType": "uses-with", "currentValue": value}
    return ("github-actions", ".github/workflows/ci.yml", dep)


def go_mod(value, dep_type="golang"):
    dep = {"depName": "go", "datasource": "golang-version", "depType": dep_type}
    return ("gomod", "go.mod", dep | {"currentValue": value})


def releases(*lines):
    """A product's data with these (name, isEol, eolFrom) lines, newest first."""
    body = {
        "schema_version": "1.2.1",
        "result": {
            "name": "go",
            "releases": [
                {"name": name, "releaseDate": None, "isEol": eol, "eolFrom": eol_from}
                for name, eol, eol_from in lines
            ],
        },
    }
    return lambda url: Response(200, {}, json.dumps(body).encode())


@pytest.fixture(scope="module")
def scan_064aa09():
    path = FIXTURES / "azure-egress-proxy" / "renovate" / "064aa09" / "report-with-scan-config.json"
    return check(json.loads(path.read_text()))


def test_064aa09_builds_with_go_1_25_past_its_end_of_life(scan_064aa09, record_from):
    inventory, result = scan_064aa09
    go = line(result, "go")
    assert go["line"] == "1.25"
    assert go["state"] == "end_of_life"
    assert go["end_of_life"] == "2026-08-19"
    assert go["supported_lines"] == ["1.26", "1.27"]  # the oldest supported line first
    assert go["source"] == "https://endoflife.date/api/v1/products/go"
    assert go["dependencies"] == [
        "dockerfile:proxy/Dockerfile:docker.io/library/golang",
        "github-actions:.github/workflows/ci.yml:go",
        "github-actions:.github/workflows/release.yml:go",
        "gomod:proxy/go.mod:go",
    ]

    record = record_from(inventory)
    record["lifecycle"] = result.lifecycle
    record["tools"] += result.tools
    assert validate_record(record) == []


def test_064aa09_lines_that_are_supported_or_unknown(scan_064aa09):
    _, result = scan_064aa09
    states = {(e["product"], e["line"]): e["state"] for e in result.lifecycle}
    assert states == {
        ("go", "1.25"): "end_of_life",
        ("dotnet", "10"): "supported",  # setup-dotnet, six images and the devcontainer
        ("python", "3.12"): "supported",
        ("alpine-linux", "alpine"): "unknown",  # golang:1.25-alpine and python:3.12-alpine
        ("debian", "12"): "supported",  # distroless static-debian12
        ("ubuntu", "24.04"): "supported",  # the devcontainer's 2.2.3-10.0-noble
        ("ubuntu", "latest"): "unknown",  # runs-on: ubuntu-latest has no mapping
    }
    assert len(line(result, "dotnet")["dependencies"]) == 8
    assert line(result, "dotnet")["end_of_life"] == "2028-11-14"
    assert "names no release" in line(result, "alpine-linux")["reason"]
    assert "No lifecycle mapping" in line(result, "ubuntu", "latest")["reason"]
    assert line(result, "ubuntu", "24.04")["dependencies"] == [
        "dockerfile:.devcontainer/Dockerfile:mcr.microsoft.com/devcontainers/dotnet"
    ]
    assert result.gaps == []
    fetched = {t["url"].rsplit("/", 1)[1]: t for t in result.tools}
    assert sorted(fetched) == ["debian", "dotnet", "go", "python", "ubuntu"]  # each once
    assert len(result.tools) == 5
    assert fetched["go"] == {
        "name": "endoflife.date",
        "version": "v1",
        "url": "https://endoflife.date/api/v1/products/go",
        "fetched_at": "2026-10-09T09:05:00+00:00",
    }


def test_each_product_is_fetched_once_without_credentials(monkeypatch):
    sent = []

    def answer(request, timeout):
        sent.append(request)
        return _Answer((ENDOFLIFE / "go.json").read_bytes())

    monkeypatch.setattr(lifecycle._OPENER, "open", answer)
    report = report_of(
        go_mod("1.25.14"),
        image("golang", "1.25-alpine"),
        image("golang", "1.26", file="other/Dockerfile"),
    )
    _, result = check(report, get=lifecycle.get)
    assert [r.full_url for r in sent] == ["https://endoflife.date/api/v1/products/go"]
    assert sent[0].get_method() == "GET"
    assert not any(k.lower() == "authorization" for k, _ in sent[0].header_items())
    assert line(result, "go", "1.26")["state"] == "supported"


@pytest.mark.parametrize(
    ("eol_from", "state"),
    [
        ("2026-10-09", "end_of_life"),  # ends on the scan's day
        ("2026-10-10", "nearing_end_of_life"),
        ("2027-01-07", "nearing_end_of_life"),  # 90 days after the scan
        ("2027-01-08", "supported"),
    ],
)
def test_a_line_ending_within_90_days_is_nearing_its_end(eol_from, state):
    _, result = check(
        report_of(go_mod("1.27.1")), get=releases(("1.27", False, eol_from), ("1.26", True, None))
    )
    go = line(result, "go")
    assert go["state"] == state
    assert go["end_of_life"] == eol_from
    assert go["supported_lines"] == ([] if state == "end_of_life" else ["1.27"])


def test_dotnet_8_is_nearing_its_end_in_the_captured_data():
    _, result = check(report_of(image("mcr.microsoft.com/dotnet/aspnet", "8.0")))
    dotnet = line(result, "dotnet")
    assert (dotnet["line"], dotnet["state"]) == ("8", "nearing_end_of_life")
    assert dotnet["end_of_life"] == "2026-11-10"
    assert dotnet["supported_lines"] == ["8", "9", "10"]


def test_a_line_without_an_end_date_is_supported_without_one():
    _, result = check(report_of(go_mod("1.27.2")))
    go = line(result, "go")
    assert go["state"] == "supported"
    assert "end_of_life" not in go


def test_a_line_that_ended_without_a_date_says_so(record_from):
    report = report_of(go_mod("1.26.1"))
    inventory, result = check(report, get=releases(("1.27", False, None), ("1.26", True, None)))
    go = line(result, "go")
    assert go["state"] == "end_of_life"
    assert "without a date" in go["reason"]
    record = record_from(inventory)
    record["lifecycle"] = result.lifecycle
    assert validate_record(record) == []


def test_a_line_the_data_lacks_is_unknown_not_supported():
    _, result = check(report_of(image("golang", "1.30-alpine3.22")))
    go = line(result, "go")
    assert go["state"] == "unknown"
    assert go["reason"] == "endoflife.date lists no go 1.30 line."
    assert go["supported_lines"] == ["1.26", "1.27"]
    assert line(result, "alpine-linux")["state"] == "supported"


@pytest.mark.parametrize(
    ("dep", "product", "version"),
    [
        (image("redis", "7-alpine"), "redis", "7-alpine"),
        (("github-actions", "ci.yml", {"depName": "java", "datasource": "java-version",
          "currentValue": "21"}), "java", "21"),
        (setup("ruby", "3.3"), "ruby", "3.3"),
        (image("mcr.microsoft.com/dotnet/aspire-dashboard", "9.5"),
         "mcr.microsoft.com/dotnet/aspire-dashboard", "9.5"),
    ],
)  # fmt: skip
def test_an_unmapped_image_or_runtime_is_unknown(dep, product, version, record_from):
    inventory, result = check(report_of(dep))
    unmapped = line(result, product)
    assert unmapped["line"] == version
    assert unmapped["state"] == "unknown"
    assert "No lifecycle mapping" in unmapped["reason"]
    assert "source" not in unmapped
    record = record_from(inventory)
    record["lifecycle"] = result.lifecycle
    assert validate_record(record) == []


VNET = "avm/res/network/virtual-network"


def test_packages_modules_and_features_have_no_lifecycle_line():
    report = report_of(
        ("nuget", "App.csproj", {"depName": "Azure.Core", "datasource": "nuget",
                                 "currentValue": "1.53.0"}),
        ("gomod", "go.mod", {"depName": "golang.org/x/net", "datasource": "go",
                             "currentValue": "v0.58.0"}),
        image("ghcr.io/devcontainers/features/docker-in-docker", "2",
              file=".devcontainer/devcontainer.json", manager="devcontainer", depType="feature"),
        ("regex", "main.bicep", {"depName": "avm/res/network/virtual-network",
                                 "packageName": f"mcr.microsoft.com/bicep/{VNET}",
                                 "datasource": "docker", "currentValue": "0.10.2"}),
    )  # fmt: skip
    _, result = check(report)
    assert result.lifecycle == []
    assert result.tools == []  # nothing to look up, so nothing was requested


def test_an_unreachable_api_makes_every_mapped_line_unknown(scan_064aa09, record_from):
    requested = []

    def unreachable(url):
        requested.append(url)
        raise urllib.error.URLError("Name or service not known")

    path = FIXTURES / "azure-egress-proxy" / "renovate" / "064aa09" / "report-with-scan-config.json"
    inventory, result = check(json.loads(path.read_text()), get=unreachable)
    assert len(requested) == 1  # the rest isn't tried
    assert {e["state"] for e in result.lifecycle} == {"unknown"}
    assert line(result, "go")["reason"] == (
        "endoflife.date couldn't be reached: Name or service not known."
    )
    assert all("supported_lines" not in e for e in result.lifecycle)
    assert result.gaps == [
        {
            "kind": "unavailable_source",
            "subject": "endoflife.date",
            "reason": "endoflife.date couldn't be reached: Name or service not known.",
        }
    ]
    assert result.tools == []  # nothing was read, so nothing has a fetch time
    record = record_from(inventory)
    record["lifecycle"] = result.lifecycle
    record["gaps"] += result.gaps
    assert validate_record(record) == []


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (Response(503, {}, b"busy"), "endoflife.date answered 503 for go."),
        (Response(200, {}, b"<html>"), "endoflife.date's answer for go isn't JSON"),
        (Response(200, {}, b'{"result": {}}'), "isn't a list of releases"),
        (
            Response(200, {}, b'{"result": {"releases": [{"name": "1.25", "isEol": "yes"}]}}'),
            "isn't a list of releases",
        ),
        (
            Response(
                200,
                {},
                b'{"result": {"releases": [{"name": "1.25", "isEol": true, '
                b'"eolFrom": "2026-02-30"}]}}',
            ),
            "isn't a list of releases",
        ),
    ],
)
def test_an_unusable_answer_makes_that_product_unknown(response, reason):
    def answer(url):
        return response if url.endswith("/go") else served(url)

    _, result = check(report_of(go_mod("1.25.14"), image("python", "3.12")), get=answer)
    assert line(result, "go")["state"] == "unknown"
    assert reason in line(result, "go")["reason"]
    assert line(result, "python")["state"] == "supported"
    assert [g["reason"] for g in result.gaps] == [line(result, "go")["reason"]]


@pytest.mark.parametrize(
    ("name", "tag", "alpine", "state"),
    [
        ("golang", "1.25-alpine3.22", "3.22", "supported"),
        ("python", "3.12-alpine3.21", "3.21", "nearing_end_of_life"),
        ("python", "alpine3.20", "3.20", "end_of_life"),
        ("node", "20-alpine3.24-slim", "3.24", "supported"),
        ("alpine", "3.22", "3.22", "supported"),
        ("alpine", "3.22.1", "3.22", "supported"),
        ("golang", "1.25-alpine", "alpine", "unknown"),  # floats with the image's builds
        ("python", "alpine", "alpine", "unknown"),
        ("alpine", "latest", "latest", "unknown"),
    ],
)
def test_the_alpine_release_is_read_from_the_tag(name, tag, alpine, state):
    _, result = check(report_of(image(name, tag)))
    found = line(result, "alpine-linux")
    assert (found["line"], found["state"]) == (alpine, state)
    if alpine == "alpine":
        assert found["reason"] == (
            "'alpine' names no release: it follows whichever one the image was last built on."
        )


@pytest.mark.parametrize("tag", ["1.25", "3.12-slim-bookworm", "nonroot"])
def test_a_tag_without_alpine_has_no_alpine_line(tag):
    _, result = check(report_of(image("golang", tag)))
    assert not [e for e in result.lifecycle if e["product"] == "alpine-linux"]


def test_an_image_on_alpine_still_reports_the_image_itself():
    _, result = check(report_of(image("redis", "7-alpine3.22")))
    assert line(result, "alpine-linux")["line"] == "3.22"
    assert line(result, "redis")["state"] == "unknown"  # Alpine doesn't speak for redis


@pytest.mark.parametrize(
    ("name", "debian", "state"),
    [
        ("gcr.io/distroless/static-debian12", "12", "supported"),
        ("gcr.io/distroless/cc-debian11", "11", "end_of_life"),
        ("gcr.io/distroless/static", "gcr.io/distroless/static", "unknown"),
    ],
)
def test_distroless_images_name_their_debian_release(name, debian, state):
    _, result = check(report_of(image(name, "nonroot")))
    found = line(result, "debian")
    assert (found["line"], found["state"]) == (debian, state)


@pytest.mark.parametrize(
    ("dep", "dotnet"),
    [
        (image("mcr.microsoft.com/dotnet/sdk", "10.0.100-noble"), "10"),
        (image("mcr.microsoft.com/dotnet/runtime-deps", "3.1-alpine"), "3.1"),
        (image("mcr.microsoft.com/devcontainers/dotnet", "2.2.3-10.0-noble"), "10"),
        (("github-actions", "ci.yml", {"depName": "dotnet-sdk", "datasource": "dotnet-version",
          "currentValue": "10.0.x"}), "10"),
    ],
)  # fmt: skip
def test_dotnet_lines_are_named_by_major_from_5_on(dep, dotnet):
    _, result = check(report_of(dep))
    assert line(result, "dotnet")["line"] == dotnet


@pytest.mark.parametrize(
    ("dep", "shown", "reason"),
    [
        (image("golang", "latest"), "latest", "golang declares 'latest', which isn't one version"),
        (image("golang", "1-alpine"), "1-alpine", "floats to the newest release"),
        (go_mod("1"), "1", "floats to the newest release"),
    ],
)
def test_a_declaration_that_names_no_line_is_unknown(dep, shown, reason):
    _, result = check(report_of(dep))
    go = line(result, "go")
    assert (go["line"], go["state"]) == (shown, "unknown")
    assert reason in go["reason"]
    assert result.tools == []  # nothing to look up


def test_only_the_directive_that_sets_the_toolchain_counts():
    report = report_of(go_mod("1.24.0"), go_mod("go1.25.14", dep_type="toolchain"))
    _, result = check(report)
    assert [(e["line"], e["dependencies"]) for e in result.lifecycle] == [
        ("1.25", ["gomod:go.mod:go#2"])
    ]


def test_the_supported_lines_follow_the_scan_date_not_the_data():
    # isEol was computed when the data was generated; the date decides at the scan's time.
    get = releases(
        ("1.27", False, None), ("1.26", False, "2026-10-01"), ("1.25", True, "2026-08-19")
    )
    _, result = check(report_of(go_mod("1.26.3")), get=get)
    go = line(result, "go")
    assert (go["state"], go["supported_lines"]) == ("end_of_life", ["1.27"])


def test_redirects_are_followed_only_within_the_api():
    handler = lifecycle._WithinApi()
    request = urllib.request.Request(f"{lifecycle.API}/products/alpine")  # noqa: S310
    renamed = f"{lifecycle.API}/products/alpine-linux/"
    assert handler.redirect_request(request, None, 301, "Moved", {}, renamed).full_url == renamed
    for elsewhere in (
        "https://example.com/api/v1/products/go",
        "http://endoflife.date/api/v1/products/go",
        "https://endoflife.date.example.com/api/v1/products/go",
    ):
        assert handler.redirect_request(request, None, 302, "Found", {}, elsewhere) is None


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


@pytest.mark.parametrize(
    ("dep", "product", "version", "state"),
    [
        (setup("python", "3.12.x"), "python", "3.12", "supported"),
        (setup("node", "20"), "nodejs", "20", "end_of_life"),
        (image("node", "24.9.0-alpine3.22"), "nodejs", "24", "supported"),
    ],
)  # fmt: skip
def test_setup_python_setup_node_and_node_images_are_mapped(dep, product, version, state):
    _, result = check(report_of(dep))
    found = line(result, product)
    assert (found["line"], found["state"]) == (version, state)


@pytest.mark.parametrize(
    ("name", "tag", "product", "version", "state"),
    [
        ("golang", "1.25-bookworm", "debian", "12", "supported"),
        ("python", "3.12-slim-bookworm", "debian", "12", "supported"),
        ("golang", "1.25-bullseye", "debian", "11", "end_of_life"),
        ("mcr.microsoft.com/dotnet/aspnet", "10.0-noble", "ubuntu", "24.04", "supported"),
        ("mcr.microsoft.com/dotnet/aspnet", "10.0-noble-chiseled", "ubuntu", "24.04", "supported"),
        ("mcr.microsoft.com/devcontainers/dotnet", "2.2.3-10.0-noble", "ubuntu", "24.04",
         "supported"),
        ("eclipse-temurin", "21-jdk-jammy", "ubuntu", "22.04", "supported"),
        ("debian", "bookworm-slim", "debian", "12", "supported"),
        ("debian", "12.7-slim", "debian", "12", "supported"),
        ("ubuntu", "noble", "ubuntu", "24.04", "supported"),
        ("ubuntu", "22.04", "ubuntu", "22.04", "supported"),
        ("ubuntu", "plucky-20250415", "ubuntu", "25.04", "end_of_life"),
    ],
)  # fmt: skip
def test_os_codenames_in_tags_name_their_release(name, tag, product, version, state):
    _, result = check(report_of(image(name, tag)))
    found = line(result, product)
    assert (found["line"], found["state"]) == (version, state)
    assert found["source"] == f"https://endoflife.date/api/v1/products/{product}"


@pytest.mark.parametrize(
    ("name", "tag", "product", "version", "reason"),
    [
        ("golang", "1.30-forky", "debian/ubuntu", "forky",
         "'forky' isn't the codename of a Debian or Ubuntu release endoflife.date lists."),
        ("debian", "forky-slim", "debian", "forky",
         "'forky' isn't the codename of a Debian release endoflife.date lists."),
        ("ubuntu", "latest", "ubuntu", "latest",
         "ubuntu declares 'latest', which floats to the newest release, so its line is unknown."),
        ("debian", "stable-slim", "debian", "stable-slim",
         "debian declares 'stable-slim', which floats to the newest release, so its line is "
         "unknown."),
    ],
)  # fmt: skip
def test_a_codename_without_a_release_is_unknown(name, tag, product, version, reason):
    _, result = check(report_of(image(name, tag)))
    found = line(result, product)
    assert (found["line"], found["state"], found["reason"]) == (version, "unknown", reason)


@pytest.mark.parametrize("tag", ["1.25-alpine", "3.12-slim", "nonroot", "21-jdk", "latest"])
def test_a_tag_without_a_codename_has_no_os_line(tag):
    _, result = check(report_of(image("golang", tag)))
    assert [e["product"] for e in result.lifecycle if e["product"] != "go"] in (
        [],
        ["alpine-linux"],
    )


def test_codenames_are_unknown_when_endoflife_date_is_unreachable():
    def unreachable(url):
        raise urllib.error.URLError("timed out")

    _, result = check(report_of(image("python", "3.12-slim-bookworm")), get=unreachable)
    found = line(result, "debian/ubuntu")
    assert (found["line"], found["state"]) == ("bookworm", "unknown")
    assert found["reason"] == "endoflife.date couldn't be reached: timed out."
    assert result.tools == []


def test_a_line_marked_ended_is_end_of_life_even_before_its_date():
    get = releases(("1.27", False, None), ("1.26", True, "2027-02-10"))
    _, result = check(report_of(go_mod("1.26.3")), get=get)
    go = line(result, "go")
    assert go["state"] == "end_of_life"
    assert go["end_of_life"] == "2027-02-10"
    assert go["reason"] == (
        "endoflife.date marks it end of life, although its date, 2027-02-10, is later."
    )
    assert go["supported_lines"] == ["1.27"]


def test_only_products_actually_read_get_a_fetch_time():
    def answer(url):
        return Response(503, {}, b"busy") if url.endswith("/go") else served(url)

    _, result = check(report_of(go_mod("1.25.14"), image("python", "3.12")), get=answer)
    assert [t["url"] for t in result.tools] == ["https://endoflife.date/api/v1/products/python"]
