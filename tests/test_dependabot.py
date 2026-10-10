import copy
import http.client
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path

import pytest

from sdlc import dependabot, osv
from sdlc.dependabot import Alerts, Response, Unavailable
from sdlc.record import validate_record
from sdlc.renovate import Inventory, indirect, normalize

SCANNED = "064aa099ecf7ffea9664b89df29f7d89d6859358"
HEAD = "e93d7062b075352f151f8e6b5a15f60913e7bd98"  # main when the fixtures were captured

FIXTURES = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy"
ALERTS = FIXTURES / "dependabot-alerts"
AT = "2026-10-09T09:00:00+00:00"
REPO = "alanta/azure-egress-proxy"
CRYPTO = "gomod:proxy/go.mod:golang.org/x/crypto"
SERVICE_DEFAULTS = (
    "nuget:src/ServiceDefaults/ServiceDefaults.csproj:OpenTelemetry.Exporter.OpenTelemetryProtocol"
)
TOKEN = "a-token"  # noqa: S105 - a fake, never sent anywhere
ALERTS_URL = f"https://api.github.com/repos/{REPO}/dependabot/alerts?state=open&per_page=100"
REPO_URL = f"https://api.github.com/repos/{REPO}"
BRANCH_URL = f"https://api.github.com/repos/{REPO}/branches/main"


@pytest.fixture(scope="module")
def scanned():
    """The inventory and OSV-Scanner's vulnerabilities at 064aa09."""
    report = json.loads(
        (FIXTURES / "renovate" / "064aa09" / "report-with-scan-config.json").read_text()
    )
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
    return merged, found.vulnerabilities


@pytest.fixture(scope="module")
def captured():
    """Every alert of the subject on 2026-10-09; all of them fixed, so none was open."""
    return json.loads((ALERTS / "all-states.json").read_text())


def alert(captured, number, **advisory):
    """A captured alert, as if open, with its advisory's ids replaced where given."""
    found = copy.deepcopy(next(a for a in captured if a["number"] == number))
    found["state"] = "open"
    found["security_advisory"] |= advisory
    if advisory:
        found["security_advisory"]["identifiers"] = [
            {"type": t, "value": advisory[k]}
            for t, k in (("GHSA", "ghsa_id"), ("CVE", "cve_id"))
            if advisory.get(k)
        ]
    return found


def alerts(*found, head=HEAD):
    return Alerts("main", head, AT, list(found))


def compare(found, vulnerabilities, dependencies):
    return dependabot.compare(found, vulnerabilities, dependencies, SCANNED)


def record(record_from, inventory, vulnerabilities, section):
    result = record_from(inventory)
    result["vulnerabilities"] = vulnerabilities
    result["dependabot_alerts"] = section
    result["gaps"] = []
    return result


class FakeGitHub:
    """GitHub's API, answering from a table of URL to response; a missing URL fails the test."""

    def __init__(self, pages=None, **responses):
        self.responses = {
            REPO_URL: ok({"default_branch": "main"}),
            BRANCH_URL: ok({"name": "main", "commit": {"sha": HEAD}}),
            **(pages or {}),
        }
        self.requests = []

    def __call__(self, url, token):
        self.requests.append((url, token))
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


def ok(body, link=None):
    headers = {"link": link} if link else {}
    return Response(200, headers, json.dumps(body).encode())


def refused(status, message, **headers):
    body = {"message": message, "documentation_url": "https://docs.github.com/rest"}
    return Response(status, headers, json.dumps(body).encode())


def read(github, token=TOKEN):
    return dependabot.read(
        REPO, token, get=github, now=lambda: datetime(2026, 10, 9, 9, tzinfo=UTC)
    )


def test_an_alert_matches_an_osv_advisory_by_alias(scanned, captured, record_from):
    inventory, vulnerabilities = scanned
    # GO-2026-6354 is CVE-2026-78662 in OSV; Dependabot would name it by its GHSA id.
    found = alert(captured, 16, ghsa_id="GHSA-aaaa-bbbb-cccc", cve_id="CVE-2026-78662")
    section, result = compare(alerts(found), vulnerabilities, inventory.dependencies)

    assert (section["ref"], section["commit"], section["is_scanned_commit"]) == (
        "main",
        HEAD,
        False,
    )
    assert section["read_at"] == AT
    assert section["alerts"] == [
        {
            "number": 16,
            "advisory": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2026-78662"],
            "ecosystem": "go",
            "package": "golang.org/x/crypto",
            "manifest": "proxy/go.mod",
            "dependency": CRYPTO,
            "vulnerable_range": "< 0.52.0",
            "fixed_version": "0.52.0",
            "result": "matched",
        }
    ]
    corroborated = [v for v in result if "dependabot_alerts" in v]
    assert [(v["advisory"], v["dependabot_alerts"]) for v in corroborated] == [
        ("GO-2026-6354", [16])
    ]
    # The scan's own finding is unchanged otherwise, and the input isn't modified.
    assert all("dependabot_alerts" not in v for v in vulnerabilities)
    assert validate_record(record(record_from, inventory, result, section)) == []


def test_alerts_the_scan_did_not_find_are_listed_as_unmatched(scanned, captured, record_from):
    inventory, vulnerabilities = scanned
    section, result = compare(
        # A real Go alert the scan has no advisory for, and a NuGet one on a project file.
        alerts(alert(captured, 16), alert(captured, 1)),
        vulnerabilities,
        inventory.dependencies,
    )
    assert [(a["number"], a["result"], a.get("dependency")) for a in section["alerts"]] == [
        (1, "unmatched", SERVICE_DEFAULTS),
        (16, "unmatched", CRYPTO),
    ]
    assert section["alerts"][1]["advisory"] == "GHSA-qpw4-5x99-6vjp"
    assert section["alerts"][1]["aliases"] == ["CVE-2026-39827"]
    assert result == vulnerabilities
    assert validate_record(record(record_from, inventory, result, section)) == []


def test_the_same_advisory_on_another_package_does_not_match(scanned, captured):
    inventory, vulnerabilities = scanned
    # CVE-2026-78659 is an x/net advisory in the scan; on x/crypto it is another finding.
    found = alert(captured, 16, ghsa_id="GHSA-aaaa-bbbb-cccc", cve_id="CVE-2026-78659")
    section, result = compare(alerts(found), vulnerabilities, inventory.dependencies)
    assert section["alerts"][0]["result"] == "unmatched"
    assert all("dependabot_alerts" not in v for v in result)


def test_an_alert_on_a_package_the_inventory_lacks_names_no_dependency(scanned, captured):
    inventory, vulnerabilities = scanned
    found = alert(captured, 1)
    found["dependency"]["manifest_path"] = "src/Other/Other.csproj"
    section, _ = compare(alerts(found), vulnerabilities, inventory.dependencies)
    assert "dependency" not in section["alerts"][0]
    assert section["alerts"][0]["result"] == "unmatched"


def test_no_open_alerts_is_an_empty_section_not_a_gap(scanned, record_from):
    """What the subject had on 2026-10-09: the alerts were read, and none was open."""
    inventory, vulnerabilities = scanned
    github = FakeGitHub({ALERTS_URL: ok(json.loads((ALERTS / "open.json").read_text()))})
    section, result = compare(read(github), vulnerabilities, inventory.dependencies)
    assert section == {
        "ref": "main",
        "commit": HEAD,
        "is_scanned_commit": False,
        "read_at": AT,
        "alerts": [],
    }
    assert validate_record(record(record_from, inventory, result, section)) == []


def test_every_page_is_read_with_the_token(captured):
    second = (
        f"https://api.github.com/repos/{REPO}/dependabot/alerts?state=open&after=Y3Vy&per_page=100"
    )
    github = FakeGitHub(
        {
            ALERTS_URL: ok(
                [alert(captured, 16), alert(captured, 15)],
                link=f'<{second}>; rel="next", <{ALERTS_URL}>; rel="first"',
            ),
            second: ok([alert(captured, 1)], link=f'<{ALERTS_URL}>; rel="first"'),
        }
    )
    found = read(github)
    assert [a["number"] for a in found.alerts] == [16, 15, 1]
    assert found.ref == "main"
    assert found.read_at == AT
    assert found.commit == HEAD
    # The head is read before the alerts, so it is no newer than what they describe.
    assert [url for url, _ in github.requests] == [REPO_URL, BRANCH_URL, ALERTS_URL, second]
    assert {token for _, token in github.requests} == {TOKEN}


def test_a_next_page_outside_the_api_is_not_followed(captured):
    elsewhere = "https://example.com/alerts?page=2"
    github = FakeGitHub({ALERTS_URL: ok([alert(captured, 16)], link=f'<{elsewhere}>; rel="next"')})
    with pytest.raises(Unavailable, match="outside its API"):
        read(github)
    assert elsewhere not in [url for url, _ in github.requests]


def test_without_a_token_nothing_is_requested():
    github = FakeGitHub()
    with pytest.raises(Unavailable, match="No token in SDLC_GITHUB_TOKEN"):
        read(github, token=None)
    assert github.requests == []


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            refused(403, "Resource not accessible by personal access token"),
            "The token lacks the Dependabot alerts: read permission (GitHub answered 403: "
            "Resource not accessible by personal access token).",
        ),
        (
            refused(403, "Dependabot alerts are disabled for this repository."),
            "Dependabot alerts are disabled for the repository (GitHub answered 403: "
            "Dependabot alerts are disabled for this repository.).",
        ),
        (
            refused(404, "Not Found"),
            "The repository or its Dependabot alerts aren't visible to the token",
        ),
        (
            Response(401, {}, (ALERTS / "unauthenticated.json").read_bytes()),
            "GitHub rejected the token (GitHub answered 401: Requires authentication).",
        ),
        (
            refused(
                403,
                "API rate limit exceeded for user ID 1.",
                **{"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1791536400"},
            ),
            "GitHub's rate limit was reached, until 2026-10-09T09:00:00+00:00",
        ),
        (
            refused(429, "You have exceeded a secondary rate limit.", **{"retry-after": "60"}),
            "GitHub's rate limit was reached, for 60 seconds",
        ),
        (Response(502, {}, b"<html>Bad gateway</html>"), "GitHub answered 502."),
        (Response(200, {}, b"not json"), "GitHub's answer isn't JSON"),
        (ok({"message": "not a list"}), "isn't a list of Dependabot alerts"),
        (ok([{"number": 1}]), "isn't a list of Dependabot alerts"),
        (
            http.client.IncompleteRead(b"[{", 1000),
            "GitHub's answer broke off: IncompleteRead(2 bytes read, 1000 more expected).",
        ),
        (
            Response(302, {"location": "https://example.com/alerts"}, b""),
            "GitHub redirected to https://example.com/alerts, outside its API, so it wasn't "
            "followed (GitHub answered 302).",
        ),
        (
            urllib.error.URLError(OSError(-2, "Name or service not known")),
            "GitHub's API couldn't be reached: [Errno -2] Name or service not known.",
        ),
        (TimeoutError("timed out"), "GitHub's API couldn't be reached: timed out."),
    ],
)
def test_alerts_that_cannot_be_read_say_why(response, expected):
    with pytest.raises(Unavailable) as error:
        read(FakeGitHub({ALERTS_URL: response}))
    assert expected in str(error.value)


def test_a_repository_without_a_default_branch_is_unavailable():
    github = FakeGitHub()
    github.responses[REPO_URL] = refused(404, "Not Found")
    with pytest.raises(Unavailable, match="aren't visible to the token"):
        read(github)
    assert ALERTS_URL not in [url for url, _ in github.requests]


def test_a_head_that_cannot_be_read_makes_the_alerts_unavailable():
    github = FakeGitHub()
    github.responses[BRANCH_URL] = ok({"name": "main", "commit": None})
    with pytest.raises(Unavailable, match="no head commit for main"):
        read(github)
    assert ALERTS_URL not in [url for url, _ in github.requests]


def test_the_section_says_whether_the_head_is_the_scanned_commit(scanned, record_from):
    inventory, vulnerabilities = scanned
    for head, expected in ((SCANNED, True), (HEAD, False)):
        section, result = compare(alerts(head=head), vulnerabilities, inventory.dependencies)
        assert section["is_scanned_commit"] is expected
        assert validate_record(record(record_from, inventory, result, section)) == []
    wrong = record(record_from, inventory, result, section | {"is_scanned_commit": True})
    assert "$.dependabot_alerts.is_scanned_commit: disagrees with the commits" in (
        validate_record(wrong)
    )


def test_a_next_link_back_to_a_page_already_read_stops(captured):
    github = FakeGitHub({ALERTS_URL: ok([alert(captured, 16)], link=f'<{ALERTS_URL}>; rel="next"')})
    with pytest.raises(Unavailable, match="links back to a page already read"):
        read(github)
    assert [url for url, _ in github.requests].count(ALERTS_URL) == 1


def test_an_alert_on_two_pages_counts_once(captured):
    second = f"{ALERTS_URL}&after=Y3Vy"
    github = FakeGitHub(
        {
            ALERTS_URL: ok(
                [alert(captured, 16), alert(captured, 15)], link=f'<{second}>; rel="next"'
            ),
            second: ok([alert(captured, 15), alert(captured, 1)]),
        }
    )
    assert [a["number"] for a in read(github).alerts] == [16, 15, 1]


def without(field_path):
    def change(found):
        *parents, last = field_path
        target = found
        for key in parents:
            target = target[key]
        target[last] = None

    return change


def replaced(field_path, value):
    def change(found):
        *parents, last = field_path
        target = found
        for key in parents:
            target = target[key]
        target[last] = value

    return change


@pytest.mark.parametrize(
    "change",
    [
        replaced(["number"], "16"),
        replaced(["number"], True),
        replaced(["number"], 0),
        without(["security_advisory"]),
        replaced(["security_advisory"], "GHSA-qpw4-5x99-6vjp"),
        without(["security_advisory", "ghsa_id"]),
        replaced(["security_advisory", "ghsa_id"], ""),
        replaced(["security_advisory", "cve_id"], 39827),
        replaced(["security_advisory", "identifiers"], "GHSA-qpw4-5x99-6vjp"),
        replaced(["security_advisory", "identifiers"], [None]),
        replaced(["security_advisory", "identifiers"], [{"value": 1}]),
        without(["dependency"]),
        without(["dependency", "package"]),
        replaced(["dependency", "package"], "golang.org/x/crypto"),
        without(["dependency", "package", "name"]),
        replaced(["dependency", "package", "ecosystem"], ["go"]),
        replaced(["dependency", "manifest_path"], {"path": "proxy/go.mod"}),
        replaced(["security_vulnerability"], "< 0.52.0"),
        replaced(["security_vulnerability", "vulnerable_version_range"], 52),
        replaced(["security_vulnerability", "first_patched_version"], "0.52.0"),
        replaced(["security_vulnerability", "first_patched_version", "identifier"], 52),
    ],
)
def test_a_malformed_alert_makes_the_alerts_unavailable(captured, change):
    found = alert(captured, 16)
    change(found)
    with pytest.raises(Unavailable, match="isn't a list of Dependabot alerts"):
        read(FakeGitHub({ALERTS_URL: ok([found])}))


def test_optional_alert_fields_may_be_null(captured, scanned):
    inventory, vulnerabilities = scanned
    found = alert(captured, 16)
    found["security_advisory"]["cve_id"] = None
    found["security_advisory"]["identifiers"] = None
    found["dependency"]["manifest_path"] = None
    found["security_vulnerability"] = None
    section, _ = compare(
        read(FakeGitHub({ALERTS_URL: ok([found])})), vulnerabilities, inventory.dependencies
    )
    assert section["alerts"][0] == {
        "number": 16,
        "advisory": "GHSA-qpw4-5x99-6vjp",
        "ecosystem": "go",
        "package": "golang.org/x/crypto",
        "manifest": "",
        "fixed_version": None,
        "result": "unmatched",
    }


def nuget_entry(dep_id, file):
    return {
        "id": dep_id,
        "ecosystem": "nuget",
        "name": "Some.Package",
        "current": "1.0.0",
        "origin": "locked" if dep_id.startswith("locked:") else "declared",
        **({"locked_because": "drift"} if dep_id.startswith("locked:") else {}),
        "location": {"file": file},
        "lookup": {"state": "skipped", "reason": "Not looked up in this test."},
    }


CENTRAL = nuget_entry("nuget:Directory.Packages.props:Some.Package", "Directory.Packages.props")
PROJECT = nuget_entry("nuget:src/App/App.csproj:Some.Package", "src/App/App.csproj")
LOCKED = nuget_entry("locked:src/App/packages.lock.json:Some.Package", "src/App/packages.lock.json")
OTHER = nuget_entry(
    "locked:src/Other/packages.lock.json:Some.Package", "src/Other/packages.lock.json"
)


def nuget_vulnerability(entry):
    return {
        "advisory": "GHSA-aaaa-bbbb-cccc",
        "dependency": entry["id"],
        "affected_version": "1.0.0",
        "fixed_version": None,
        "source": "osv",
        "reachability": "unknown",
    }


def nuget_alert(name="some.package", ecosystem="nuget"):
    return {
        "number": 3,
        "dependency": {
            "package": {"ecosystem": ecosystem, "name": name},
            "manifest_path": "src/App/App.csproj",
        },
        "security_advisory": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": None},
    }


@pytest.mark.parametrize(
    ("in_scan", "result", "cited"),
    [
        # The lock file beside the alert's project file goes before the central version.
        ([CENTRAL, LOCKED, OTHER], "matched", [LOCKED["id"]]),
        ([CENTRAL, PROJECT], "matched", [PROJECT["id"]]),
        # Only other files: still a match, but one that says so.
        ([CENTRAL, OTHER], "matched_elsewhere", [CENTRAL["id"], OTHER["id"]]),
    ],
)
def test_matches_in_the_alerts_file_go_first(record_from, in_scan, result, cited):
    dependencies = [CENTRAL, PROJECT, LOCKED, OTHER]
    vulnerabilities = [nuget_vulnerability(e) for e in in_scan]
    section, found = compare(alerts(nuget_alert()), vulnerabilities, dependencies)
    assert section["alerts"][0]["result"] == result
    assert section["alerts"][0]["dependency"] == PROJECT["id"]
    assert [v["dependency"] for v in found if v.get("dependabot_alerts") == [3]] == cited
    assert validate_record(record(record_from, Inventory(dependencies, []), found, section)) == []


def test_pip_names_compare_as_pep_503_normalises_them():
    entry = nuget_entry("pypi:src/App/App.csproj:PyJWT", "src/App/App.csproj") | {
        "ecosystem": "pypi",
        "name": "Py_JWT.crypto",
    }
    vulnerability = nuget_vulnerability(entry)
    section, _ = compare(alerts(nuget_alert("py-jwt-Crypto", "pip")), [vulnerability], [entry])
    assert section["alerts"][0]["result"] == "matched"
    assert section["alerts"][0]["dependency"] == entry["id"]
    section, _ = compare(alerts(nuget_alert("pyjwt-crypto", "pip")), [vulnerability], [entry])
    assert section["alerts"][0]["result"] == "unmatched"


def test_redirects_are_followed_only_within_the_api():
    redirecting = [
        h for h in dependabot._OPENER.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
    ]
    assert [type(h) for h in redirecting] == [dependabot._WithinApi]
    handler = dependabot._WithinApi()
    request = urllib.request.Request(ALERTS_URL, headers={"Authorization": f"Bearer {TOKEN}"})
    moved = "https://api.github.com/repositories/1/dependabot/alerts"
    followed = handler.redirect_request(request, None, 301, "Moved", {}, moved)
    assert followed.full_url == moved
    assert followed.get_header("Authorization") == f"Bearer {TOKEN}"
    for elsewhere in (
        "https://example.com/alerts",
        "http://api.github.com/repos/x/y",
        "https://api.github.com.example.com/x",
    ):
        assert handler.redirect_request(request, None, 302, "Found", {}, elsewhere) is None


def test_get_turns_an_http_error_into_a_response(monkeypatch):
    sent = []

    def refuse(request, timeout):
        sent.append(request)
        headers = Message()
        headers["X-RateLimit-Remaining"] = "0"
        raise urllib.error.HTTPError(
            request.full_url, 403, "Forbidden", headers, _Body(b'{"message": "rate"}')
        )

    monkeypatch.setattr(dependabot._OPENER, "open", refuse)
    response = dependabot.get(ALERTS_URL, TOKEN)
    assert response == Response(403, {"x-ratelimit-remaining": "0"}, b'{"message": "rate"}')
    assert sent[0].get_method() == "GET"
    assert sent[0].get_header("Authorization") == f"Bearer {TOKEN}"


class _Body:
    def __init__(self, data):
        self.data = data

    def read(self, *args):
        data, self.data = self.data, b""
        return data

    def close(self):
        pass
