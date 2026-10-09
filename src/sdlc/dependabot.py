"""Read the subject's open Dependabot alerts and compare them with the scan's advisories.

Dependabot is the baseline the scan has to match (design decision 5), so its alerts are a
comparison source, the way its open PRs are, not findings of the scan. They describe the
repository's default branch as Dependabot last analysed it, which need not be the scanned
commit. So the record keeps them in a section of their own, with the branch they describe, its
head when they were read, whether that head is the scanned commit, and the time:
- an alert whose advisory (by GHSA or CVE id) the scan also found on the same package, in the
  alert's manifest or a file beside it, is `matched`;
- one the scan found on that package only in other files, such as a central version, is
  `matched_elsewhere`, so a match by package alone can be told apart;
- any other alert is `unmatched`, so the disagreement shows.
A matched vulnerability lists the alert's number as corroboration. Each alert also names the
inventory entry its package and manifest point to, when there is one.

Reading them needs a token with `Dependabot alerts: read`. Without one, or when the alerts
are disabled, rate limited, malformed or out of reach, the source is an `unavailable_source`
gap with the reason, and the record has no alerts section: it says nothing about what the
alerts would have said. Only GET requests are made; the scan never changes an alert.
"""

import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

API = "https://api.github.com"
SUBJECT = "dependabot-alerts"  # the gap's subject when the alerts can't be read
PERMISSION = "Dependabot alerts: read"
TIMEOUT = 30

_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class Unavailable(Exception):
    """A source on GitHub can't be read; the message says why."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]  # names in lower case
    body: bytes


@dataclass(frozen=True)
class Alerts:
    ref: str  # the default branch, which the alerts describe
    commit: str  # its head, read just before the alerts
    read_at: str
    alerts: list[dict[str, Any]]  # as the API returns them, one per number


class _WithinApi(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only within GitHub's API, so the token never goes to another host.

    A refused redirect comes back as its 3xx response, which makes the source unavailable.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _in_api(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_WithinApi())


def get(url: str, token: str) -> Response:
    """One GET to GitHub's REST API. An HTTP error is a response; a network error raises."""
    request = urllib.request.Request(  # noqa: S310 - only API URLs, checked by the caller
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            return Response(response.status, _lower(response.headers), response.read())
    except urllib.error.HTTPError as error:
        return Response(error.code, _lower(error.headers or {}), error.read())


def read(
    repository: str,
    token: str | None,
    *,
    get: Callable[[str, str], Response] = get,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Alerts:
    """The repository's open Dependabot alerts, every page, and the branch head they describe."""
    if not token:
        raise Unavailable(
            "No token in SDLC_GITHUB_TOKEN; reading Dependabot alerts needs one with "
            "Dependabot alerts: read."
        )
    repo = decode(fetch(get, f"{API}/repos/{repository}", token))
    ref = repo.get("default_branch") if isinstance(repo, dict) else None
    if not isinstance(ref, str) or not ref:
        raise Unavailable("GitHub's answer names no default branch for the alerts to describe.")
    branch = decode(
        fetch(get, f"{API}/repos/{repository}/branches/{urllib.parse.quote(ref, safe='')}", token)
    )
    commit = branch.get("commit") if isinstance(branch, dict) else None
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not _COMMIT.match(sha):
        raise Unavailable(f"GitHub's answer names no head commit for {ref}.")

    read_at = now().isoformat(timespec="seconds")
    alerts: dict[int, dict[str, Any]] = {}
    url: str | None = f"{API}/repos/{repository}/dependabot/alerts?state=open&per_page=100"
    fetched: set[str] = set()
    while url:
        if url in fetched:
            raise Unavailable(f"GitHub's pagination links back to a page already read: {url}")
        fetched.add(url)
        response = fetch(get, url, token)
        page = decode(response)
        if not isinstance(page, list) or not all(_is_alert(a) for a in page):
            raise Unavailable("GitHub's answer isn't a list of Dependabot alerts.")
        # An alert can move to the next page while the pages are read; it counts once.
        for alert in page:
            alerts.setdefault(alert["number"], alert)
        url = next_page(response.headers.get("link"))
    return Alerts(ref, sha, read_at, list(alerts.values()))


def compare(
    alerts: Alerts,
    vulnerabilities: list[dict[str, Any]],
    dependencies: list[dict[str, Any]],
    scanned_commit: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The record's alerts section, and the vulnerabilities with the alerts that match them.

    A vulnerability matches an alert when they share an advisory id or alias and its inventory
    entry is the alert's package. Vulnerabilities in the alert's manifest, or in a file beside
    it such as the lock file next to a project file, go first; only when there are none do
    those in other files count, and the alert is then `matched_elsewhere`.
    """
    entries = {d["id"]: d for d in dependencies}
    result = [dict(v) for v in vulnerabilities]
    section = []
    for alert in sorted(alerts.alerts, key=lambda a: a["number"]):
        advisory = alert["security_advisory"]
        dependency = alert["dependency"]
        package = dependency["package"]
        ecosystem, name = package.get("ecosystem") or "", package["name"]
        manifest = dependency.get("manifest_path") or ""
        ids = {
            advisory["ghsa_id"],
            advisory.get("cve_id"),
            *(i.get("value") for i in advisory.get("identifiers") or []),
        } - {None, ""}
        folded = {i.casefold() for i in ids}
        vulnerable = alert.get("security_vulnerability") or {}

        same_advisory = [
            (v, entries[v["dependency"]])
            for v in result
            if v["dependency"] in entries
            and _same_name(ecosystem, entries[v["dependency"]]["name"], name)
            and {n.casefold() for n in (v["advisory"], *v.get("aliases", []))} & folded
        ]
        here = [v for v, entry in same_advisory if _beside(entry["location"]["file"], manifest)]
        elsewhere = [v for v, _ in same_advisory]
        matching = here or elsewhere
        for vulnerability in matching:
            numbers = vulnerability.setdefault("dependabot_alerts", [])
            if alert["number"] not in numbers:
                numbers.append(alert["number"])

        found: dict[str, Any] = {
            "number": alert["number"],
            "advisory": advisory["ghsa_id"],
        }
        if aliases := sorted(ids - {advisory["ghsa_id"]}):
            found["aliases"] = aliases
        found |= {"ecosystem": ecosystem, "package": name, "manifest": manifest}
        listed = next(
            (
                d
                for d in dependencies
                if d["location"]["file"] == manifest and _same_name(ecosystem, d["name"], name)
            ),
            None,
        )
        if listed is not None:
            found["dependency"] = listed["id"]
        if vulnerable.get("vulnerable_version_range"):
            found["vulnerable_range"] = vulnerable["vulnerable_version_range"]
        found["fixed_version"] = (vulnerable.get("first_patched_version") or {}).get("identifier")
        found["result"] = "matched" if here else "matched_elsewhere" if elsewhere else "unmatched"
        section.append(found)
    return {
        "ref": alerts.ref,
        "commit": alerts.commit,
        "is_scanned_commit": alerts.commit == scanned_commit,
        "read_at": alerts.read_at,
        "alerts": section,
    }, result


def fetch(
    get: Callable[[str, str], Response],
    url: str,
    token: str,
    *,
    what: str = "Dependabot alerts",
    permission: str = PERMISSION,
) -> Response:
    """A 200 answer from GitHub's API, or Unavailable saying why there is none.

    `what` and `permission` name what is being read and the token permission it needs, so a
    refusal can say which is missing.
    """
    # The token goes to GitHub's API only, wherever a pagination link points.
    if not _in_api(url):
        raise Unavailable(f"GitHub's answer links to {url}, outside its API.")
    try:
        response = get(url, token)
    except OSError as error:  # URLError, timeouts, refused connections
        reason = getattr(error, "reason", None) or error
        raise Unavailable(f"GitHub's API couldn't be reached: {reason}.") from error
    except http.client.HTTPException as error:  # a cut-off or garbled answer
        raise Unavailable(f"GitHub's answer broke off: {error!r}.") from error
    if response.status != 200:
        raise Unavailable(_explain(response, what, permission))
    return response


def _explain(response: Response, what: str, permission: str) -> str:
    """Why GitHub refused, as far as its answer tells."""
    message = _message(response.body)
    said = f"GitHub answered {response.status}" + (f": {message}" if message else "")
    headers = response.headers
    if 300 <= response.status < 400:
        where = headers.get("location", "elsewhere")
        return f"GitHub redirected to {where}, outside its API, so it wasn't followed ({said})."
    if response.status in (403, 429) and (
        headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers
    ):
        when = ""
        if headers.get("x-ratelimit-reset", "").isdigit():
            reset = datetime.fromtimestamp(int(headers["x-ratelimit-reset"]), UTC)
            when = f", until {reset.isoformat(timespec='seconds')}"
        elif headers.get("retry-after"):
            when = f", for {headers['retry-after']} seconds"
        return f"GitHub's rate limit was reached{when} ({said})."
    if "disabled" in message.casefold():
        return f"{what[:1].upper()}{what[1:]} are disabled for the repository ({said})."
    if response.status == 401:
        return f"GitHub rejected the token ({said})."
    if response.status == 403 and "not accessible" in message.casefold():
        return f"The token lacks the {permission} permission ({said})."
    if response.status == 404:
        return (
            f"The repository or its {what} aren't visible to the token: it may lack "
            f"{permission} ({said})."
        )
    return f"{said}."


def _message(body: bytes) -> str:
    try:
        message = json.loads(body).get("message")
    except (ValueError, AttributeError):
        return ""
    return message.strip() if isinstance(message, str) else ""


def decode(response: Response) -> Any:
    try:
        return json.loads(response.body)
    except ValueError as error:
        raise Unavailable(f"GitHub's answer isn't JSON: {error}") from error


def next_page(link: str | None) -> str | None:
    match = _NEXT.search(link or "")
    return match.group(1) if match else None


def _in_api(url: str) -> bool:
    return url.startswith(f"{API}/")


def _is_alert(alert: Any) -> bool:
    """Whether every field the comparison reads has the type it expects."""
    if not isinstance(alert, dict):
        return False
    number = alert.get("number")
    advisory = alert.get("security_advisory")
    dependency = alert.get("dependency")
    vulnerable = alert.get("security_vulnerability")
    if not (
        isinstance(number, int)
        and not isinstance(number, bool)
        and number >= 1
        and isinstance(advisory, dict)
        and isinstance(dependency, dict)
        and _optional(vulnerable, dict)
    ):
        return False
    package = dependency.get("package")
    identifiers = advisory.get("identifiers")
    patched = (vulnerable or {}).get("first_patched_version")
    return bool(
        _text(advisory.get("ghsa_id"))
        and _optional(advisory.get("cve_id"), str)
        and _optional(identifiers, list)
        and all(isinstance(i, dict) and _optional(i.get("value"), str) for i in identifiers or [])
        and isinstance(package, dict)
        and _text(package.get("name"))
        and _optional(package.get("ecosystem"), str)
        and _optional(dependency.get("manifest_path"), str)
        and _optional((vulnerable or {}).get("vulnerable_version_range"), str)
        and _optional(patched, dict)
        and _optional((patched or {}).get("identifier"), str)
    )


def _optional(value: Any, kind: type) -> bool:
    return value is None or isinstance(value, kind)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _beside(file: str, manifest: str) -> bool:
    """Whether the scan's file is the alert's manifest, or in the same directory."""
    return file == manifest or PurePosixPath(file).parent == PurePosixPath(manifest).parent


def _lower(headers: Mapping[str, str] | Any) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _same_name(ecosystem: str, a: str, b: str) -> bool:
    if ecosystem == "nuget":  # NuGet package ids are case-insensitive
        return a.casefold() == b.casefold()
    if ecosystem == "pip":  # PEP 503: case, and runs of -, _ and ., don't matter
        return _pep503(a) == _pep503(b)
    return a == b


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()
