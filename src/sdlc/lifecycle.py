"""Report whether the platforms, toolchains and base images in use still get support.

Renovate knows versions, not support windows: staying on a line that no longer gets security
fixes, such as Go 1.25 once 1.27 was out, looks the same to it as being current within that
line. The lifecycle data comes from endoflife.date (design decision 6a), linked to inventory
entries by the table in MAPPINGS. Each line in use is:
- `end_of_life` when the data says it ended, or its end-of-life date has passed;
- `nearing_end_of_life` when that date is within 90 days of the scan;
- `supported` otherwise, with its date when one is published;
- `unknown` when there is no data for it: the entry has no mapping, its declared value names
  no line (`latest`, a variable, a bare `-alpine`), the product's data lacks the line or the
  codename, or the API couldn't be read. Never supported.

The record lists one result per product and line, with the inventory entries and locations
that use it. An entry of a kind that could have lifecycle data (a base image, or a runtime
declaration such as setup-go or `runs-on`) that no mapping covers is listed as `unknown`
under its own name. Packages are not: their support is their maintainers' release practice,
which endoflife.date doesn't track for them.

endoflife.date needs no account, so no token is ever sent to it. An unreachable API, an
error status or malformed data makes every line of the affected products `unknown`, with an
`unavailable_source` gap, and the scan carries on.
"""

import http.client
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sdlc import consistency, renovate
from sdlc.consistency import HUB_LIBRARY, TAG_SUFFIX, VERSION, Matcher
from sdlc.dependabot import Response

# The current API. Its product data is `result.releases[]`, each with `name` (the line, such
# as 1.25), `codename` (such as "Noble Numbat"), `releaseDate`, `isEol` and `eolFrom` (a date,
# or null when none is published). The older /api/<product>.json, with `cycle` and an `eol`
# that is a date or a boolean, still answers but is the legacy one.
API = "https://endoflife.date/api/v1"
SOURCE = "endoflife.date"
SUBJECT = "endoflife.date"  # the gap's subject when the data can't be read
NEARING = timedelta(days=90)
TIMEOUT = 30

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Words in image tags that name a variant of the image, not the OS release it is built on.
VARIANTS = (
    "bare|chiseled|composite|debug|dev|extra|full|headless|jdk|jre|minimal|nanoserver"
    "|nonroot|preview|slim|windowsservercore"
)
# Tags that follow a moving release rather than naming one.
FLOATING = {"devel", "latest", "oldstable", "rolling", "sid", "stable", "testing", "unstable"}
# A codename in an image tag, after its version and any variant words: `1.25-bookworm`,
# `3.12-slim-bookworm`, `10.0-noble-chiseled`, and the devcontainer's `2.2.3-10.0-noble`.
CODENAME_SUFFIX = (
    rf"(?:[^-]*-)*?\d[^-]*-(?:(?:{VARIANTS})-)*"
    rf"(?P<codename>(?!(?:{VARIANTS}|alpine)(?:-|$))[a-z]+)(?:-.+)?"
)
# A setup action's version: `3.12`, or `3.12.x` for the newest patch.
SETUP_VERSION = rf"{VERSION}(?:\.x)?"


def _major_minor(parts: tuple[int, ...]) -> str | None:
    return ".".join(map(str, parts[:2])) if len(parts) >= 2 else None


def _major(parts: tuple[int, ...]) -> str | None:
    return str(parts[0]) if parts else None


def _ubuntu(parts: tuple[int, ...]) -> str | None:
    """Ubuntu names lines year.month, with the month in two digits: 22.04, not 22.4."""
    return f"{parts[0]}.{parts[1]:02d}" if len(parts) >= 2 else None


def _dotnet(parts: tuple[int, ...]) -> str | None:
    """.NET 5 and later are named by major alone: 10.0 is line 10. .NET Core 3.1 is 3.1."""
    if parts and parts[0] >= 5:
        return str(parts[0])
    return _major_minor(parts)


@dataclass(frozen=True)
class Mapping:
    """Which inventory entries use an endoflife.date product, and how to read their line.

    `matcher` selects entries and reads the version as the consistency check does: its
    `version` group, from the declared value, or from the image name when `in_name` is set.
    `cycle` turns the version into the product's line name, or None when the version is too
    imprecise to name one, such as Go `1`, which floats to the newest release.

    A `codename` group is looked up instead among the `codename`s of the products in
    `codenames`, by its first word in lower case: Ubuntu's "Noble Numbat" is `noble`.

    A `suffix` mapping reads the OS another image is built on from its tag. It applies only
    when its pattern matches, and doesn't cover the image itself: `node:20-alpine3.22` is
    Alpine 3.22 as well as Node.js 20. Its `suffix` group is the line as declared, for when
    it names no release.
    """

    product: str
    matcher: Matcher
    cycle: Callable[[tuple[int, ...]], str | None] = _major_minor
    in_name: bool = False
    suffix: bool = False
    codenames: tuple[str, ...] = ()


def _alias(name: str) -> consistency.Alias:
    return next(a for a in consistency.ALIASES if a.name == name)


def _image(name: str, value: str = VERSION + TAG_SUFFIX) -> Matcher:
    """The official image of that name, from Docker Hub or a mirror."""
    return Matcher(f"{HUB_LIBRARY}{name}", datasource="docker", value=value)


MAPPINGS = [
    # The Go toolchain, read as the consistency check reads it: go.mod's directive that sets
    # the toolchain, setup-go's go-version and golang image tags. Go names lines major.minor.
    *(Mapping("go", m) for m in _alias("Go toolchain").matchers),
    # .NET: setup-dotnet and global.json, the sdk, aspnet, runtime and runtime-deps images,
    # and the .NET line in the devcontainer image's tag, as the consistency check reads them.
    *(Mapping("dotnet", m, cycle=_dotnet) for m in _alias(".NET").matchers),
    # The official python image: python:3.12-alpine is Python 3.12.
    Mapping("python", _image("python")),
    # setup-python's python-version, which Renovate looks up in actions/python-versions.
    Mapping("python", Matcher("actions/python-versions", "github-actions", value=SETUP_VERSION)),
    # The official node image and setup-node's node-version: Node.js names lines by major.
    Mapping("nodejs", _image("node"), cycle=_major),
    Mapping(
        "nodejs",
        Matcher("actions/node-versions", "github-actions", value=SETUP_VERSION),
        cycle=_major,
    ),
    # The official alpine image: alpine:3.22 and alpine:3.22.1 are Alpine 3.22. endoflife.date
    # calls the product alpine-linux; /products/alpine redirects there.
    Mapping("alpine-linux", _image("alpine", VERSION)),
    # The official debian image: debian:12, debian:12.7-slim, debian:bookworm-slim.
    Mapping(
        "debian",
        _image("debian", rf"(?:{VERSION}|(?P<codename>[a-z]+))(?:-.+)?"),
        cycle=_major,
        codenames=("debian",),
    ),
    # The official ubuntu image: ubuntu:24.04, ubuntu:noble. Its line ends with standard
    # support (`eolFrom`); Ubuntu Pro's extended support isn't counted.
    Mapping(
        "ubuntu",
        _image("ubuntu", rf"(?:{VERSION}|(?P<codename>[a-z]+))(?:-.+)?"),
        cycle=_ubuntu,
        codenames=("ubuntu",),
    ),
    # The Alpine another image is built on, from its tag: golang:1.25-alpine3.22 is Alpine
    # 3.22. A bare -alpine names no release: it follows whichever one the image was last
    # built on, so its line is unknown rather than guessed.
    Mapping(
        "alpine-linux",
        Matcher(
            r".+", datasource="docker", value=rf"(?:.+-)?(?P<suffix>alpine(?:{VERSION})?)(?:-.+)?"
        ),
        suffix=True,
    ),
    # The Debian or Ubuntu release another image is built on, from the codename in its tag:
    # python:3.12-slim-bookworm is Debian 12, aspnet:10.0-noble-chiseled Ubuntu 24.04. A word
    # that neither product has as a codename is unknown, not skipped.
    Mapping(
        "debian/ubuntu",
        Matcher(r".+", datasource="docker", value=CODENAME_SUFFIX),
        suffix=True,
        codenames=("debian", "ubuntu"),
    ),
    # Distroless images name their Debian release: gcr.io/distroless/static-debian12 is
    # Debian 12. One without -debianN follows distroless's default, so it names no release.
    Mapping(
        "debian",
        Matcher(
            r"gcr\.io/distroless/.+",
            datasource="docker",
            value=r"gcr\.io/distroless/.+?(?:-debian(?P<version>\d+))?",
        ),
        cycle=_major,
        in_name=True,
    ),
]

# Entries of these kinds could have lifecycle data, so one no mapping covers is `unknown`.
# Runtime declarations, by datasource: go.mod's directive, setup-dotnet, `runs-on` labels.
RUNTIMES = {
    "dotnet-version",
    "github-runners",
    "golang-version",
    "java-version",
    "node-version",
    "python-version",
    "ruby-version",
}
# Versions setup actions install, which Renovate looks up in GitHub's actions/*-versions.
SETUP_ACTIONS = r"actions/[\w-]+-versions"
# Images, by the managers that read where images are used. Other docker-datasource entries
# are OCI artifacts, such as Bicep modules, or devcontainer features.
IMAGE_MANAGERS = {"dockerfile", "docker-compose", "devcontainer", "github-actions", "kubernetes"}


class Unavailable(Exception):
    """A product's lifecycle data can't be read; the message says why."""


class Unreachable(Unavailable):
    """endoflife.date can't be reached at all, so no other product is tried."""


@dataclass
class Result:
    # The record's lifecycle section: one entry per product and line in use.
    lifecycle: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    # One tool entry per product whose data was read, with the time it was.
    tools: list[dict[str, str]] = field(default_factory=list)


class _WithinApi(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only within the API, as when a product is renamed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith(f"{API}/"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_WithinApi())


def get(url: str) -> Response:
    """One GET without credentials. An HTTP error is a response; a network error raises."""
    request = urllib.request.Request(  # noqa: S310 - only API URLs, built here
        url, headers={"Accept": "application/json", "User-Agent": "sdlc-scan"}
    )
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            return Response(response.status, {}, response.read())
    except urllib.error.HTTPError as error:
        return Response(error.code, {}, error.read())


def releases(product: str, *, get: Callable[[str], Response] = get) -> list[dict[str, Any]]:
    """The product's lines as endoflife.date lists them, newest first."""
    url = f"{API}/products/{product}"
    try:
        response = get(url)
    except OSError as error:  # URLError, timeouts, refused connections
        reason = getattr(error, "reason", None) or error
        raise Unreachable(f"endoflife.date couldn't be reached: {reason}.") from error
    except http.client.HTTPException as error:  # a cut-off or garbled answer
        raise Unavailable(f"endoflife.date's answer for {product} broke off: {error!r}.") from error
    if response.status != 200:
        raise Unavailable(f"endoflife.date answered {response.status} for {product}.")
    try:
        body = json.loads(response.body)
    except ValueError as error:
        raise Unavailable(f"endoflife.date's answer for {product} isn't JSON: {error}") from error
    result = body.get("result") if isinstance(body, dict) else None
    found = result.get("releases") if isinstance(result, dict) else None
    if not isinstance(found, list) or not all(_is_release(r) for r in found):
        raise Unavailable(f"endoflife.date's answer for {product} isn't a list of releases.")
    return found


def check(
    report: dict,
    dependencies: list[dict[str, Any]],
    *,
    scanned_at: datetime,
    get: Callable[[str], Response] = get,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Result:
    """The lifecycle of every line in use, against the scan's date.

    Only entries in Renovate's report count, with their locations from the inventory. Of
    go.mod's directives only the one that sets the toolchain counts, as for consistency.
    Each product is fetched once.
    """
    result = Result()
    uses = _uses(report, {d["id"]: d for d in dependencies})
    needed = [u.product for u in uses if u.cycle is not None and u.mapped]
    needed += [p for u in uses if u.codename for p in u.codenames]

    data: dict[str, list[dict[str, Any]]] = {}
    failed: dict[str, str] = {}
    unreachable = None
    for product in dict.fromkeys(needed):
        if unreachable:
            failed[product] = unreachable
            continue
        try:
            data[product] = releases(product, get=get)
        except Unavailable as error:
            failed[product] = str(error)
            # One gap when the API can't be reached at all, otherwise one per product.
            if isinstance(error, Unreachable):
                unreachable = str(error)
            result.gaps.append(
                {"kind": "unavailable_source", "subject": SUBJECT, "reason": str(error)}
            )
            continue
        result.tools.append(
            {
                "name": SOURCE,
                "version": "v1",
                "url": f"{API}/products/{product}",
                "fetched_at": now().isoformat(timespec="seconds"),
            }
        )

    today = scanned_at.astimezone(UTC).date()
    # An unmapped entry's "product" is its own name, which mustn't join a mapped product's line.
    grouped: dict[tuple[str, str, bool], dict[str, Any]] = {}
    for use in (_resolve(u, data, failed) if u.codename else u for u in uses):
        key = (use.product, use.line, use.mapped)
        if key not in grouped:
            grouped[key] = {"product": use.product, "line": use.line} | _state(
                use, data, failed, today
            )
            grouped[key] |= {"dependencies": [], "locations": []}
        entry = grouped[key]
        if use.dependency["id"] not in entry["dependencies"]:
            entry["dependencies"].append(use.dependency["id"])
            entry["locations"].append(use.dependency["location"])
    result.lifecycle = list(grouped.values())
    return result


@dataclass(frozen=True)
class _Use:
    """One inventory entry using one product's line."""

    product: str
    line: str
    cycle: str | None  # None when the declaration names no line; `reason` says why
    dependency: dict[str, Any]
    mapped: bool = True
    reason: str | None = None
    # A codename still to be looked up among these products' releases.
    codename: str | None = None
    codenames: tuple[str, ...] = ()


def _uses(report: dict, located: dict[str, dict[str, Any]]) -> list[_Use]:
    toolchains = set(renovate.go_toolchains(report).values())
    uses = []
    for dep_id, (manager, dep) in renovate.entries(report).items():
        if dep_id not in located:
            continue
        if (
            manager == "gomod"
            and dep.get("datasource") == "golang-version"
            and dep_id not in toolchains
        ):
            continue  # a minimum beside the toolchain directive, not what builds
        entry = located[dep_id]
        names, value = consistency.declared(dep)
        primary = False
        for mapping in MAPPINGS:
            if primary and not mapping.suffix:
                continue  # one product per image or declaration, besides the OS it's built on
            if not mapping.matcher.matches(manager, dep, names):
                continue
            use = _read(mapping, names, value, entry)
            if use is None:
                continue
            primary = primary or not mapping.suffix
            uses.append(use)
        if not primary and _could_have_lifecycle(manager, dep):
            name = names[0] if names else entry["name"]
            uses.append(
                _Use(
                    name,
                    value or "(no version)",
                    None,
                    entry,
                    mapped=False,
                    reason="No lifecycle mapping: the table in sdlc/lifecycle.py doesn't link "
                    "it to an endoflife.date product.",
                )
            )
    return uses


def _read(
    mapping: Mapping, names: list[str], value: str | None, entry: dict[str, Any]
) -> _Use | None:
    """The line a mapped entry uses, or None when a suffix mapping doesn't apply."""
    text = next((n for n in names if re.fullmatch(mapping.matcher.name, n, re.IGNORECASE)), None)
    if not mapping.in_name:
        text = value
    found = re.fullmatch(mapping.matcher.value, text or "")
    if mapping.suffix and not found:
        return None
    groups = found.groupdict() if found else {}
    codename = groups.get("codename")
    if codename and codename not in FLOATING:
        return _Use(
            mapping.product, codename, None, entry, codename=codename, codenames=mapping.codenames
        )
    version = groups.get("version")
    cycle = mapping.cycle(tuple(int(p) for p in version.split("."))) if version else None
    if cycle is not None:
        return _Use(mapping.product, cycle, cycle, entry)
    if mapping.suffix:
        line = found["suffix"]
        reason = f"{line!r} names no release: it follows whichever one the image was last built on."
    elif mapping.in_name:
        line = text or entry["name"]
        reason = f"{line} names no release: it follows the image's default."
    else:
        line = value or "(no version)"
        shown = names[0] if names else entry["name"]
        reason = (
            f"{shown} {consistency.skip_reason(value, floats=bool(found))}, so its line is unknown."
        )
    return _Use(mapping.product, line, None, entry, reason=reason)


def _resolve(use: _Use, data: dict[str, list[dict]], failed: dict[str, str]) -> _Use:
    """The release a codename names, by the first word of its products' codenames."""
    for product in use.codenames:
        for release in data.get(product, []):
            words = (release.get("codename") or "").split()
            if words and words[0].lower() == use.codename:
                name = release["name"]
                return replace(use, product=product, line=name, cycle=name, codename=None)
    unread = [failed[p] for p in use.codenames if p in failed]
    if unread:
        reason = " ".join(dict.fromkeys(unread))
    else:
        products = " or ".join(p.capitalize() for p in use.codenames)
        reason = (
            f"{use.codename!r} isn't the codename of a {products} release endoflife.date lists."
        )
    return replace(use, reason=reason, codename=None)


def _could_have_lifecycle(manager: str, dep: dict) -> bool:
    if dep.get("datasource") in RUNTIMES:
        return True
    if manager == "github-actions" and re.fullmatch(SETUP_ACTIONS, dep.get("packageName") or ""):
        return True
    return (
        dep.get("datasource") == "docker"
        and manager in IMAGE_MANAGERS
        and dep.get("depType") != "feature"
    )


def _state(
    use: _Use, data: dict[str, list[dict]], failed: dict[str, str], today: date
) -> dict[str, Any]:
    """The state of a line, with its date, the supported lines and where that came from."""
    if use.cycle is None:
        return {"state": "unknown", "reason": use.reason}
    if use.product in failed:
        return {"state": "unknown", "reason": failed[use.product]}
    lines = data[use.product]
    # Oldest first, so the first is the oldest supported line. The API lists newest first.
    oldest_first = sorted(reversed(lines), key=lambda r: r.get("releaseDate") or "")
    supported = [r["name"] for r in oldest_first if _supported(r, today)]
    known = {"supported_lines": supported, "source": f"{API}/products/{use.product}"}
    release = next((r for r in lines if r["name"] == use.cycle), None)
    if release is None:
        return {
            "state": "unknown",
            "reason": f"endoflife.date lists no {use.product} {use.cycle} line.",
        } | known
    eol = release.get("eolFrom")
    ends = date.fromisoformat(eol) if eol else None
    dated = {"end_of_life": eol} if eol else {}
    # `isEol` says the line has ended, and that holds even beside a later date: support can
    # stop before its announced end, and data that contradicts itself must never read as
    # supported. Without `isEol`, the date decides, because `isEol` was computed when the data
    # was generated, which may be before the scan.
    if release["isEol"]:
        if ends is None:
            reason = "endoflife.date marks it end of life without a date."
        elif ends > today:
            reason = f"endoflife.date marks it end of life, although its date, {eol}, is later."
        else:
            return {"state": "end_of_life"} | dated | known
        return {"state": "end_of_life", "reason": reason} | dated | known
    if ends is None:
        return {"state": "supported"} | known
    if ends <= today:
        state = "end_of_life"
    elif ends - today <= NEARING:
        state = "nearing_end_of_life"
    else:
        state = "supported"
    return {"state": state} | dated | known


def _supported(release: dict, today: date) -> bool:
    """Whether a line still gets support on the scan's date: not marked ended, nor past its
    date."""
    if release["isEol"]:
        return False
    eol = release.get("eolFrom")
    return eol is None or date.fromisoformat(eol) > today


def _is_release(release: Any) -> bool:
    if not isinstance(release, dict):
        return False
    name, eol, released = release.get("name"), release.get("eolFrom"), release.get("releaseDate")
    codename = release.get("codename")
    return (
        isinstance(name, str)
        and bool(name)
        and isinstance(release.get("isEol"), bool)
        and (eol is None or _is_date(eol))
        and (released is None or isinstance(released, str))
        and (codename is None or isinstance(codename, str))
    )


def _is_date(value: Any) -> bool:
    if not isinstance(value, str) or not _DATE.match(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True
