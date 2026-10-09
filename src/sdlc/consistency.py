"""Flag a logical dependency whose declarations in different files disagree.

The Go toolchain, for example, is declared by go.mod, by `setup-go` in the workflows and by
the `golang` build image. Renovate updates each on its own, so they drift apart: a Dockerfile
that builds with Go 1.27 while go.mod and CI stay on 1.25 ships a binary nothing tested.

Which declarations belong together is listed by hand in ALIASES (design decision 6): inferring
it would match unrelated packages, and there are only a few. Extend the table when a missed
inconsistency turns up.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sdlc import renovate

# A version as declared: numbers separated by dots, compared as far as the declaration goes.
VERSION = r"v?(?P<version>\d+(?:\.\d+)*)"
# Anything after the version in an image tag, such as `-alpine` or `-noble-chiseled`.
TAG_SUFFIX = r"(?:-.+)?"
# An SDK version may end in a feature band instead: `10.0.1xx`, or `10.0.x` for any band.
SDK_VERSION = rf"{VERSION}(?:\.(?:x|(?P<band>\d)xx))?"

# Roles within one alias. Declarations in different roles compare at major.minor only.
SDK = "sdk"
RUNTIME = "runtime"


@dataclass(frozen=True)
class Matcher:
    """Which inventory entries declare an alias, and how to read their version.

    `name` must match the entry's depName or packageName in full (for an image Renovate
    couldn't name, the image in the text it would replace); `manager` and `datasource`
    narrow it down when set. `value` must match the declared value in full, and its
    `version` group is what gets compared. `line` finds the declaring line when Renovate
    doesn't say which it is: `{value}` stands for the declared value, `{directive}` for the
    go.mod directive.
    """

    name: str
    manager: str | None = None
    datasource: str | None = None
    value: str = VERSION
    line: str | None = None
    role: str | None = None


@dataclass(frozen=True)
class Alias:
    """One logical dependency and the matchers for every way it is declared.

    A declaration with fewer than `minimum_parts` version parts, such as Go `1.x`, floats
    to the newest release: it doesn't say which version it gets, so it can't agree.
    """

    name: str
    matchers: list[Matcher]
    minimum_parts: int = 1


# The Docker Hub library image, also through the registries that mirror it.
HUB_LIBRARY = (
    r"(?:(?:(?:index|registry-1)\.)?docker\.io/(?:library/)?|library/"
    r"|mirror\.gcr\.io/(?:library/)?|public\.ecr\.aws/docker/library/)?"
)

ALIASES = [
    Alias(
        "Go toolchain",
        [
            # go.mod's `toolchain` directive, or its `go` directive when there is none (see
            # renovate.go_toolchains). Renovate names both `go`.
            Matcher(
                "go",
                manager="gomod",
                value=rf"(?:go)?{VERSION}",
                line=r"^\s*{directive}\s+(?:go)?{value}(?![\w.])",
            ),
            # `go-version` of actions/setup-go, which Renovate looks up in actions/go-versions.
            # `1.25.x` means the same as `1.25`; a range such as `^1.25` isn't one version.
            Matcher(
                "actions/go-versions",
                manager="github-actions",
                value=rf"{VERSION}(?:\.x)?",
                line=r"^\s*(?:-\s+)?go-version:\s*[\"']?{value}[\"']?\s*(?:#.*)?$",
            ),
            # The official image, wherever it is used: `golang:1.27-alpine` declares 1.27.
            Matcher(f"{HUB_LIBRARY}golang", datasource="docker", value=VERSION + TAG_SUFFIX),
        ],
        minimum_parts=2,
    ),
    Alias(
        ".NET",
        [
            # SDK declarations compare with each other at their own precision, with the third
            # part read as a feature band and a patch: 10.0.401 is band 4, patch 1, and agrees
            # with 10.0.4xx but not with 10.0.1xx. Against the runtime they compare at
            # major.minor only: SDK 10.0.4xx builds for runtime 10.0.x, whose third part is a
            # patch that counts something else. Building with one major.minor and running on
            # another is the inconsistency that matters across the two.
            #
            # `dotnet-version` of actions/setup-dotnet and the SDK in global.json.
            Matcher(
                "dotnet-sdk",
                datasource="dotnet-version",
                value=SDK_VERSION,
                line=r"^\s*(?:-\s+)?(?:dotnet-version:\s*[\"']?|\"version\"\s*:\s*\"){value}"
                r"(?![\w.])",
                role=SDK,
            ),
            Matcher(
                r"mcr\.microsoft\.com/dotnet/sdk",
                datasource="docker",
                value=SDK_VERSION + TAG_SUFFIX,
                role=SDK,
            ),
            # The runtime images: `mcr.microsoft.com/dotnet/aspnet:10.0-alpine` declares 10.0.
            # Other images under dotnet/, such as the Aspire dashboard, carry their own
            # versions.
            Matcher(
                r"mcr\.microsoft\.com/dotnet/(?:aspnet|runtime|runtime-deps)",
                datasource="docker",
                value=VERSION + TAG_SUFFIX,
                role=RUNTIME,
            ),
            # The devcontainer image: `2.2.3-10.0-noble` is image version 2.2.3 with .NET 10.0.
            # It ships an SDK, but its tag only names the line, so it compares like a runtime.
            Matcher(
                r"mcr\.microsoft\.com/devcontainers/dotnet",
                datasource="docker",
                value=rf"(?:\d+(?:\.\d+)*-)?{VERSION}{TAG_SUFFIX}",
                role=RUNTIME,
            ),
        ],
        minimum_parts=2,
    ),
    Alias(
        "Aspire",
        [
            # The AppHost SDK: `<Project Sdk="Aspire.AppHost.Sdk/13.5.4">` or an <Sdk> element.
            Matcher(
                "Aspire.AppHost.Sdk",
                datasource="nuget",
                line=r"Aspire\.AppHost\.Sdk(?:/|\"\s+Version=\"){value}(?![\w.])",
            ),
            # The Aspire CLI the devcontainer installs as a .NET tool.
            Matcher("Aspire.Cli", datasource="nuget"),
        ],
    ),
]

# The go.mod directive Renovate's dependency type stands for.
DIRECTIVES = {"golang": "go", "toolchain": "toolchain"}


@dataclass
class Result:
    inconsistencies: list[dict[str, Any]] = field(default_factory=list)
    # Declarations that can't be compared, as coverage gaps: never counted as agreeing.
    gaps: list[dict[str, Any]] = field(default_factory=list)
    # Per alias, the ids of the declarations compared; empty when nothing declares it.
    compared: dict[str, list[str]] = field(default_factory=dict)


def check(
    report: dict,
    dependencies: list[dict[str, Any]],
    *,
    checkout: Path | None = None,
    aliases: list[Alias] = ALIASES,
) -> Result:
    """Compare the declarations of every alias, at the precision each one declares.

    Only entries in Renovate's report count as declarations; their locations come from the
    inventory. Of go.mod's directives only the one that sets the toolchain counts: `go
    1.25.0` beside `toolchain go1.25.14` is a minimum, not a disagreement.
    """
    result = Result()
    lines = _Lines(checkout)
    located = {d["id"]: d for d in dependencies}
    toolchains = set(renovate.go_toolchains(report).values())
    reported = renovate.entries(report)
    for alias in aliases:
        declarations = []
        for dep_id, (manager, dep) in reported.items():
            names, value = _declared(dep)
            matcher = _matcher(alias, manager, dep, names)
            if matcher is None or dep_id not in located:
                continue
            if manager == "gomod" and dep_id not in toolchains:
                continue
            entry = located[dep_id]
            found = re.fullmatch(matcher.value, value or "")
            parts = _parts(found) if found else ()
            if len(parts) < alias.minimum_parts:
                reason = _skip_reason(value, floats=bool(found))
                result.gaps.append(
                    {
                        "kind": "unparseable_source",
                        "subject": entry["location"]["file"],
                        "reason": f"{alias.name}: {names[0] if names else entry['name']} "
                        f"{reason}, so the consistency check skips it.",
                    }
                )
                continue
            location = dict(entry["location"])
            if "line" not in location and matcher.line and value:
                pattern = matcher.line.format(
                    value=re.escape(value), directive=DIRECTIVES.get(dep.get("depType"), "go")
                )
                line = lines.find(location["file"], pattern)
                if line:
                    location["line"] = line
            declarations.append(
                (
                    {"dependency": dep_id, "location": location, "version": found["version"]},
                    _comparable(found, matcher.role),
                    matcher.role,
                )
            )
        result.compared[alias.name] = [d["dependency"] for d, _, _ in declarations]
        if any(
            not agree(a, b, same_role=ra == rb)
            for i, (_, a, ra) in enumerate(declarations)
            for _, b, rb in declarations[i + 1 :]
        ):
            result.inconsistencies.append(
                {"dependency": alias.name, "declarations": [d for d, _, _ in declarations]}
            )
    return result


def agree(a: tuple[int, ...], b: tuple[int, ...], *, same_role: bool = True) -> bool:
    """Whether two versions are the same as far as both declare: 1.25 agrees with 1.25.14.

    Across roles, such as an SDK and a runtime, only major.minor counts.
    """
    common = min(len(a), len(b)) if same_role else min(len(a), len(b), 2)
    return a[:common] == b[:common]


def _parts(found: re.Match) -> tuple[int, ...]:
    return tuple(int(p) for p in found["version"].split("."))


def _comparable(found: re.Match, role: str | None) -> tuple[int, ...]:
    """The version as compared: an SDK's third part splits into its feature band and patch."""
    parts = _parts(found)
    if role != SDK:
        return parts
    if found.groupdict().get("band"):
        return (*parts, int(found["band"]))
    if len(parts) >= 3:
        return (*parts[:2], parts[2] // 100, parts[2] % 100, *parts[3:])
    return parts


def _declared(dep: dict) -> tuple[list[str], str | None]:
    """The names an entry goes by, and its declared value.

    Renovate leaves an image it can't resolve, such as `golang:${GO_VERSION}-alpine`,
    without a name or value; the text it would replace still names the image.
    """
    names = [n for n in (dep.get("depName"), dep.get("packageName")) if n]
    value = dep.get("currentValue")
    if not names and dep.get("datasource") == "docker" and dep.get("replaceString"):
        image, _, tag = dep["replaceString"].split("@")[0].rpartition(":")
        if image and "/" not in tag:
            names, value = [image], tag
    return names, value or dep.get("currentDigest")


def _matcher(alias: Alias, manager: str, dep: dict, names: list[str]) -> Matcher | None:
    for matcher in alias.matchers:
        if matcher.manager and manager != matcher.manager:
            continue
        if matcher.datasource and dep.get("datasource") != matcher.datasource:
            continue
        # NuGet ids aren't case-sensitive; neither is anything else in the table in practice.
        if any(re.fullmatch(matcher.name, n, re.IGNORECASE) for n in names):
            return matcher
    return None


def _skip_reason(value: str | None, *, floats: bool) -> str:
    if not value:
        return "declares no version"
    if "${" in value:
        return f"declares {value!r}, a variable the scan can't resolve"
    if value.startswith("sha256:"):
        return "is pinned by digest only, which has no version to compare"
    if floats:
        return f"declares {value!r}, which floats to the newest release"
    return f"declares {value!r}, which isn't one version"


class _Lines:
    """Find a declaring line by pattern; the same pattern twice in a file gets the next line."""

    def __init__(self, checkout: Path | None):
        self.checkout = checkout
        self.used: dict[tuple[str, str], int] = {}

    def find(self, file: str, pattern: str) -> int | None:
        if self.checkout is None:
            return None
        path = self.checkout / file
        if not path.is_file():
            return None
        text = path.read_text(errors="replace").splitlines()
        matches = [i for i, line in enumerate(text, 1) if re.search(pattern, line)]
        nth = self.used.get((file, pattern), 0)
        self.used[(file, pattern)] = nth + 1
        return matches[nth] if nth < len(matches) else None
