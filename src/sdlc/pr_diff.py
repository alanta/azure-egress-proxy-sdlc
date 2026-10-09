"""Read the versions a Dependabot PR's diff removes, for updates its text gives no from-version.

Some NuGet PRs, like #98, state only the version they move to ("Bumps Azure.Core to 1.63.0"),
because the dependency has several versions in the repository: a central one, and older ones
in lock files. Dependabot writes the diff's version lines mechanically, so the removed lines
say what each file had.

The diff is upstream data like the PR's text (design decision 9). Only removed lines are read,
only in files the scan knows, and only by fixed patterns per file type:
- `Directory.Packages.props`: `<PackageVersion Include="x" Version="1.2.3" />`;
- `*.csproj`: `<PackageReference Include="x" Version="1.2.3" />`, or `VersionOverride`;
- `packages.lock.json`: `"resolved": "1.2.3"` inside the package's block, which a header line
  `"x": {` of the same side of the diff (removed or unchanged) opens, at the indentation
  NuGet writes. A resolved line whose block opens outside the hunk can't be tied to a
  package, so it is ignored;
- `go.mod`: `module v1.2.3` inside a `require (` block, or `require module v1.2.3`. Lines in
  `exclude` and `retract` blocks, and other blocks, are not requirements. A hunk's block is
  the one it opens or closes, or else the one git names in the hunk header (`@@ … @@
  require (`), which is the last line before it that starts a directive;
- Dockerfiles: `FROM image:tag`, with a literal tag. Dependabot names an image without its
  registry, so `dotnet/sdk` is the path of `mcr.microsoft.com/dotnet/sdk` as much as of a
  Docker Hub image; only a name with a registry is tied to that registry;
- workflows: `uses: owner/repo@v1.2.3`, or a commit SHA with the version in its comment.
A line that matches no pattern, or can't be tied to the dependency, is never guessed at.

A file of these types whose patch GitHub leaves out or cuts short, which it does for large
diffs, makes the reading incomplete: what's missing might be the version.

Versions have two forms. `version` drops a leading `v` before a digit, as Dependabot's text
does (`1.23.1`, not go.mod's `v1.23.1`, or a tag comment's `v3.0.2`); comparisons use it.
`written` keeps the file's own text, for matching an inventory that writes the `v`.
"""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


@dataclass(frozen=True)
class FileVersion:
    file: str
    version: str  # without a leading `v`, such as `1.23.1`
    written: str  # as the file writes it, such as `v1.23.1` in go.mod


@dataclass(frozen=True)
class Reading:
    removed: dict[str, list[FileVersion]]  # per dependency name, as the PR names it
    problems: list[str]  # why the diff can't be read completely; empty when it can


_PROPS = re.compile(
    r'^<PackageVersion\s+Include="(?P<name>[^"]+)"\s+Version="(?P<version>[^"$]+)"\s*/>$'
)
_CSPROJ = re.compile(
    r'^<PackageReference\s+Include="(?P<name>[^"]+)"\s+(?:Version|VersionOverride)='
    r'"(?P<version>[^"$]+)"\s*/>$'
)
_LOCK_HEADER = re.compile(r'^ {6}"(?P<name>[^"]+)": \{$')
_LOCK_RESOLVED = re.compile(r'^ {8}"resolved": "(?P<version>[^"]+)",?$')
_LOCK_CLOSE = re.compile(r"^ {6}\},?$")
_GOMOD_REQUIREMENT = r"(?P<name>[^\s()]+)\s+(?P<version>v\d\S*)(?:\s+//.*)?$"
_GOMOD_IN_BLOCK = re.compile(rf"^{_GOMOD_REQUIREMENT}")
_GOMOD_SINGLE = re.compile(rf"^require\s+{_GOMOD_REQUIREMENT}")
_GOMOD_OPEN = re.compile(r"^(?P<directive>[a-z]+)\s*\($")
_HUNK = re.compile(r"^@@ [^@]* @@ ?(?P<heading>.*)$")
_FROM = re.compile(
    r"^(?i:FROM)\s+(?:--platform=\S+\s+)?(?P<name>[^\s:@$]+):(?P<version>[^\s@$]+)"
    r"(?:@sha256:[0-9a-f]+)?(?:\s+(?i:AS)\s+\S+)?$"
)
_USES = re.compile(
    r"^(?:-\s+)?uses:\s+(?P<name>[^@\s'\"]+)@(?P<ref>[^\s#'\"]+)(?:\s+#\s*(?P<comment>\S+))?$"
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$")


def kind(path: str) -> str | None:
    """Which of the scan's file types a changed file is, if any."""
    base = PurePosixPath(path).name
    if base == "Directory.Packages.props":
        return "props"
    if base.endswith(".csproj"):
        return "csproj"
    if base == "packages.lock.json":
        return "lock"
    if base == "go.mod":
        return "gomod"
    if (
        base == "Dockerfile"
        or base.startswith("Dockerfile.")
        or base.lower().endswith(".dockerfile")
    ):
        return "docker"
    if _WORKFLOW.match(path):
        return "workflow"
    return None


def removed_versions(files: list[dict[str, Any]], names: set[str]) -> Reading:
    """The versions the diff removes for each of the names, per file, each pair once."""
    removed: dict[str, list[FileVersion]] = {name: [] for name in names}
    problems = []
    for changed in files:
        path = changed["filename"]
        file_kind = kind(path)
        if file_kind is None:
            continue
        patch = changed.get("patch")
        if not isinstance(patch, str):
            problems.append(f"GitHub doesn't show the diff of {path}")
            continue
        lines = patch.splitlines()
        added = sum(line.startswith("+") for line in lines)
        deleted = sum(line.startswith("-") for line in lines)
        if (added, deleted) != (changed.get("additions"), changed.get("deletions")):
            problems.append(f"GitHub shows the diff of {path} cut short")
            continue
        for found, version in _removed(file_kind, lines):
            for name in names:
                entry = FileVersion(path, bare(version), version)
                if _same(file_kind, found, name) and entry not in removed[name]:
                    removed[name].append(entry)
    return Reading(removed, problems)


def bare(version: str) -> str:
    """The version without a leading `v` before a digit: go.mod and tags write one."""
    return re.sub(r"^v(?=\d)", "", version)


def _removed(file_kind: str, lines: list[str]):
    """(name, version) for each removed line that a pattern ties to a dependency."""
    if file_kind == "lock":
        yield from _removed_from_lock(lines)
        return
    if file_kind == "gomod":
        yield from _removed_from_go_mod(lines)
        return
    for line in lines:
        if not line.startswith("-"):
            continue
        content = line[1:].strip()
        if file_kind == "props":
            match = _PROPS.match(content)
        elif file_kind == "csproj":
            match = _CSPROJ.match(content)
        elif file_kind == "docker":
            match = _FROM.match(content)
        else:
            match = _USES.match(content)
            if match:
                version = match["ref"]
                if _SHA.match(version):
                    if not match["comment"]:
                        continue  # a bare SHA says no version
                    version = match["comment"]
                yield match["name"], version
            continue
        if match:
            yield match["name"], match["version"]


def _removed_from_lock(lines: list[str]):
    """Resolved versions on removed lines, tied to the block the old side of the diff is in."""
    package = None
    for line in lines:
        if line.startswith("@@"):
            package = None  # what lies between hunks isn't shown
            continue
        if line.startswith("+") or line.startswith("\\"):
            continue
        content = line[1:]
        if header := _LOCK_HEADER.match(content):
            package = header["name"]
        elif _LOCK_CLOSE.match(content):
            package = None
        elif (resolved := _LOCK_RESOLVED.match(content)) and line.startswith("-") and package:
            yield package, resolved["version"]


def _removed_from_go_mod(lines: list[str]):
    """Requirements on removed lines, in the block the old side of the diff is in."""
    block = None  # the open block's directive; None at the top level
    for line in lines:
        if hunk := _HUNK.match(line):
            heading = _GOMOD_OPEN.match(hunk["heading"].strip())
            block = heading["directive"] if heading else None
            continue
        if line.startswith("+") or line.startswith("\\"):
            continue
        content = line[1:].strip()
        if opened := _GOMOD_OPEN.match(content):
            block = opened["directive"]
        elif content == ")":
            block = None
        elif line.startswith("-"):
            pattern = _GOMOD_IN_BLOCK if block == "require" else _GOMOD_SINGLE
            if block in ("require", None) and (match := pattern.match(content)):
                yield match["name"], match["version"]


def _same(file_kind: str, found: str, name: str) -> bool:
    if file_kind in ("props", "csproj", "lock"):  # NuGet ids are case-insensitive
        return found.casefold() == name.casefold()
    if file_kind == "docker":
        return same_image(found, name)
    if file_kind == "workflow":  # `owner/repo/path` is the action `owner/repo`
        return "/".join(found.split("/")[:2]).casefold() == name.casefold()
    return found == name


_DOCKER_HUB = {"docker.io", "index.docker.io", "registry-1.docker.io"}


def image_parts(name: str) -> tuple[str | None, str]:
    """An image's registry and path: `golang`, `library/golang` and `docker.io/library/golang`
    are all Docker Hub's `golang`. The registry is None when the name doesn't say one."""
    first, _, rest = name.partition("/")
    registry = None
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, name = first, rest
        if registry in _DOCKER_HUB:
            registry = "docker.io"
    if registry in (None, "docker.io"):
        name = name.removeprefix("library/")
    return registry, name


def same_image(written: str, named: str) -> bool:
    """Whether a file's image is the one Dependabot names.

    Dependabot leaves the registry out of its names (`dotnet/sdk` for
    `mcr.microsoft.com/dotnet/sdk`), so a name without one matches the path in any registry.
    A name with one matches only that registry, where a file without one means Docker Hub.
    """
    (registry, path), (wanted, wanted_path) = image_parts(written), image_parts(named)
    return path == wanted_path and (wanted is None or (registry or "docker.io") == wanted)
