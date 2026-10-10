"""Find known vulnerabilities with OSV-Scanner and tie each one to an inventory entry.

OSV-Scanner runs in a pinned container on the scan's throwaway checkout and reads its lock
files: every `packages.lock.json`, and `go.mod`, which lists every module a Go build resolves
(OSV-Scanner has no extractor for `go.sum`). It matches the resolved versions against
osv.dev. It doesn't decide reachability: its own call analysis is turned off, because
govulncheck supplies reachability for Go (see `sdlc.govulncheck`). Every finding starts as
`unknown`.

An advisory on a dependency the inventory doesn't list, such as a transitive NuGet package or
an indirect Go module, adds a locked entry for it, with the fixed version as its candidate
(design decision 3a).
"""

import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sdlc.coverage import tracked_files
from sdlc.native import line_naming

VERSION = "2.6.0"
IMAGE = (
    f"ghcr.io/google/osv-scanner:v{VERSION}"
    "@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"
)

SOURCE = "osv"
LOCK_FILES = ("packages.lock.json", "go.mod")

# OSV's ecosystem names, mapped to the inventory's ecosystem (Renovate's datasource) and the
# Renovate manager the policy's rules match on.
ECOSYSTEMS = {"Go": ("go", "gomod"), "NuGet": ("nuget", "nuget")}

# 0: no advisories; 1: advisories found. Everything else, such as 127 for a general error or
# 128 for no packages found, means the scan didn't happen.
SCANNED = {0, 1}

# Lower than any version, for an advisory "introduced" at 0.
_ZERO: tuple = ((-1,), 0, ())


class OsvError(Exception):
    """OSV-Scanner didn't produce a usable result."""


@dataclass(frozen=True)
class Findings:
    dependencies: list[dict[str, Any]]  # locked entries for affected lock-file-only packages
    updated: list[dict[str, Any]]  # existing indirect Go entries, now with a lookup to match
    candidates: list[dict[str, Any]]  # fixed versions as candidates, classified by the policy
    vulnerabilities: list[dict[str, Any]]
    gaps: list[dict[str, Any]]  # packages OSV-Scanner couldn't check


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: list[str]
    records: list[dict[str, Any]]  # the OSV entries of one group: the same issue


def tool_entry() -> dict[str, str]:
    return {"name": "osv-scanner", "version": VERSION, "image": IMAGE}


def lock_files(checkout: Path) -> list[str]:
    return [f for f in tracked_files(checkout) if Path(f).name in LOCK_FILES]


def run(checkout: Path, files: list[str]) -> dict[str, Any]:
    """Scan these lock files in the checkout and return OSV-Scanner's JSON output."""
    if not files:
        return {"results": []}
    runtime = os.environ.get("SDLC_CONTAINER_RUNTIME", "docker")
    with tempfile.TemporaryDirectory(prefix="sdlc-osv-") as config:
        # An `osv-scanner.toml` in the subject can ignore advisories or packages, and
        # OSV-Scanner would then leave them out without a trace. An empty configuration of
        # the scan's own replaces any the subject has.
        (Path(config) / "osv-scanner.toml").write_text("")
        command = [
            runtime,
            "run",
            "--rm",
            "--volume",
            f"{checkout}:/src:ro,Z",
            "--volume",
            f"{config}:/config:ro,Z",
            IMAGE,
            "scan",
            "source",
            "--format=json",
            "--config=/config/osv-scanner.toml",
            # Every package, not only affected ones, so those it couldn't check show up too.
            "--all-packages",
            # Reachability comes from govulncheck, not from this experimental analysis.
            "--no-call-analysis=all",
        ]
        for file in files:
            command += ["--lockfile", f"/src/{file}"]
        result = subprocess.run(  # noqa: S603 - fixed command; values are data
            command, capture_output=True, text=True, check=False
        )
    if result.returncode not in SCANNED:
        output = (result.stderr.strip() or result.stdout.strip())[-1500:]
        raise OsvError(f"OSV-Scanner failed ({result.returncode}): {output}")
    try:
        output = json.loads(result.stdout)
    except ValueError as error:
        raise OsvError(f"OSV-Scanner's output isn't JSON: {error}") from error
    if not isinstance(output, dict) or not isinstance(output.get("results"), list):
        raise OsvError("OSV-Scanner's output has no results")
    return output


def findings(
    output: dict[str, Any],
    dependencies: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    *,
    indirect: set[str],
    looked_up_at: str,
    scanned: Sequence[str] = (),
    classify: Callable[[list[dict], dict[str, dict]], list[dict]] = lambda c, fields: c,
    checkout: Path | None = None,
) -> Findings:
    """Tie each advisory in OSV-Scanner's output to an inventory entry.

    An advisory refers to the declared entry at the affected version (a central version, a
    direct Go requirement) or to a lock-drift entry of the same lock file. Otherwise it gets
    a locked entry, one per lock file and package, as lock-drift entries are.

    `indirect` holds the ids of indirect Go requirements. Renovate lists them, so an advisory
    on one refers to that entry rather than to a second one for the same go.mod line. When
    Renovate skipped it, as it does by default, the entry gets the fixed version as its
    candidate and a lookup that says so, returned in `updated`. When the policy had Renovate
    look it up, its lookup and candidates stay, and the fixed version is added only if no
    candidate reaches that far.

    `scanned` lists the lock files OSV-Scanner was given: one missing from its output is a gap,
    not a clean file. `classify` applies the policy to the candidates added here, given the
    fields its rules match on; whether a fix is reached counts in-scope candidates only. With
    a checkout, references to the subject's own projects in NuGet lock files are recognised;
    without one, they are reported as unchecked, to be safe.
    """
    added: list[dict[str, Any]] = []
    updated: dict[str, dict[str, Any]] = {}  # skipped indirect entries, taken over
    looked_up: dict[str, dict[str, Any]] = {}  # indirect entries Renovate looked up
    found: list[tuple[dict[str, Any], str, str, str, Advisory]] = []
    gaps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    results = output.get("results") or []
    reported = {(r.get("source") or {}).get("path", "").removeprefix("/src/") for r in results}
    for file in scanned:
        if file not in reported:
            gaps.append(
                {
                    "kind": "unavailable_source",
                    "subject": file,
                    "reason": "OSV-Scanner returned no result for this lock file, so whether "
                    "an advisory concerns its packages is unknown.",
                }
            )

    for result in results:
        file = (result.get("source") or {}).get("path", "").removeprefix("/src/")
        projects = _projects(checkout, file)
        for package in result.get("packages") or []:
            info = package.get("package") or {}
            ecosystem, name, version = (
                info.get("ecosystem", ""),
                info.get("name", ""),
                info.get("version"),
            )
            if not version:
                if name.casefold() not in projects:
                    gaps.append(
                        {
                            "kind": "unavailable_source",
                            "subject": f"{file}: {name}",
                            "reason": "OSV-Scanner found no resolved version, so whether an "
                            "advisory concerns it is unknown.",
                        }
                    )
                continue
            advisories = _advisories(package)
            if not advisories:
                continue
            entry = _match(dependencies + added, ecosystem, name, version, file, indirect)
            if entry is None:
                listed = _indirect_entry(dependencies, indirect, name, version, file)
                if listed is not None and listed["lookup"]["state"] == "skipped":
                    entry = updated.setdefault(listed["id"], dict(listed))
                elif listed is not None:
                    entry = looked_up.setdefault(listed["id"], listed)
            if entry is None:
                entry = _locked(dependencies + added, ecosystem, name, version, file, checkout)
                added.append(entry)
            for advisory in advisories:
                if (advisory.id, entry["id"]) in seen:
                    continue
                seen.add((advisory.id, entry["id"]))
                found.append((entry, ecosystem, name, version, advisory))

    existing: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        existing.setdefault(candidate["dependency"], []).append(candidate)

    new_candidates = []
    for entry in added + list(updated.values()) + list(looked_up.values()):
        fixes = [
            fixed
            for e, ecosystem, name, version, advisory in found
            if e is entry and (fixed := fix(version, advisory.records, ecosystem, name)[0])
        ]
        datasource = entry["ecosystem"]
        target = max(fixes, key=_key) if fixes else None
        if entry["id"] in looked_up:
            # Renovate's lookup stands; the fix is only added where its candidates fall short.
            if target is None or entry["lookup"]["state"] != "outdated":
                continue
            if any(
                (k := _key(c["version"])) is not None and k >= _key(target)
                for c in existing.get(entry["id"], [])
            ):
                continue
        elif target is None:
            entry["lookup"] = {
                "state": "skipped",
                "reason": "Listed for its advisories, none of which states a fixed version; "
                "lock-file-only dependencies and indirect modules aren't looked up.",
                "datasource": datasource,
            }
            continue
        else:
            entry["lookup"] = {
                "state": "outdated",
                "datasource": datasource,
                "looked_up_at": looked_up_at,
            }
        new_candidates.append(
            {
                "dependency": entry["id"],
                "update_type": _update_type(entry["current"], target),
                "version": _display(datasource, target),
                "classification": "in_scope",
            }
        )
    # Like lock-file drift, these candidates come from the advisories, not from Renovate, so
    # only the policy's rules classify them.
    new_candidates = classify(
        new_candidates,
        match_fields(added + list(updated.values()) + list(looked_up.values())),
    )

    by_entry: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates + new_candidates:
        by_entry.setdefault(candidate["dependency"], []).append(candidate)
    vulnerabilities = [
        vulnerability(entry, by_entry.get(entry["id"], []), advisory, ecosystem, name, version)
        for entry, ecosystem, name, version, advisory in found
    ]
    return Findings(added, list(updated.values()), new_candidates, vulnerabilities, gaps)


def vulnerability(
    entry: dict[str, Any],
    candidates: list[dict[str, Any]],
    advisory: Advisory,
    ecosystem: str,
    name: str,
    version: str,
    *,
    source: str = SOURCE,
    reachability: str = "unknown",
) -> dict[str, Any]:
    """The record's vulnerability for an advisory on the entry's version, given its candidates.

    Reachability is `unknown` unless the caller knows better: OSV-Scanner's matches say nothing
    about it.
    """
    found: dict[str, Any] = {"advisory": advisory.id}
    if advisory.aliases:
        found["aliases"] = advisory.aliases
    fixed, last_affected = fix(version, advisory.records, ecosystem, name)
    found |= {
        "dependency": entry["id"],
        "affected_version": _display(entry["ecosystem"], version),
        "fixed_version": _display(entry["ecosystem"], fixed) if fixed else None,
    }
    if last_affected and not fixed:
        found["last_affected"] = _display(entry["ecosystem"], last_affected)
    if fixed or last_affected:
        reached, held_by = _reached(entry, candidates, advisory, ecosystem, name)
        found["fix_reached_by_candidate"] = reached
        if held_by:
            found["fix_held_by"] = held_by
    found |= {"source": source, "reachability": reachability}
    return found


def match_fields(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The fields Renovate's package rules match on, for locked entries added here."""
    managers = {datasource: manager for datasource, manager in ECOSYSTEMS.values()}
    return {
        e["id"]: {
            "depName": e["name"],
            "packageName": e["name"],
            "datasource": e["ecosystem"],
            "manager": managers.get(e["ecosystem"], e["ecosystem"]),
        }
        for e in entries
    }


def _advisories(package: dict[str, Any]) -> list[Advisory]:
    """One advisory per group: OSV-Scanner groups entries that describe the same issue."""
    records = {v["id"]: v for v in package.get("vulnerabilities") or [] if v.get("id")}
    groups = [[i for i in g.get("ids") or [] if i in records] for g in package.get("groups") or []]
    grouped = {i for ids in groups for i in ids}
    groups += [[i] for i in records if i not in grouped]
    advisories = []
    for ids in groups:
        if not ids:
            continue
        aliases = set(ids)
        for i in ids:
            aliases |= set(records[i].get("aliases") or [])
        advisories.append(Advisory(ids[0], sorted(aliases - {ids[0]}), [records[i] for i in ids]))
    return advisories


def _match(
    dependencies: list[dict[str, Any]],
    ecosystem: str,
    name: str,
    version: str,
    file: str,
    indirect: set[str],
) -> dict[str, Any] | None:
    """The inventory entry the affected package and version stand for, if the scan has one."""
    datasource = ECOSYSTEMS.get(ecosystem, (ecosystem.lower(),))[0]

    def same(dep: dict[str, Any]) -> bool:
        return (
            dep["ecosystem"] == datasource
            and _same_name(ecosystem, dep["name"], name)
            and bool(dep["current"])
            and _same_version(dep["current"], version)
        )

    declared = [
        d
        for d in dependencies
        if d["origin"] == "declared"
        and d["id"] not in indirect
        and same(d)
        # A Go module's version is per go.mod; a central NuGet version applies everywhere.
        and (ecosystem != "Go" or d["location"]["file"] == file)
    ]
    # A version declared next to the lock file goes before a central one.
    declared.sort(key=lambda d: Path(d["location"]["file"]).parent != Path(file).parent)
    locked = [
        d
        for d in dependencies
        if d["origin"] == "locked" and d["location"]["file"] == file and same(d)
    ]
    return (declared + locked)[0] if declared or locked else None


def _indirect_entry(
    dependencies: list[dict[str, Any]], indirect: set[str], name: str, version: str, file: str
) -> dict[str, Any] | None:
    """Renovate's entry for an indirect Go module required at this version here."""
    for dep in dependencies:
        if (
            dep["id"] in indirect
            and dep["name"] == name
            and dep["location"]["file"] == file
            and _same_version(dep["current"] or "", version)
        ):
            return dep
    return None


def _locked(
    dependencies: list[dict[str, Any]],
    ecosystem: str,
    name: str,
    version: str,
    file: str,
    checkout: Path | None,
) -> dict[str, Any]:
    """A locked entry for an affected package the inventory doesn't list yet."""
    datasource = ECOSYSTEMS.get(ecosystem, (ecosystem.lower(),))[0]
    taken = {d["id"] for d in dependencies}
    base = dep_id = f"locked:{file}:{name}"
    n = 1
    while dep_id in taken:
        n += 1
        dep_id = f"{base}#{n}"

    location: dict[str, Any] = {"file": file}
    if datasource == "go":
        line = _go_line(checkout, file, name)
    else:
        line = line_naming(checkout, file, name)
    if line:
        location["line"] = line
    return {
        "id": dep_id,
        "ecosystem": datasource,
        "name": name,
        "current": _display(datasource, version),
        "origin": "locked",
        "locked_because": "vulnerability",
        "location": location,
        # The lookup follows once the entry's advisories, and so its fixes, are known.
    }


def _projects(checkout: Path | None, file: str) -> set[str]:
    """The subject's own projects a NuGet lock file refers to, which have no version.

    Their packages are resolved in the same lock file, so OSV-Scanner checks those anyway.
    """
    if checkout is None or Path(file).name != "packages.lock.json":
        return set()
    try:
        lock = json.loads((checkout / file).read_text())
    except (OSError, ValueError):
        return set()
    return {
        name.casefold()
        for packages in (lock.get("dependencies") or {}).values()
        if isinstance(packages, dict)
        for name, package in packages.items()
        if isinstance(package, dict) and package.get("type") == "Project"
    }


def _go_line(checkout: Path | None, file: str, name: str) -> int | None:
    """The go.mod line requiring the module, inside a require block or not."""
    if checkout is None or not (checkout / file).exists():
        return None
    for number, line in enumerate((checkout / file).read_text().splitlines(), 1):
        words = line.split()
        if name in words[:2] and words[0] in (name, "require"):
            return number
    return None


def affected(version: str, records: list[dict[str, Any]], ecosystem: str, name: str) -> bool | None:
    """Whether an advisory concerns the version; None when its ranges can't be evaluated."""
    key = _key(version)
    if key is None:
        return None
    undecided = False
    for entry in _affected_entries(records, ecosystem, name):
        if any(_same_version(version, v) for v in entry.get("versions") or []):
            return True
        for affected_range in entry.get("ranges") or []:
            if affected_range.get("type") not in ("SEMVER", "ECOSYSTEM"):
                undecided = True  # a GIT range names commits, not versions
                continue
            hit = _in_range(key, affected_range.get("events") or [])
            if hit is None:
                undecided = True
            elif hit:
                return True
    return None if undecided else False


def fix(
    version: str, records: list[dict[str, Any]], ecosystem: str, name: str
) -> tuple[str | None, str | None]:
    """The version that fixes the advisory for this one, or else its last affected version.

    Only a range that contains the version counts, and within it the event that ends it: a
    `fixed` version, or a `last_affected` one, which says a fix exists without naming it.
    The entries of one group describe one issue but may disagree, so a fixed version is
    accepted only if every entry agrees it is unaffected; otherwise the next one is tried.
    """
    key = _key(version)
    if key is None:
        return None, None
    fixes, last = set(), set()
    for entry in _affected_entries(records, ecosystem, name):
        for affected_range in entry.get("ranges") or []:
            if affected_range.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            end = _range_end(key, affected_range.get("events") or [])
            if end is not None:
                (fixes if end[0] == "fixed" else last).add(end[1])
    for fixed in sorted(fixes, key=_key):
        if all(affected(fixed, [record], ecosystem, name) is False for record in records):
            return fixed, None
    # A last affected version is exact: any version above it is outside the advisory, which
    # is how candidates are judged. A guessed "next version" would not be.
    return None, max(last, key=_key) if last else None


def _reached(
    entry: dict[str, Any],
    candidates: list[dict[str, Any]],
    advisory: Advisory,
    ecosystem: str,
    name: str,
) -> tuple[bool | str, str | None]:
    """Whether an in-scope candidate is outside the advisory: true, false or "unknown".

    When only a candidate the policy holds gets there, the answer is false, with the rule.
    """
    state = entry["lookup"]["state"]
    if state == "current":
        return False, None
    if state != "outdated":
        return "unknown", None
    judged = [
        (c, affected(c["version"], advisory.records, ecosystem, name))
        for c in candidates
        if c["update_type"] != "digest"
    ]
    in_scope = [result for c, result in judged if c["classification"] == "in_scope"]
    if any(result is False for result in in_scope):
        return True, None
    if any(result is None for result in in_scope):
        return "unknown", None
    held = [c for c, result in judged if c["classification"] != "in_scope" and result is False]
    if held:
        return False, held[0].get("held_by")
    if not judged:
        return "unknown", None
    return False, None


def _affected_entries(
    records: list[dict[str, Any]], ecosystem: str, name: str
) -> list[dict[str, Any]]:
    # One advisory can name several packages: Go's x/net advisories also cover the stdlib.
    return [
        entry
        for record in records
        for entry in record.get("affected") or []
        if (entry.get("package") or {}).get("ecosystem") == ecosystem
        and _same_name(ecosystem, (entry.get("package") or {}).get("name", ""), name)
    ]


def _points(events: list[dict[str, str]]) -> list[tuple[tuple, str, str]] | None:
    """A range's events in version order, as (key, kind, version); None if one isn't one."""
    points = []
    for event in events:
        # `limit` only bounds a commit search; it doesn't change which versions are affected.
        for kind in ("introduced", "fixed", "last_affected"):
            if kind in event:
                point = _ZERO if event[kind] == "0" else _key(event[kind])
                if point is None:
                    return None
                points.append((point, kind, event[kind]))
    return sorted(points, key=lambda p: p[0])


def _in_range(key: tuple, events: list[dict[str, str]]) -> bool | None:
    """OSV's range evaluation: walk the events in version order."""
    points = _points(events)
    if points is None:
        return None
    hit = False
    for point, kind, _ in points:
        if kind == "introduced" and key >= point:
            hit = True
        elif (kind == "fixed" and key >= point) or (kind == "last_affected" and key > point):
            hit = False
    return hit


def _range_end(key: tuple, events: list[dict[str, str]]) -> tuple[str, str] | None:
    """The event that ends the range's stretch containing the version, if it contains it."""
    if not _in_range(key, events):
        return None
    for point, kind, version in _points(events) or []:
        if (kind == "fixed" and point > key) or (kind == "last_affected" and point >= key):
            return kind, version
    return None  # affected from here on


def _key(version: str) -> tuple | None:
    """A sort key with SemVer precedence, which Go and NuGet versions both follow.

    NuGet's fourth number is kept; prerelease labels compare case-insensitively, as NuGet
    compares them. None for something that isn't a version.
    """
    core, _, prerelease = _bare(version).split("+", 1)[0].partition("-")
    try:
        numbers = tuple(int(part) for part in core.split("."))
    except ValueError:
        return None
    if not 1 <= len(numbers) <= 4:
        return None
    numbers += (0,) * (4 - len(numbers))
    if not prerelease:
        return (numbers, 1, ())
    labels = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part.casefold())
        for part in prerelease.split(".")
    )
    return (numbers, 0, labels)


def _update_type(current: str, target: str) -> str:
    old, new = _key(current), _key(target)
    if old is None or new is None or new[0][0] != old[0][0]:
        return "major"
    if new[0][1] != old[0][1]:
        return "minor"
    return "patch"


def _same_version(a: str, b: str) -> bool:
    """Equal as versions, so `2.1` is `2.1.0`; as text when either isn't a version."""
    key_a, key_b = _key(a), _key(b)
    if key_a is None or key_b is None:
        return _bare(a) == _bare(b)
    return key_a == key_b


def _bare(version: str) -> str:
    return version.strip().removeprefix("v")


def _display(datasource: str, version: str) -> str:
    """Versions as the inventory writes them: Go's with their `v`."""
    if datasource == "go" and not version.startswith("v"):
        return f"v{version}"
    return version


def _same_name(ecosystem: str, a: str, b: str) -> bool:
    # NuGet package ids are case-insensitive; OSV-Scanner lowercases some of them.
    return a.casefold() == b.casefold() if ecosystem == "NuGet" else a == b
