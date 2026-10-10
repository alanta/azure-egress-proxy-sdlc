"""Compare the scan's candidates with the updates Dependabot's open PRs propose.

Dependabot is the baseline the scan has to match (design decision 7). Only PRs that target the
branch the scanned revision is on are compared, or the default branch when the scan names a
commit or tag; others are listed as `not_compared`, with the reason. Each update a compared,
parsed PR proposes gets one result:
- `stale`: the PR was made for another revision. None of its from-versions is what the scanned
  revision has, so it says nothing about this scan and counts neither as matched nor missed;
- `held_by_policy`: the subject's policy holds the version Dependabot proposes, by a rule the
  record names;
- `matched`: every entry the update changes, in every file that still has its from-version,
  has an in-scope candidate at the same or a newer version; the record names the closest one;
- `missed`: anything else, with the reasons the scan knows, per entry: the dependency isn't in
  the inventory in a file it changes (never `stale`, since that may be the scan's blind spot),
  its lookup was unknown or skipped, it has no candidate, or only older or held ones.
A PR with a stale update is stale itself: Dependabot would have to rebase it first.

An update is tied to inventory entries by ecosystem (Dependabot's package-ecosystem to
Renovate's managers and datasources), by name (NuGet ids ignore case; an image is its path,
with Docker Hub's `library/` dropped and the registry only compared when Dependabot names one;
an action is its `owner/repo`; Go module paths are exact) and by file. The files are the ones
whose removed lines gave the PR's from-versions (see `pr_diff`), which are more exact than
Dependabot's directory: #77 changes only AppHost's lock file, not the central version. Only
when the diff gave none does the directory decide; for devcontainers, the directory is the one
holding `.devcontainer/`.

Staleness is checked per file, because a dependency can have several versions at once: #98's
Azure.Core is 1.62.0 centrally, while some lock files resolve 1.53.0 or 1.55.0. Each file's
from-version is compared with what the revision has in that same file: its inventory entries,
or, for a lock file, the version it resolves in the scanned checkout (a transitive can resolve
above the declared version), else its locked entry. A file the revision doesn't have at all
differs too: the PR was made for a revision that has it, as #75 later was for a workflow added
after 064aa09. A file that exists without the entry is the scan's blind spot, not a
difference. When nothing tells, such as without a checkout, for a path in a submodule or
when only the directory says where, the file is unknown, which is not the same as
differing. A per-dependency comparison would call a PR current when the version it replaces
survives in some other file. The update is stale when every file
the scan knows differs. When only some do, the revision still has what the PR replaces, so
the update isn't stale; those files are left out of the comparison, and the reason names them.

A lock file follows the entry that governs it: a version in the project file next to it, or
else the nearest `Directory.Packages.props` above it. Its own locked entry is covered by that
entry's candidate too, and a lock file without an entry is covered by it alone. The governing
entry is never listed as one the update maps to unless the update changes its file.

The policy decides per entry. A candidate at Dependabot's version, if the scan has one, was
classified by Renovate, so its classification counts. Otherwise the hold rules are evaluated
on Dependabot's update itself, with the entry's match fields, Dependabot's update type and its
to-version as the entry writes versions (`v1.23.2` in go.mod), so a hold is named even when
the scan has no candidate at that version. A rule the scan can't evaluate for that version
makes the comparison incomplete.

Versions compare per ecosystem: image tags by their numbers, only with the same suffix
(`1.27-alpine` reaches `1.27-alpine`, `1.28-alpine` beyond it, but `1.27` or `1.27-bookworm`
neither); PyPI by PEP 440; everything else as SemVer, with a leading `v`, any number of parts,
and NuGet's prerelease labels in any case. Versions that can't be compared don't match.

Scan-only candidates are in-scope candidates of entries no compared update maps to. The
record lists their dependencies, one id per entry, however many candidates it has.

Parity holds only at a point in time, so the section records when the PRs were read and when
the lookups ran. When the PRs couldn't be read, it compares nothing and lists nothing as
scan-only: an unread source must never look like one without open PRs.
"""

import json
import re
from dataclasses import dataclass, field
from functools import cmp_to_key
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.version import InvalidVersion, Version

from sdlc import policy as policies
from sdlc.dependabot_prs import PullRequest, PullRequests, Update
from sdlc.pr_diff import bare, image_parts

# Dependabot's package-ecosystem: the Renovate managers and datasources of what it updates,
# the usual one first. The gomod one isn't `golang-version`: Dependabot doesn't move the `go`
# directive. Actions are `uses:` refs, not `setup-*` versions (`github-releases`) or runner
# labels (`github-runners`).
ECOSYSTEMS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "nuget": (("nuget",), ("nuget",)),
    "gomod": (("gomod",), ("go",)),
    "docker": (("dockerfile",), ("docker",)),
    "github-actions": (("github-actions",), ("github-tags", "github-digest")),
    "devcontainers": (("devcontainer",), ("docker",)),
    "pip": (("pip_requirements", "pip_setup", "pipenv", "poetry", "pep621"), ("pypi",)),
    "npm": (("npm",), ("npm",)),
}
_IMAGES = {"docker", "devcontainers"}
_PROJECTS = {".csproj", ".fsproj", ".vbproj"}
LOCK_FILE = "packages.lock.json"

_TAG = re.compile(r"^v?(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>.*)$")
_SEMVER = re.compile(
    r"^v?(?P<numbers>\d+(?:\.\d+)*)(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_WRITTEN_WITH_V = re.compile(r"^v\d")


def compare(
    pulls: PullRequests | None,
    dependencies: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    fields: dict[str, dict[str, Any]],
    policy: policies.Policy,
    *,
    looked_up_at: str,
    branch: str,
    checkout: Path | None = None,
    unavailable: str | None = None,
) -> dict[str, Any]:
    """The record's parity section.

    `pulls` is None when the PRs couldn't be read, and `unavailable` says why. `fields` gives
    every dependency id the fields Renovate's package rules match on. `branch` is the branch
    the compared PRs target. `checkout` is the scanned revision, for the versions its lock
    files resolve.
    """
    section: dict[str, Any] = {"baseline": "dependabot", "looked_up_at": looked_up_at}
    if pulls is None:
        why = unavailable or "they weren't read"
        return section | {
            "complete": False,
            "reasons": [f"Dependabot's open PRs couldn't be read: {why}"],
            "pull_requests": [],
            "scan_only": [],
        }

    index = _Index(dependencies, candidates, fields, checkout)
    reasons: list[str] = []
    covered: set[str] = set()
    compared = []
    for pull in pulls.pull_requests:
        if pull.base != branch:
            # Another branch's PR proposes changes to another revision than the scanned one.
            reason = f"it targets {pull.base}, not {branch}, which the scanned revision is on"
            compared.append(_pull(pull, "not_compared", [], reason))
            continue
        if pull.state != "parsed":
            reasons.append(f"#{pull.number} is unparseable: {pull.reason}")
            compared.append(_pull(pull, "unparseable", [], pull.reason))
            continue
        updates = []
        for update in pull.updates:
            result, mapped, doubts = _compare(update, index, policy)
            covered |= set(mapped)
            reasons += [f"#{pull.number}: {doubt}" for doubt in doubts]
            updates.append(result)
        stale = [u["name"] for u in updates if u["result"] == "stale"]
        if stale:
            reason = f"the revision no longer has what it updates for {', '.join(stale)}"
            compared.append(_pull(pull, "stale", updates, reason))
        else:
            compared.append(_pull(pull, "current", updates))

    in_scope = {c["dependency"] for c in candidates if c["classification"] == "in_scope"}
    section |= {"captured_at": pulls.read_at, "complete": not reasons}
    if reasons:
        section["reasons"] = reasons
    return section | {
        "pull_requests": compared,
        "scan_only": [
            d["id"] for d in dependencies if d["id"] in in_scope and d["id"] not in covered
        ],
    }


def _pull(
    pull: PullRequest, state: str, updates: list[dict[str, Any]], reason: str | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "number": pull.number,
        "title": pull.title,
        "head": pull.head,
        "base": pull.base,
        "state": state,
    }
    if reason:
        entry["reason"] = reason
    return entry | {"updates": updates}


class _Index:
    """The inventory, its candidates and match fields, by what an update looks up."""

    def __init__(
        self,
        dependencies: list[dict[str, Any]],
        candidates: list[dict[str, Any]],
        fields: dict[str, dict[str, Any]],
        checkout: Path | None,
    ):
        self.dependencies = dependencies
        self.fields = fields
        self.checkout = checkout
        self.candidates: dict[str, list[dict[str, Any]]] = {}
        for candidate in candidates:
            self.candidates.setdefault(candidate["dependency"], []).append(candidate)

    def named(self, update: Update) -> list[dict[str, Any]]:
        """The entries of the update's dependency, in its ecosystem, anywhere."""
        managers, datasources = ECOSYSTEMS[update.ecosystem or ""]
        key = name_key(update.ecosystem, update.name)
        registry = image_parts(update.name)[0] if update.ecosystem in _IMAGES else None
        found = []
        for dep in self.dependencies:
            f = self.fields[dep["id"]]
            if f.get("manager") not in managers or f.get("datasource") not in datasources:
                continue
            names = {dep["name"], f.get("depName"), f.get("packageName")} - {None}
            if any(
                name_key(update.ecosystem, n) == key and _registry_fits(update, n, registry)
                for n in names
            ):
                found.append(dep)
        return found


def _registry_fits(update: Update, name: str, registry: str | None) -> bool:
    """A Dependabot image name with a registry only matches that registry."""
    if update.ecosystem not in _IMAGES or registry is None:
        return True
    return (image_parts(name)[0] or "docker.io") == registry


@dataclass
class _File:
    """One file the update changes, as the scanned revision has it."""

    file: str | None
    old: str  # the version the update replaces there
    have: set[str] | None  # the versions the revision has there; None when unknown
    entries: list[dict[str, Any]] = field(default_factory=list)
    governing: dict[str, Any] | None = None  # for a lock file, the entry it follows
    absent: bool = False  # the scanned revision doesn't have the file at all


def _compare(
    update: Update, index: _Index, policy: policies.Policy
) -> tuple[dict[str, Any], list[str], list[str]]:
    """The update's result, the ids of the entries it maps to, and doubts that make the
    comparison incomplete."""
    result: dict[str, Any] = {"name": update.name}
    if update.ecosystem:
        result["ecosystem"] = update.ecosystem
    if update.directory:
        result["directory"] = update.directory
    if update.group:
        result["group"] = update.group
    if update.update_type:
        result["update_type"] = update.update_type
        result["update_type_derived"] = update.update_type_derived
    result["from_source"] = update.from_source
    if update.from_version:
        result["from"] = update.from_version
    if update.from_versions:
        result["from_versions"] = [
            {"file": f.file, "version": f.version} for f in update.from_versions
        ]
    result["to"] = update.to_version

    if update.ecosystem not in ECOSYSTEMS:
        what = f"Dependabot's {update.ecosystem} ecosystem" if update.ecosystem else "its ecosystem"
        return (
            result | _missed(f"the scan doesn't know which of its entries {what} updates"),
            [],
            [],
        )

    ecosystem = update.ecosystem
    files = _locate(update, index)
    mapped = _unique_entries(d for f in files for d in f.entries)
    ids = [d["id"] for d in mapped]
    if ids:
        result["dependencies"] = ids

    known = [f for f in files if f.have is not None]
    differing = [
        f for f in known if not any(same_version(ecosystem, f.old, v) for v in f.have or ())
    ]
    if known and len(differing) == len(known):
        return result | {"result": "stale", "reason": _differences(differing)}, ids, []
    note = f"not stale, but {_differences(differing)}" if differing else None
    active = [f for f in files if f not in differing]

    if not any(f.entries or f.governing for f in active):
        return _not_in_inventory(update, active, policy, result, ids, note)

    # Each entry that has to reach Dependabot's version, with the entry that may do it instead.
    needed: dict[str, tuple[dict[str, Any], dict[str, Any] | None]] = {}
    absent = []
    for f in active:
        if f.entries:
            for dep in f.entries:
                instead = f.governing if dep["origin"] != "declared" else None
                needed.setdefault(dep["id"], (dep, instead))
        elif f.governing:
            needed.setdefault(f.governing["id"], (f.governing, None))
        else:
            absent.append(f.file)

    holding, doubts = [], []
    for dep, _ in needed.values():
        rules, doubt = _holds(update, dep, index, policy)
        holding += rules
        if doubt:
            doubts.append(doubt)
    if holding:
        return result | _held(_unique(holding), note), ids, []

    reached, short = [], []
    for dep, instead in needed.values():
        found = _reaching(update, dep, index) or (instead and _reaching(update, instead, index))
        if found:
            reached += found
        else:
            short.append(instead or dep)
    if not short and not absent:
        closest = min(
            reached,
            key=cmp_to_key(lambda a, b: version_order(ecosystem, a["version"], b["version"]) or 0),
        )
        matched: dict[str, Any] = {"result": "matched", "candidate": closest["version"]}
        reasons = [*doubts, note] if note else doubts
        if reasons:
            matched["reason"] = "; ".join(reasons)
        return result | matched, ids, doubts

    why = [_why_missed(update, dep, index) for dep in _unique_entries(short)]
    why += [f"{update.name} is not in the inventory in {file}" for file in absent]
    reason = "; ".join(_unique([*doubts, *why, *([note] if note else [])]))
    return result | _missed(reason), ids, doubts


def _not_in_inventory(
    update: Update,
    active: list[_File],
    policy: policies.Policy,
    result: dict[str, Any],
    ids: list[str],
    note: str | None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """The policy can still hold an update the inventory doesn't have, by Dependabot's names."""
    managers, datasources = ECOSYSTEMS[update.ecosystem or ""]
    own = {
        "depName": update.name,
        "packageName": update.name,
        "datasource": datasources[0],
        "manager": managers[0],
    }
    version = update.to_version
    if update.ecosystem == "gomod" and not version.startswith("v"):
        version = f"v{version}"  # as Renovate writes Go module versions
    try:
        holding = policies.holds(own, update.update_type, version, policy)
    except policies.PolicyError as error:
        doubt = f"whether the policy holds {update.name} {update.to_version} is unknown: {error}"
        holding, doubts = [], [doubt]
    else:
        doubts = []
    if holding:
        return result | _held(holding, note), ids, []
    files = sorted({f.file for f in active if f.file})
    where = f" in {', '.join(files)}"
    if len(files) > 3:
        where = f" in any of the {len(files)} files it changes"
    elif not files:
        where = ""
    # Not stale: a dependency the scan doesn't see may be a blind spot of the scan.
    reason = "; ".join([*doubts, f"{update.name} is not in the inventory{where}"])
    return result | _missed(f"{reason}; {note}" if note else reason), ids, doubts


def _locate(update: Update, index: _Index) -> list[_File]:
    """Per file the update changes: the version it replaces, what the revision has there,
    and the entries there."""
    named = index.named(update)
    if not update.from_versions:
        # Only the text gave a from-version; the directory says where.
        old = bare(update.from_version or "")
        here = [d for d in named if _in_directory(d, update.directory, update.ecosystem)]
        if not here:
            return [_File(None, old, None)]
        return [
            _File(d["location"]["file"], old, {bare(d["current"])} if d["current"] else None, [d])
            for d in _one_registry(update, here)
        ]

    files = []
    for changed in update.from_versions:
        if present(index.checkout, changed.file) is False:
            # The PR changes a file the revision doesn't have, so it was made for another one.
            files.append(_File(changed.file, changed.version, set(), absent=True))
            continue
        here = _one_registry(update, [d for d in named if d["location"]["file"] == changed.file])
        have = {bare(d["current"]) for d in here if d["current"]} or None
        governing = None
        if PurePosixPath(changed.file).name == LOCK_FILE:
            governing = _governing(changed.file, named)
            # What the lock file resolves, which can be above the declared version.
            have = lock_versions(index.checkout, changed.file, update.name) or have
        files.append(_File(changed.file, changed.version, have, here, governing))
    return files


def _one_registry(update: Update, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """For an image Dependabot names without a registry, the entries of one registry only:
    Docker Hub's when there are some, or else the only other registry's. Images of several
    other registries with the same path can't be told apart, so none of them is taken."""
    if update.ecosystem not in _IMAGES or image_parts(update.name)[0] is not None:
        return entries
    registries = {(image_parts(d["name"])[0] or "docker.io") for d in entries}
    if "docker.io" in registries:
        return [d for d in entries if (image_parts(d["name"])[0] or "docker.io") == "docker.io"]
    return entries if len(registries) <= 1 else []


def _governing(lock_file: str, named: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The declared entry a lock file's version follows: the project file next to it, or else
    the nearest Directory.Packages.props above it. Only entries that state a version count."""
    declared = [d for d in named if d["origin"] == "declared" and d["current"]]
    folder = PurePosixPath(lock_file).parent
    for dep in declared:
        path = PurePosixPath(dep["location"]["file"])
        if path.parent == folder and path.suffix in _PROJECTS:
            return dep
    for above in (folder, *folder.parents):
        props = str(above / "Directory.Packages.props")
        for dep in declared:
            if dep["location"]["file"] == props:
                return dep
    return None


def present(checkout: Path | None, file: str) -> bool | None:
    """Whether the scanned revision has a file a PR's diff names; None when that can't be
    known: no checkout, a path outside it, or a path in a submodule, whose files a checkout
    may not have."""
    if checkout is None:
        return None
    root = checkout.resolve()
    path = (root / file).resolve()
    if not path.is_relative_to(root):  # the name comes from the PR's diff
        return None
    if path.exists():
        return True
    for submodule in _submodules(root):
        if PurePosixPath(file).is_relative_to(submodule):
            return None
    return False


_SUBMODULE_PATH = re.compile(r"^\s*path\s*=\s*(.+?)\s*$", re.MULTILINE)


def _submodules(root: Path) -> list[PurePosixPath]:
    try:
        text = (root / ".gitmodules").read_text(encoding="utf-8")
    except OSError:
        return []
    return [PurePosixPath(p.strip("/")) for p in _SUBMODULE_PATH.findall(text)]


def lock_versions(checkout: Path | None, file: str, name: str) -> set[str] | None:
    """The versions a packages.lock.json in the checkout resolves for a package, in any target
    framework; None when that can't be read, so the file counts as unknown, not as differing."""
    if checkout is None:
        return None
    root = checkout.resolve()
    path = (root / file).resolve()
    if not path.is_relative_to(root):  # the name comes from the PR's diff
        return None
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    targets = lock.get("dependencies") if isinstance(lock, dict) else None
    if not isinstance(targets, dict):
        return None
    found = set()
    for packages in targets.values():
        if not isinstance(packages, dict):
            continue
        for package, entry in packages.items():
            resolved = entry.get("resolved") if isinstance(entry, dict) else None
            if package.casefold() == name.casefold() and isinstance(resolved, str):
                found.add(bare(resolved))
    return found or None


def _in_directory(dep: dict[str, Any], directory: str | None, ecosystem: str | None) -> bool:
    # Actions live in .github/workflows whatever directory dependabot.yml names.
    if not directory or ecosystem == "github-actions":
        return True
    file = PurePosixPath(dep["location"]["file"])
    folder = PurePosixPath(directory.strip("/") or ".")
    if ecosystem == "devcontainers":
        # dependabot.yml names the directory holding `.devcontainer/` or `.devcontainer.json`.
        return (
            file == folder / ".devcontainer.json"
            or folder / ".devcontainer" in (file.parent, *file.parent.parents)
            or file.parent == folder
        )
    return file.parent == folder


def _holds(
    update: Update, dep: dict[str, Any], index: _Index, policy: policies.Policy
) -> tuple[list[str], str | None]:
    """The rules holding Dependabot's version for one entry, and a doubt when unknown.

    A candidate at that version was classified by Renovate itself, so it decides first.
    """
    same = [
        c
        for c in index.candidates.get(dep["id"], [])
        if same_version(update.ecosystem, c["version"], update.to_version)
    ]
    held = [r for c in same if c["classification"] == "held_by_policy" for r in _rules(c)]
    if held or any(c["classification"] == "in_scope" for c in same):
        return _unique(held), None
    update_type = update.update_type or next((c["update_type"] for c in same), None)
    version = update.to_version
    if _WRITTEN_WITH_V.match(dep["current"] or "") and not version.startswith("v"):
        version = f"v{version}"  # as go.mod or an action's tag writes it
    try:
        return policies.holds(index.fields[dep["id"]], update_type, version, policy), None
    except policies.PolicyError as error:
        return [], f"whether the policy holds {update.name} {update.to_version} is unknown: {error}"


def _rules(candidate: dict[str, Any]) -> list[str]:
    return [r for r in candidate.get("held_by", "").split("; ") if r]


def _reaching(update: Update, dep: dict[str, Any], index: _Index) -> list[dict[str, Any]]:
    """The entry's in-scope candidates at or past Dependabot's version."""
    return [
        c
        for c in index.candidates.get(dep["id"], [])
        if c["classification"] == "in_scope"
        and c["update_type"] != "digest"
        and (order := version_order(update.ecosystem, c["version"], update.to_version)) is not None
        and order >= 0
    ]


def _differences(differing: list[_File]) -> str:
    return "; ".join(
        f"{f.file} is absent from the scanned revision"
        if f.absent
        else f"{f.file or 'the revision'} has {' or '.join(sorted(f.have or ()))}, not {f.old}"
        for f in differing
    )


def _why_missed(update: Update, dep: dict[str, Any], index: _Index) -> str:
    """What the scan has for an entry instead of a candidate at Dependabot's version."""
    file, lookup = dep["location"]["file"], dep["lookup"]
    own = index.candidates.get(dep["id"], [])
    if lookup["state"] == "unknown":
        return f"the lookup in {file} is unknown: {lookup.get('reason', 'no reason')}"
    if lookup["state"] == "skipped":
        return f"Renovate skipped it in {file}: {lookup.get('reason', 'no reason')}"
    if not own:
        found = " (its lookup found it current)" if lookup["state"] == "current" else ""
        return f"the scan has no candidate in {file}{found}"
    return _candidates_fall_short(update, file, own)


def _candidates_fall_short(update: Update, file: str, own: list[dict[str, Any]]) -> str:
    ecosystem, to = update.ecosystem, update.to_version
    in_scope = [
        c for c in own if c["classification"] == "in_scope" and c["update_type"] != "digest"
    ]
    held = [
        c
        for c in own
        if c["classification"] == "held_by_policy"
        and (order := version_order(ecosystem, c["version"], to)) is not None
        and order >= 0
    ]
    if held:
        c = held[0]
        return f"the scan's candidate {c['version']} in {file} is held by policy ({c['held_by']})"
    comparable = [c for c in in_scope if version_order(ecosystem, c["version"], to) is not None]
    if comparable:
        newest = max(
            comparable,
            key=cmp_to_key(lambda a, b: version_order(ecosystem, a["version"], b["version"]) or 0),
        )
        return (
            f"the scan's newest in-scope candidate in {file} is {newest['version']}, "
            f"older than {to}"
        )
    versions = ", ".join(c["version"] for c in own)
    return f"the scan's candidates in {file} ({versions}) can't be compared with {to}"


def _held(holding: list[str], note: str | None = None) -> dict[str, Any]:
    held = {"result": "held_by_policy", "held_by": "; ".join(holding)}
    return held | {"reason": note} if note else held


def _missed(reason: str) -> dict[str, Any]:
    return {"result": "missed", "reason": reason}


def _unique(items) -> list[str]:
    return list(dict.fromkeys(items))


def _unique_entries(entries) -> list[dict[str, Any]]:
    return list({d["id"]: d for d in entries}.values())


def name_key(ecosystem: str | None, name: str) -> str:
    """The name as the ecosystem compares it. An image's is its path; registries are compared
    separately, because Dependabot leaves them out."""
    if ecosystem == "nuget":  # NuGet ids are case-insensitive
        return name.casefold()
    if ecosystem in _IMAGES:
        return image_parts(name)[1]
    if ecosystem == "github-actions":  # `owner/repo/path` is the action `owner/repo`
        return "/".join(name.split("/")[:2]).casefold()
    if ecosystem == "pip":  # PEP 503
        return re.sub(r"[-_.]+", "-", name).lower()
    return name  # Go module paths, among others, are exact


def same_version(ecosystem: str | None, a: str, b: str) -> bool:
    """Whether two versions are the same: image tags by their text, as registries do, and
    other versions by their order, so `10.0.12` is `10.0.12.0` and NuGet ignores case."""
    if ecosystem in _IMAGES:
        return bare(a) == bare(b)
    order = version_order(ecosystem, a, b)
    return order == 0 if order is not None else bare(a) == bare(b)


def version_order(ecosystem: str | None, a: str, b: str) -> int | None:
    """-1, 0 or 1 as `a` is older than, the same as or newer than `b`; None when the
    ecosystem's versions can't tell."""
    if ecosystem == "nuget":  # NuGet's prerelease labels ignore case
        a, b = a.lower(), b.lower()
    if a == b:
        return 0
    if ecosystem in _IMAGES:
        x, y = _TAG.match(a), _TAG.match(b)
        if x is None or y is None or x["suffix"] != y["suffix"]:
            return None
        return _order(*_padded(x["numbers"], y["numbers"]))
    if ecosystem == "pip":
        try:
            return _order(Version(a), Version(b))
        except InvalidVersion:
            return None
    x, y = _SEMVER.match(a), _SEMVER.match(b)
    if x is None or y is None:
        return None
    return _order(*_padded(x["numbers"], y["numbers"])) or _prerelease(x["pre"], y["pre"])


def _padded(a: str, b: str) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """`1.27` and `1.27.0` are the same version."""
    x, y = [int(p) for p in a.split(".")], [int(p) for p in b.split(".")]
    width = max(len(x), len(y))
    return tuple(x + [0] * (width - len(x))), tuple(y + [0] * (width - len(y)))


def _prerelease(a: str | None, b: str | None) -> int:
    """SemVer's precedence: a release is newer than its prereleases, whose identifiers
    compare numerically when both are numbers, and as text otherwise."""
    if a == b:
        return 0
    if a is None or b is None:
        return 1 if a is None else -1
    for x, y in zip(a.split("."), b.split("."), strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _order(int(x), int(y))
        if x.isdigit() or y.isdigit():
            return -1 if x.isdigit() else 1
        return _order(x, y)
    return _order(len(a.split(".")), len(b.split(".")))


def _order(a, b) -> int:
    return (a > b) - (a < b)
