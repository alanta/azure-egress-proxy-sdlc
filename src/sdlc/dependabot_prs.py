"""Read the subject's open Dependabot PRs and the updates they propose.

Dependabot is the baseline the scan has to match (design decision 7), so each open PR by
`dependabot[bot]` is broken down into the updates it proposes, one per dependency: its name,
the version it moves from and to, the update type, the package ecosystem, the directory and the
group. Comparing them with the scan's candidates comes after this.

Where each part comes from:
- names, target versions, update types and groups from the `updated-dependencies` block
  Dependabot writes at the end of its commit message. That block, and nothing else, goes through
  a YAML parser, one that builds only strings, lists and maps, so `3.10` stays `3.10`;
- from-versions from fixed `… from A to B` lines in the PR's title, the commit message above
  the block, and the body above its first `<details>` or `<blockquote>`, where upstream release
  notes start. Dependabot words them differently per ecosystem: `Updates `x` from` for most,
  `Updated [x](…) from` in NuGet bodies and `Bumps x from` in NuGet commits;
- what each file had, from the PR's diff (see `pr_diff`), which is always read. A text-stated
  from-version must be among the diff's versions for the dependency, when it has any. When the
  text has none, as for #98's Azure.Core, the diff's versions are the from-versions;
- an update type the block lacks (Docker's) from the two versions: the first number that
  differs, so `3.12-alpine` to `3.14-alpine` is minor;
- the ecosystem from Dependabot's branch name, and the directory from the `Bumps the … group …
  /dir …` line or the title's `in /dir`. Neither is always there: NuGet PRs name no directory.

PR text is written by Dependabot from upstream data (decision 9): beyond these fixed patterns,
nothing in it is read. A PR whose updates can't all be read this way, such as one without the
block, with a dependency neither its text nor its diff gives a from-version, with a diff
GitHub cuts short, with a commit not by Dependabot, or whose head moves while it is read, is
`unparseable` with the reason.
It then lists no updates, so a partial reading never passes for a complete one.

Only GET requests are made, with the scan's token. When the PRs can't be listed, the source is
an `unavailable_source` gap and nothing is said about them; a PR whose commits can't be read is
unparseable.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import yaml

from sdlc.dependabot import API, Response, Unavailable, decode, fetch, get, next_page
from sdlc.pr_diff import FileVersion, bare, removed_versions

SUBJECT = "dependabot-prs"  # the gap's subject when the PRs can't be read
BOT = "dependabot[bot]"
COMMITTER = "web-flow"  # GitHub, which commits and signs Dependabot's changes
WHAT = "pull requests"
PERMISSION = "Pull requests: read"
MAX_BLOCK = 64 * 1024  # bytes; Dependabot's blocks are a few hundred per dependency

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
# The block is a YAML document of its own: `---`, the list, then `...`.
_BLOCK = re.compile(r"^---\n(updated-dependencies:\n.*?)^\.\.\.$", re.MULTILINE | re.DOTALL)
_TOKEN = re.compile(r"^\S+$")
_UPDATE_TYPE = re.compile(r"^version-update:semver-(major|minor|patch)$")

# `Updates `x` from A to B`: the body and commit of most ecosystems.
_UPDATES = re.compile(r"^Updates `(?P<name>[^`\s]+)` from (?P<old>\S+) to (?P<new>\S+)$")
# `Updated [x](url) from A to B.` (NuGet bodies), `Bumps [x](url) from A to B.` (single updates).
_LINKED = re.compile(
    r"^(?:Updated|Bumps) \[(?P<name>[^\]\s]+)\]\([^)\s]*\) from (?P<old>\S+) to (?P<new>\S+)\.$"
)
# `Bumps x from A to B`: NuGet's commits.
_BUMPS = re.compile(r"^Bumps (?P<name>[^\s\[\]]+) from (?P<old>\S+) to (?P<new>\S+)$")
# A single update's title: `nuget: Bump x from A to B`, `bump x from A to B in /dir in the g group`.
_TITLE = re.compile(
    r"^(?:\S+: )?[Bb]ump (?P<name>\S+) from (?P<old>\S+) to (?P<new>\S+)"
    r"(?: in (?P<directory>/\S*))?(?: in the \S+ group)?$"
)
# Which dependencies of a group are in which directory.
_GROUP_IN = (
    re.compile(
        r"^Bumps the \S+ group with \d+ updates? in the (?P<directory>/\S*) directory: "
        r"(?P<names>.+)\.$"
    ),
    re.compile(r"^Bumps the \S+ group in (?P<directory>/\S*) with \d+ updates?: (?P<names>.+)\.$"),
)
_NOTES = re.compile(r"<(?:details|blockquote)\b", re.IGNORECASE)
_LISTED = re.compile(r"\[(?P<linked>[^\]\s]+)\]\([^)\s]*\)|(?P<plain>[^\s,\[\]()]+)")
_BRANCH = re.compile(r"^dependabot/(?P<manager>[a-z_]+)/")
_NUMBERS = re.compile(r"^v?(\d+(?:\.\d+)*)")

# Dependabot's package managers in its branch names, as dependabot.yml's package-ecosystem.
ECOSYSTEMS = {
    "bundler": "bundler",
    "cargo": "cargo",
    "composer": "composer",
    "devcontainers": "devcontainers",
    "docker": "docker",
    "docker_compose": "docker-compose",
    "github_actions": "github-actions",
    "go_modules": "gomod",
    "gradle": "gradle",
    "maven": "maven",
    "npm_and_yarn": "npm",
    "nuget": "nuget",
    "pip": "pip",
    "terraform": "terraform",
    "uv": "uv",
}


@dataclass(frozen=True)
class Update:
    name: str
    # The version it replaces: as the text states it, or else the diff's (without a leading `v`)
    # when the diff has only one.
    from_version: str | None
    to_version: str
    update_type: str | None  # major, minor or patch; None when the versions don't tell
    update_type_derived: bool  # derived from the versions, because the block had none
    ecosystem: str | None  # dependabot.yml's package-ecosystem, from the branch name
    directory: str | None  # as Dependabot writes it, such as `/proxy`; None when not said
    group: str | None
    from_source: str = "text"  # `text`, or `diff` when no line of the text gave it
    # What the diff removes, per file; any of them may differ from a text-stated version.
    from_versions: tuple[FileVersion, ...] = ()


@dataclass(frozen=True)
class PullRequest:
    number: int
    title: str
    url: str
    head: str  # the commit the updates were read from
    base: str  # the branch it targets
    state: str  # `parsed` or `unparseable`
    updates: tuple[Update, ...]  # empty when unparseable
    reason: str | None = None  # why it is unparseable


@dataclass(frozen=True)
class PullRequests:
    read_at: str
    pull_requests: list[PullRequest]


class _Unparseable(Exception):
    """The PR's updates can't all be read; the message says why."""


def read(
    repository: str,
    token: str | None,
    *,
    get: Callable[[str, str], Response] = get,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> PullRequests:
    """The repository's open Dependabot PRs, every page, each with its proposed updates."""
    if not token:
        raise Unavailable(
            f"No token in SDLC_GITHUB_TOKEN; reading Dependabot's PRs needs one with {PERMISSION}."
        )
    read_at = now().isoformat(timespec="seconds")
    listed: dict[int, dict[str, Any]] = {}
    for page in _pages(get, f"{API}/repos/{repository}/pulls?state=open&per_page=100", token):
        if not isinstance(page, list) or not all(_is_pull(p) for p in page):
            raise Unavailable("GitHub's answer isn't a list of pull requests.")
        # A PR can move to the next page while the pages are read; it counts once.
        for pull in page:
            if pull["user"]["login"] == BOT:
                listed.setdefault(pull["number"], pull)
    return PullRequests(
        read_at,
        [_read_pull(get, repository, token, listed[n]) for n in sorted(listed)],
    )


def parse(
    pull: dict[str, Any],
    commits: list[dict[str, Any]],
    files: Callable[[], list[dict[str, Any]]] | None = None,
) -> PullRequest:
    """A PR's proposed updates, from the API's PR and its commits; `unparseable` if incomplete.

    `files` gives the PR's changed files as the API lists them, with their patches. It is only
    called when the text gives some dependency no from-version, and may raise Unavailable.
    """
    try:
        updates = _updates(pull, commits, files)
    except _Unparseable as error:
        return _unparseable(pull, str(error))
    return PullRequest(**_header(pull), state="parsed", updates=updates)


def derive_update_type(old: str, new: str) -> str | None:
    """major, minor or patch by the first number that differs; None when that tells nothing.

    Only the leading numbers count, so an image tag's suffix (`-alpine`) doesn't matter. Equal
    numbers, a lower new number or a version without numbers give None.
    """
    a, b = _NUMBERS.match(old), _NUMBERS.match(new)
    if a is None or b is None:
        return None
    x, y = ([int(p) for p in m.group(1).split(".")] for m in (a, b))
    width = max(len(x), len(y))
    x, y = x + [0] * (width - len(x)), y + [0] * (width - len(y))
    for index, (p, q) in enumerate(zip(x, y, strict=True)):
        if p != q:
            return None if q < p else ("major", "minor")[index] if index < 2 else "patch"
    return None


def _read_pull(
    get: Callable[[str, str], Response], repository: str, token: str, pull: dict[str, Any]
) -> PullRequest:
    url = f"{API}/repos/{repository}/pulls/{pull['number']}/commits?per_page=100"
    commits: list[dict[str, Any]] = []
    try:
        for page in _pages(get, url, token):
            if not isinstance(page, list) or not all(_is_commit(c) for c in page):
                raise Unavailable("GitHub's answer isn't a list of commits.")
            commits += page
    except Unavailable as error:
        return _unparseable(pull, f"its commits couldn't be read: {error}")
    head = pull["head"]["sha"]
    return parse(pull, commits, lambda: _files(get, repository, token, pull["number"], head))


def _files(
    get: Callable[[str, str], Response], repository: str, token: str, number: int, head: str
) -> list[dict[str, Any]]:
    """The PR's changed files at `head`, all of them, or Unavailable.

    The files API names no commit, so the PR's head is read before and after the pages: if it
    moved, the files may belong to another commit than the one the commits were read for.
    """
    url = f"{API}/repos/{repository}/pulls/{number}"
    # The list stops at 3000 files; the PR's own count shows whether it has them all.
    count = _changed_files(get, url, token, head)
    files: list[dict[str, Any]] = []
    for page in _pages(get, f"{url}/files?per_page=100", token):
        if not isinstance(page, list) or not all(_is_file(f) for f in page):
            raise Unavailable("GitHub's answer isn't a list of changed files.")
        files += page
    _changed_files(get, url, token, head)
    if len(files) != count:
        raise Unavailable(f"GitHub listed {len(files)} of the {count} files the PR changes.")
    return files


def _changed_files(get: Callable[[str, str], Response], url: str, token: str, head: str) -> int:
    """How many files the PR changes, after checking its head is still `head`."""
    pull = decode(fetch(get, url, token, what=WHAT, permission=PERMISSION))
    if not isinstance(pull, dict):
        raise Unavailable("GitHub's answer isn't a pull request.")
    now = (pull.get("head") or {}).get("sha") if isinstance(pull.get("head"), dict) else None
    if now != head:
        raise Unavailable(f"its head moved from {head[:7]} to {str(now)[:7]} while it was read.")
    count = pull.get("changed_files")
    if not isinstance(count, int) or isinstance(count, bool):
        raise Unavailable("GitHub's answer doesn't say how many files the PR changes.")
    return count


def _header(pull: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": pull["number"],
        "title": pull["title"],
        "url": pull["html_url"],
        "head": pull["head"]["sha"],
        "base": pull["base"]["ref"],
    }


def _unparseable(pull: dict[str, Any], reason: str) -> PullRequest:
    return PullRequest(**_header(pull), state="unparseable", updates=(), reason=reason)


def _pages(get: Callable[[str, str], Response], url: str | None, token: str):
    """Each page's JSON, following GitHub's `next` links within its API."""
    fetched: set[str] = set()
    while url:
        if url in fetched:
            raise Unavailable(f"GitHub's pagination links back to a page already read: {url}")
        fetched.add(url)
        response = fetch(get, url, token, what=WHAT, permission=PERMISSION)
        yield decode(response)
        url = next_page(response.headers.get("link"))


def _updates(
    pull: dict[str, Any],
    commits: list[dict[str, Any]],
    files: Callable[[], list[dict[str, Any]]] | None,
) -> tuple[Update, ...]:
    if not commits:
        raise _Unparseable("it has no commits to read the updated-dependencies block from")
    if commits[-1]["sha"] != pull["head"]["sha"]:
        raise _Unparseable("its head commit changed while it was read")
    # Someone else's commit could change what the PR does, or write a block of its own.
    if not all(_by_dependabot(c) for c in commits):
        raise _Unparseable("it has commits by others than Dependabot")
    blocks = {}
    for commit in commits:
        message = commit["commit"]["message"].replace("\r\n", "\n")
        found = list(_BLOCK.finditer(message))
        if len(found) > 1:
            raise _Unparseable("a commit message has more than one updated-dependencies block")
        if found:
            blocks.setdefault(found[0].group(1), message[: found[0].start()])
    if not blocks:
        raise _Unparseable("no commit message has an updated-dependencies block")
    if len(blocks) > 1:
        raise _Unparseable("its commits carry different updated-dependencies blocks")
    ((block, above),) = blocks.items()
    entries = _entries(block)

    # Release notes and changelogs, which upstream authors write, start at the body's first
    # `<details>` or `<blockquote>`; nothing from there on is read. Dependabot puts a grouped
    # PR's later lines below an earlier one's notes, but its commit message has them all.
    body = pull["body"] or ""
    notes = _NOTES.search(body)
    text = [pull["title"], *body[: notes.start() if notes else None].splitlines()]
    text += above.splitlines()
    lines = [line.strip() for line in text]
    proposed: dict[str, set[tuple[str, str]]] = {}  # name -> {(from, to)}
    directories: dict[str, set[str]] = {}
    title = _TITLE.match(pull["title"].strip())
    if title:
        proposed.setdefault(title["name"], set()).add((title["old"], title["new"]))
        if title["directory"]:
            directories.setdefault(title["name"], set()).add(title["directory"])
    for line in lines:
        for pattern in (_UPDATES, _LINKED, _BUMPS):
            if match := pattern.match(line):
                proposed.setdefault(match["name"], set()).add((match["old"], match["new"]))
        for pattern in _GROUP_IN:
            if match := pattern.match(line):
                for name in _listed(match["names"]):
                    directories.setdefault(name, set()).add(match["directory"])

    targets: dict[str, set[str]] = {}
    for name, version, _, _ in entries:
        targets.setdefault(name, set()).add(version)
    gaps = []
    for name, pairs in sorted(proposed.items()):
        if name in targets and (others := sorted({new for _, new in pairs} - targets[name])):
            gaps.append(
                f"its text moves {name} to {', '.join(others)}, its metadata to "
                f"{', '.join(sorted(targets[name]))}"
            )
    stated = {
        (name, version): sorted({old for old, new in proposed.get(name, ()) if new == version})
        for name, version, _, _ in entries
    }
    # Always read: the text may only be trusted where the diff, which Dependabot writes
    # mechanically, doesn't contradict it.
    diff = _diff(files, {name for name, _ in stated})

    match = _BRANCH.match(pull["head"]["ref"])
    ecosystem = ECOSYSTEMS.get(match["manager"]) if match else None
    updates = []
    for name, version, update_type, group in entries:
        froms = stated[name, version]
        if len(froms) > 1:
            gaps.append(f"its lines move {name} to {version} from {' and '.join(froms)}")
            continue
        removed = tuple(diff.removed[name])
        if froms:
            # Files at other versions too are fine: they go into from_versions.
            source, from_version = "text", froms[0]
            if removed and not any(r.version == bare(from_version) for r in removed):
                gaps.append(
                    f"its text moves {name} from {from_version}, its diff from "
                    f"{', '.join(sorted({r.version for r in removed}))}"
                )
                continue
        elif removed:
            source = "diff"
            distinct = {r.version for r in removed}  # without a leading `v`
            from_version = distinct.pop() if len(distinct) == 1 else None
        else:
            gaps.append(
                f"neither its title, body and commit message nor its diff say which version "
                f"{name} {version} replaces"
            )
            continue
        derived = update_type is None
        if derived:
            update_type = derive_update_type(from_version, version) if from_version else None
        where = directories.get(name, set())
        updates.append(
            Update(
                name=name,
                from_version=from_version,
                to_version=version,
                update_type=update_type,
                update_type_derived=derived,
                ecosystem=ecosystem,
                directory=next(iter(where)) if len(where) == 1 else None,
                group=group,
                from_source=source,
                from_versions=removed,
            )
        )
    if gaps:
        raise _Unparseable("; ".join(gaps))
    return tuple(updates)


def _diff(files: Callable[[], list[dict[str, Any]]] | None, names: set[str]):
    """What the PR's diff removes for the names; unparseable when it can't all be read."""
    if files is None:
        raise _Unparseable("its diff wasn't read")
    try:
        reading = removed_versions(files(), names)
    except Unavailable as error:
        raise _Unparseable(f"its changed files couldn't be read: {error}") from error
    if reading.problems:
        raise _Unparseable("; ".join(reading.problems))
    return reading


def _entries(block: str) -> list[tuple[str, str, str | None, str | None]]:
    """(name, to-version, update type, group) per dependency in the block, each once."""
    if len(block.encode()) > MAX_BLOCK:
        raise _Unparseable(f"its updated-dependencies block is over {MAX_BLOCK // 1024} KiB")
    try:
        # BaseLoader builds only strings, lists and maps: no tags, no numbers, no objects.
        data = yaml.load(block, Loader=yaml.BaseLoader)  # noqa: S506
    except RecursionError as error:
        raise _Unparseable("its updated-dependencies block is nested too deeply") from error
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark else ""
        problem = getattr(error, "problem", None) or "malformed"
        raise _Unparseable(
            f"its updated-dependencies block isn't valid YAML ({problem}{where})"
        ) from error
    listed = data.get("updated-dependencies") if isinstance(data, dict) else None
    if not isinstance(listed, list) or not listed:
        raise _Unparseable("its updated-dependencies block lists no dependencies")
    entries: dict[tuple[str, str], tuple[str, str, str | None, str | None]] = {}
    for index, entry in enumerate(listed, 1):
        if not isinstance(entry, dict):
            raise _Unparseable(f"entry {index} of its updated-dependencies block isn't a map")
        name, version = entry.get("dependency-name"), entry.get("dependency-version")
        update_type, group = entry.get("update-type"), entry.get("dependency-group")
        if not (isinstance(name, str) and _TOKEN.match(name)):
            raise _Unparseable(f"entry {index} of its updated-dependencies block has no name")
        if not (isinstance(version, str) and _TOKEN.match(version)):
            raise _Unparseable(f"{name} has no dependency-version in its metadata")
        kind = _UPDATE_TYPE.match(update_type) if isinstance(update_type, str) else None
        if update_type is not None and kind is None:
            raise _Unparseable(f"{name} has an update-type that isn't semver major, minor or patch")
        if group is not None and not (isinstance(group, str) and _TOKEN.match(group)):
            raise _Unparseable(f"{name} has a dependency-group that isn't a name")
        found = (name, version, kind.group(1) if kind else None, group)
        # Dependabot repeats a dependency it updates in several projects (#98's Azure.Core);
        # the repeats must say the same.
        if entries.setdefault((name, version), found) != found:
            raise _Unparseable(
                f"its updated-dependencies block lists {name} {version} twice, with different "
                "update types or groups"
            )
    return list(entries.values())


def _listed(names: str) -> list[str]:
    """The names in `[a](url), b and [c](url)`; none when an item isn't a plain or linked name."""
    found = []
    for item in re.split(r", | and ", names):
        match = _LISTED.fullmatch(item)
        if match is None:
            return []
        found.append(match["linked"] or match["plain"])
    return found


def _is_pull(pull: Any) -> bool:
    """Whether every field the parsing reads has the type it expects."""
    if not isinstance(pull, dict):
        return False
    number, user = pull.get("number"), pull.get("user")
    head, base = pull.get("head"), pull.get("base")
    return bool(
        isinstance(number, int)
        and not isinstance(number, bool)
        and number >= 1
        and isinstance(user, dict)
        and isinstance(user.get("login"), str)
        and isinstance(pull.get("title"), str)
        and (pull.get("body") is None or isinstance(pull.get("body"), str))
        and isinstance(pull.get("html_url"), str)
        and isinstance(head, dict)
        and isinstance(head.get("sha"), str)
        and _COMMIT.match(head["sha"])
        and isinstance(head.get("ref"), str)
        and isinstance(base, dict)
        and isinstance(base.get("ref"), str)
    )


def _is_file(changed: Any) -> bool:
    return bool(
        isinstance(changed, dict)
        and isinstance(changed.get("filename"), str)
        and changed["filename"]
        and (changed.get("patch") is None or isinstance(changed["patch"], str))
        and all(
            isinstance(changed.get(k), int) and not isinstance(changed.get(k), bool)
            for k in ("additions", "deletions")
        )
    )


def _by_dependabot(commit: dict[str, Any]) -> bool:
    """Authored by Dependabot, and committed and signed by GitHub on its behalf."""
    author, committer = commit.get("author"), commit.get("committer")
    verification = commit["commit"].get("verification")
    return bool(
        isinstance(author, dict)
        and author.get("login") == BOT
        and isinstance(committer, dict)
        and committer.get("login") == COMMITTER
        and isinstance(verification, dict)
        and verification.get("verified") is True
    )


def _is_commit(commit: Any) -> bool:
    if not isinstance(commit, dict) or not isinstance(commit.get("commit"), dict):
        return False
    sha = commit.get("sha")
    return bool(
        isinstance(sha, str)
        and _COMMIT.match(sha)
        and isinstance(commit["commit"].get("message"), str)
    )
