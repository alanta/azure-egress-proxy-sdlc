"""The subject repository: resolve a ref to a commit and check that commit out to throw away.

The subject is only ever read. Its clone lives in a temporary directory that is removed when
the scan ends, and nothing is pushed or configured on the remote. Git runs without the
user's or the system's configuration, so URL rewrites, credential helpers and hooks set up
for daily work can't change what the scan sees.
"""

import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

COMMIT = re.compile(r"^[0-9a-f]{40}$")


class SubjectError(Exception):
    """The subject repository or ref can't be read."""


@dataclass(frozen=True)
class Revision:
    repository: str
    ref: str
    commit: str
    branch: str | None = None  # the ref, when it names a branch


def github_url(repository: str) -> str:
    return f"https://github.com/{repository}.git"


def _git(*args: str, cwd: Path | None = None) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    result = subprocess.run(  # noqa: S603 - fixed git command, arguments are data
        ["git", *args],  # noqa: S607 - git from PATH, like any developer tool
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SubjectError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def resolve(repository: str, ref: str, url: str | None = None) -> Revision:
    """Resolve a branch, tag or full commit hash to the commit it names right now."""
    url = url or github_url(repository)
    if COMMIT.match(ref):
        # A full hash names itself; checkout() fails if the remote doesn't have it.
        return Revision(repository, ref, ref)

    listing = _git(
        "ls-remote", url, f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"
    )
    refs = {}
    for line in listing.splitlines():
        commit, name = line.split("\t")
        refs[name] = commit
    # An annotated tag lists both the tag object and, with ^{}, the commit it points to.
    if f"refs/heads/{ref}" in refs:
        return Revision(repository, ref, refs[f"refs/heads/{ref}"], branch=ref)
    for name in (f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}"):
        if name in refs:
            return Revision(repository, ref, refs[name])
    raise SubjectError(f"{repository} has no branch or tag named {ref!r}")


def default_branch(repository: str, url: str | None = None) -> str:
    """The branch the remote's HEAD points to."""
    listing = _git("ls-remote", "--symref", url or github_url(repository), "HEAD")
    for line in listing.splitlines():
        if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD"):
            return line.removeprefix("ref: refs/heads/").removesuffix("\tHEAD")
    raise SubjectError(f"{repository} doesn't say which branch is its default")


@contextmanager
def checkout(revision: Revision, url: str | None = None) -> Iterator[Path]:
    """Yield a directory holding exactly that commit; it is deleted afterwards."""
    url = url or github_url(revision.repository)
    with tempfile.TemporaryDirectory(prefix="sdlc-subject-") as tmp:
        path = Path(tmp)
        _git("init", "--quiet", cwd=path)
        _git("fetch", "--quiet", "--depth=1", url, revision.commit, cwd=path)
        _git("checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=path)
        head = _git("rev-parse", "HEAD", cwd=path).strip()
        if head != revision.commit:
            raise SubjectError(f"checked out {head}, expected {revision.commit}")
        yield path
