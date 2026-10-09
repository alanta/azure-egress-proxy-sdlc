import subprocess
from pathlib import Path

import pytest

from sdlc.subject import Revision, SubjectError, checkout, default_branch, resolve


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def origin(tmp_path):
    """A local repository standing in for the subject on GitHub."""
    repo = tmp_path / "origin"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "go.mod").write_text("go 1.25.14\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "first")
    first = git(repo, "rev-parse", "HEAD")
    git(repo, "tag", "v0.1.0")
    git(repo, "tag", "--annotate", "v0.1.1", "-m", "annotated")
    (repo / "go.mod").write_text("go 1.27.1\n")
    git(repo, "commit", "--quiet", "-am", "second")
    second = git(repo, "rev-parse", "HEAD")
    return repo, first, second


def test_branch_resolves_to_its_current_commit(origin):
    repo, _, second = origin
    assert resolve("alanta/demo", "main", url=str(repo)) == Revision(
        "alanta/demo", "main", second, branch="main"
    )


@pytest.mark.parametrize("tag", ["v0.1.0", "v0.1.1"])
def test_tags_resolve_to_the_commit_not_the_tag_object(origin, tag):
    repo, first, _ = origin
    assert resolve("alanta/demo", tag, url=str(repo)).commit == first


def test_full_hash_names_itself(origin):
    repo, first, _ = origin
    assert resolve("alanta/demo", first, url=str(repo)).commit == first


def test_a_tag_or_commit_names_no_branch_so_the_default_branch_is_read(origin):
    repo, first, _ = origin
    assert resolve("alanta/demo", "v0.1.0", url=str(repo)).branch is None
    assert resolve("alanta/demo", first, url=str(repo)).branch is None
    assert default_branch("alanta/demo", url=str(repo)) == "main"


def test_unknown_ref_fails(origin):
    repo, _, _ = origin
    with pytest.raises(SubjectError, match="no branch or tag named 'nope'"):
        resolve("alanta/demo", "nope", url=str(repo))


def test_checkout_holds_exactly_that_commit_and_is_removed(origin):
    repo, first, _ = origin
    with checkout(Revision("alanta/demo", "v0.1.0", first), url=str(repo)) as path:
        assert (path / "go.mod").read_text() == "go 1.25.14\n"
        kept = Path(path)
    assert not kept.exists()


def test_checkout_of_a_commit_the_remote_lacks_fails_and_cleans_up(origin, tmp_path):
    repo, _, _ = origin
    missing = Revision("alanta/demo", "x", "0" * 40)
    before = set(Path(tmp_path).iterdir())
    with pytest.raises(SubjectError), checkout(missing, url=str(repo)):
        pass
    assert set(Path(tmp_path).iterdir()) == before


def test_checkout_leaves_the_origin_untouched(origin):
    repo, _, second = origin
    status_before = git(repo, "status", "--porcelain")
    with checkout(Revision("alanta/demo", "main", second), url=str(repo)):
        pass
    assert git(repo, "rev-parse", "HEAD") == second
    assert git(repo, "status", "--porcelain") == status_before
