import copy
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sdlc.dependabot import Response, Unavailable
from sdlc.dependabot_prs import Update, derive_update_type, parse, read
from sdlc.pr_diff import FileVersion, bare, removed_versions

PRS = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy" / "prs"
REPO = "alanta/azure-egress-proxy"
TOKEN = "a-token"  # noqa: S105 - a fake, never sent anywhere
AT = "2026-10-09T09:00:00+00:00"
PULLS_URL = f"https://api.github.com/repos/{REPO}/pulls?state=open&per_page=100"


def captured(number):
    """The PR and its commits as GitHub's API returned them in 1.1."""
    pull = json.loads((PRS / str(number) / "pr.json").read_text())
    commits = json.loads((PRS / str(number) / "commits.json").read_text())
    return pull, commits


def changed_files(number):
    """The PR's changed files, with their patches, as GitHub's files API returned them."""
    return json.loads((PRS / str(number) / "files.json").read_text())


def parsed(number):
    return parse(*captured(number), lambda: changed_files(number))


def text_only(pull):
    """The updates without what the diff adds, which the tests check on their own."""
    return tuple(dataclasses.replace(u, from_versions=()) for u in pull.updates)


def versions(pull):
    return {u.name: (u.from_version, u.to_version) for u in pull.updates}


def commits_url(number):
    return f"https://api.github.com/repos/{REPO}/pulls/{number}/commits?per_page=100"


def ok(body, link=None):
    headers = {"link": link} if link else {}
    return Response(200, headers, json.dumps(body).encode())


def refused(status, message, **headers):
    return Response(status, headers, json.dumps({"message": message}).encode())


class FakeGitHub:
    """GitHub's API, answering from a table of URL to response; a missing URL fails the test."""

    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def __call__(self, url, token):
        self.requests.append((url, token))
        response = self.responses[url]
        if isinstance(response, list):  # one answer per request, in turn
            response = response.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def pull_url(number):
    return f"https://api.github.com/repos/{REPO}/pulls/{number}"


def files_url(number):
    return f"{pull_url(number)}/files?per_page=100"


def github_with(*numbers, pulls_page=None):
    """The open PRs listed on one page, with each one's captured commits and changed files."""
    pulls = [captured(n)[0] for n in numbers]
    responses = {PULLS_URL: pulls_page or ok(pulls)}
    for n in numbers:
        responses[commits_url(n)] = ok(captured(n)[1])
        responses[pull_url(n)] = ok(captured(n)[0] | {"changed_files": len(changed_files(n))})
        responses[files_url(n)] = ok(changed_files(n))
    return FakeGitHub(responses)


def read_from(github, token=TOKEN):
    return read(REPO, token, get=github, now=lambda: datetime.fromisoformat(AT).astimezone(UTC))


@pytest.mark.parametrize("number", [75, 76, 77, 98, 99, 78, 88, 89])
def test_every_captured_pr_parses(number):
    pull = parsed(number)
    assert pull.state == "parsed", pull.reason
    assert pull.reason is None
    assert pull.updates
    # Every update has a from-version, from the text or else the diff.
    assert all((u.from_version or u.from_versions) and u.to_version for u in pull.updates)


def test_the_pr_keeps_its_number_title_head_and_url():
    pull = parsed(99)
    assert pull.number == 99
    assert pull.title == "proxy: bump the gomod-minor-patch group in /proxy with 2 updates"
    assert pull.head == "7aea49513678ed1c3b0aa0f183f45f23e7d65a81"
    assert pull.url == "https://github.com/alanta/azure-egress-proxy/pull/99"
    assert pull.base == "main"


def test_grouped_action_bumps_give_every_dependency():
    pull = parsed(75)
    assert {(u.name, f.file, f.version) for u in pull.updates for f in u.from_versions} == {
        ("azure/login", ".github/workflows/allowlist.yml", "3.0.2"),
        ("azure/login", ".github/workflows/deploy.yml", "3.0.2"),
        ("docker/setup-qemu-action", ".github/workflows/release.yml", "4.3.0"),
        ("docker/setup-buildx-action", ".github/workflows/release.yml", "4.3.0"),
    }
    assert text_only(pull) == (
        Update(
            "azure/login", "3.0.2", "3.1.0", "minor", False, "github-actions", "/",
            "actions-minor-patch",
        ),
        Update(
            "docker/setup-buildx-action", "4.3.0", "4.4.1", "minor", False, "github-actions", "/",
            "actions-minor-patch",
        ),
        Update(
            "docker/setup-qemu-action", "4.3.0", "4.4.0", "minor", False, "github-actions", "/",
            "actions-minor-patch",
        ),
    )  # fmt: skip


def test_grouped_docker_bumps_get_derived_update_types_and_their_own_directories():
    # #76's block has no update-type, and its group spans two directories.
    assert text_only(parsed(76)) == (
        Update(
            "library/golang", "1.25-alpine", "1.27-alpine", "minor", True, "docker", "/proxy",
            "docker-minor-patch",
        ),
        Update(
            "python", "3.12-alpine", "3.14-alpine", "minor", True, "docker", "/mock-idp",
            "docker-minor-patch",
        ),
    )  # fmt: skip


def test_grouped_go_module_bumps_give_every_dependency():
    pull = parsed(99)
    assert versions(pull) == {
        "github.com/Azure/azure-sdk-for-go/sdk/azcore": ("1.23.1", "1.23.2"),
        "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob": ("1.8.1", "1.8.2"),
    }
    assert {(u.update_type, u.update_type_derived) for u in pull.updates} == {("patch", False)}
    assert {(u.ecosystem, u.directory, u.group) for u in pull.updates} == {
        ("gomod", "/proxy", "gomod-minor-patch")
    }


def test_the_nuget_lock_file_pr_takes_its_from_version_from_the_title():
    # #77's body only says "Pinned … at 10.0.12"; the title has both versions.
    (update,) = text_only(parsed(77))
    assert update == Update(
        "Microsoft.Extensions.Http", "10.0.11", "10.0.12", "patch", False, "nuget", None,
        "microsoft",
    )  # fmt: skip


def test_a_single_go_update_reads_its_directory_from_the_title_and_body():
    (update,) = parsed(88).updates
    pseudo = "0.0.5-0.20260706062719-a3294a6cc4e4"
    assert (update.from_version, update.to_version) == (pseudo, "0.1.0")
    assert (update.ecosystem, update.directory, update.group) == (
        "gomod", "/proxy", "gomod-minor-patch",
    )  # fmt: skip


def test_grouped_nuget_bumps_read_nuget_s_wording():
    # #89's body says "Updated [x](…) from A to B.", its commit "Bumps x from A to B".
    assert versions(parsed(89)) == {
        "Azure.Core": ("1.62.0", "1.63.0"),
        "coverlet.collector": ("10.0.1", "10.1.0"),
        "Scalar.AspNetCore": ("2.17.9", "2.17.10"),
    }
    assert versions(parsed(78)) == {"Microsoft.OpenApi": ("2.12.2", "3.10.2")}
    assert parsed(78).updates[0].update_type == "major"


def test_98_reads_azure_core_s_from_versions_from_its_diff():
    # Dependabot writes "Bumps Azure.Core to 1.63.0" and "Pinned … at 1.63.0": the central
    # version is 1.62.0, but some projects lock older ones, so there is no one from-version.
    pull = parsed(98)
    assert pull.state == "parsed", pull.reason
    core, coverlet, scalar = pull.updates
    assert (core.name, core.from_version, core.from_source, core.to_version) == (
        "Azure.Core", None, "diff", "1.63.0",
    )  # fmt: skip
    assert core.update_type == "minor"
    removed = {(f.file, f.version) for f in core.from_versions}
    assert {
        ("Directory.Packages.props", "1.62.0"),
        ("src/EgressProxy.Client/packages.lock.json", "1.53.0"),
        ("src/EgressProxy.Client.Tests/packages.lock.json", "1.53.0"),
        ("src/AppHost/AllowlistSeeder/packages.lock.json", "1.55.0"),
    } <= removed
    assert {v for _, v in removed} == {"1.62.0", "1.55.0", "1.53.0"}
    # The others keep their text's from-version, which the diff agrees with.
    assert (coverlet.from_version, coverlet.from_source) == ("10.0.1", "text")
    assert (scalar.from_version, scalar.from_source) == ("2.17.9", "text")
    assert {f.version for f in scalar.from_versions} == {"2.17.9"}
    assert FileVersion("Directory.Packages.props", "2.17.9", "2.17.9") in scalar.from_versions


def test_a_pr_without_its_diff_is_unparseable():
    # The diff is always read, even when the text gives every from-version.
    pull = parse(*captured(99))
    assert (pull.state, pull.updates, pull.reason) == ("unparseable", (), "its diff wasn't read")


def test_release_notes_cannot_set_a_from_version():
    # Upstream writes what follows the first <details>; a line there in Dependabot's wording
    # is not read. Azure.Core's from-versions still come from the diff.
    pull, commits = copy.deepcopy(captured(98))
    injected = "Updated [Azure.Core](https://example.com) from 1.0.0 to 1.63.0."
    pull["body"] = pull["body"].replace("<details>", f"<details>\n{injected}\n", 1)
    found = parse(pull, commits, lambda: changed_files(98))
    assert found.state == "parsed", found.reason
    core = found.updates[0]
    assert (core.from_source, core.from_version) == ("diff", None)
    # Also in a <blockquote>, and whatever the case of the tag.
    pull["body"] = f"<BlockQuote>\n{injected}\n</BlockQuote>\n{pull['body']}"
    assert parse(pull, commits, lambda: changed_files(98)).updates[0].from_source == "diff"


def test_a_text_from_version_the_diff_doesn_t_mention_stands():
    pull = parse(*captured(99), lambda: [])
    assert pull.state == "parsed", pull.reason
    assert {(u.from_version, u.from_source, u.from_versions) for u in pull.updates} == {
        ("1.23.1", "text", ()),
        ("1.8.1", "text", ()),
    }


def test_98_parses_once_azure_core_has_a_from_version():
    # Its three identical Azure.Core entries count once, and the others' from-versions come
    # from the body (coverlet) and the commit message (Scalar).
    pull, commits = captured(98)
    pull = copy.deepcopy(pull)
    line = "Updated [Azure.Core](https://example.com) from 1.62.0 to 1.63.0."
    pull["body"] = f"{line}\n{pull['body']}"
    assert versions(parse(pull, commits, lambda: changed_files(98))) == {
        "Azure.Core": ("1.62.0", "1.63.0"),
        "coverlet.collector": ("10.0.1", "10.1.0"),
        "Scalar.AspNetCore": ("2.17.9", "2.17.13"),
    }


def corrupted(number, change, files=None):
    pull, commits = copy.deepcopy(captured(number))
    message = commits[-1]["commit"]["message"]
    pull["body"], commits[-1]["commit"]["message"] = change(pull["body"], message)
    return parse(pull, commits, files or (lambda: changed_files(number)))


def in_message(old, new):
    """A change to the commit message only, where the block is."""
    return lambda body, message: (body, message.replace(old, new, 1))


def in_body(old, new):
    return lambda body, message: (body.replace(old, new, 1), message)


def in_both(old, new):
    return lambda body, message: (body.replace(old, new, 1), message.replace(old, new, 1))


AZCORE = "github.com/Azure/azure-sdk-for-go/sdk/azcore"
AZBLOB = "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
PYTHON_TAG = "!!python/object/apply:os.system [id]"
AZBLOB_ENTRY = f"- dependency-name: {AZBLOB}"
# A repeat of azcore's entry that disagrees on its update type.
AZCORE_AS_MINOR = (
    f"- dependency-name: {AZCORE}\n  dependency-version: 1.23.2\n"
    "  update-type: version-update:semver-minor\n"
)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (in_message("  dependency-version: 1.23.2\n", ""), f"{AZCORE} has no dependency-version"),
        (in_message("\n- dependency-name: g", "\n-dependency-name: g"), "isn't valid YAML"),
        (in_message("version: 1.23.2", "version: [1.23.2"), "isn't valid YAML"),
        (in_message("dependencies:\n- ", "dependencies:\n  "), "isn't valid YAML"),
        (in_message("updated-dependencies:", "updated-dependency:"), "no commit message has"),
        (in_message("\n...\n", "\n"), "no commit message has an updated-dependencies block"),
        (
            in_message("version-update:semver-patch", "patch"),
            f"{AZCORE} has an update-type that isn't semver major, minor or patch",
        ),
        (
            # The parser builds no objects: the tag is ignored, and the entry isn't a map.
            in_message(":\n- dependency-name", f":\n- {PYTHON_TAG}\n- dependency-name"),
            "entry 1 of its updated-dependencies block isn't a map",
        ),
        (
            in_message("Signed-off-by", "---\nupdated-dependencies:\n- dependency-name: x\n...\n"),
            "a commit message has more than one updated-dependencies block",
        ),
        (
            in_message(AZBLOB_ENTRY, f"{AZCORE_AS_MINOR}{AZBLOB_ENTRY}"),
            f"lists {AZCORE} 1.23.2 twice, with different update types or groups",
        ),
        (
            in_message("updated-dependencies:\n", "updated-dependencies:\n" + "#" * 70000 + "\n"),
            "its updated-dependencies block is over 64 KiB",
        ),
        (
            in_message("dependencies:\n- ", f"dependencies:\n- {'[' * 5000}{']' * 5000}\n- "),
            "its updated-dependencies block is nested too deeply",
        ),
        (
            in_body("from 1.23.1 to", "from 1.23.0 to"),
            f"its lines move {AZCORE} to 1.23.2 from 1.23.0 and 1.23.1",
        ),
        (
            in_body("to 1.23.2", "to 1.23.3"),
            f"its text moves {AZCORE} to 1.23.3, its metadata to 1.23.2",
        ),
    ],
)  # fmt: skip
def test_a_corrupted_message_is_unparseable_with_the_reason(change, reason):
    pull = corrupted(99, change)
    assert pull.state == "unparseable"
    assert reason in pull.reason
    # Nothing partial passes for complete.
    assert pull.updates == ()


def test_numbers_in_the_block_stay_text():
    # A YAML parser that resolves types would read 3.10 as the float 3.1.
    def change(body, message):
        body, message = in_both("from 1.8.1 to 1.8.2", "from 3.9 to 3.10")(body, message)
        return body, message.replace("dependency-version: 1.8.2", "dependency-version: 3.10")

    pull = corrupted(99, change, lambda: [])  # no diff lines to disagree with the text
    assert pull.state == "parsed", pull.reason
    assert versions(pull)[AZBLOB] == ("3.9", "3.10")


def test_a_pr_without_commits_or_with_a_moved_head_is_unparseable():
    pull, commits = captured(99)
    assert "no commits" in parse(pull, [], lambda: changed_files(99)).reason
    moved = copy.deepcopy(commits)
    moved[-1]["sha"] = "f" * 40
    assert parse(pull, moved, lambda: changed_files(99)).reason == (
        "its head commit changed while it was read"
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c["author"].update(login="marnix"),
        lambda c: c.update(author=None),
        lambda c: c["committer"].update(login="marnix"),
        lambda c: c["commit"]["verification"].update(verified=False),
        lambda c: c["commit"].pop("verification"),
    ],
)
def test_commits_by_others_make_the_pr_unparseable(change):
    pull, commits = copy.deepcopy(captured(99))
    change(commits[-1])
    found = parse(pull, commits, lambda: changed_files(99))
    assert (found.state, found.updates) == ("unparseable", ())
    assert found.reason == "it has commits by others than Dependabot"


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("3.12-alpine", "3.14-alpine", "minor"),
        ("1.25-alpine", "1.27-alpine", "minor"),
        ("1.25", "2.0", "major"),
        ("v1.2.3", "v1.2.4", "patch"),
        ("10.0.1", "10.0.1.1", "patch"),
        ("1.2", "1.2.0", None),
        ("1.3", "1.2", None),
        ("latest", "1.2", None),
    ],
)
def test_update_types_are_derived_from_the_first_number_that_differs(old, new, expected):
    assert derive_update_type(old, new) == expected


def test_reading_lists_dependabot_s_open_prs_with_their_commits():
    others = copy.deepcopy(captured(99)[0])
    others |= {"number": 100, "user": {"login": "marnix"}}
    pulls = [captured(n)[0] for n in (99, 75)] + [others]
    second = f"{PULLS_URL}&page=2"
    github = github_with(75, 76, 99)
    github.responses[PULLS_URL] = ok(pulls, link=f'<{second}>; rel="next"')
    github.responses[second] = ok([captured(76)[0], captured(75)[0]])
    found = read_from(github)
    assert found.read_at == AT
    assert [p.number for p in found.pull_requests] == [75, 76, 99]
    assert {p.state for p in found.pull_requests} == {"parsed"}
    # Only GETs to the API, each with the token; the other author's PR isn't read further.
    # The PR's head is checked before and after its files are read.
    assert [url for url, _ in github.requests] == [
        PULLS_URL,
        second,
        *(
            url
            for n in (75, 76, 99)
            for url in (commits_url(n), pull_url(n), files_url(n), pull_url(n))
        ),
    ]
    assert {token for _, token in github.requests} == {TOKEN}


def test_no_open_prs_is_an_empty_list():
    assert read_from(FakeGitHub({PULLS_URL: ok([])})).pull_requests == []


def test_commits_on_several_pages_are_all_read():
    _, commits = captured(99)
    first = copy.deepcopy(commits[0]) | {"sha": "e" * 40}
    first["commit"] = {"message": "Rebase on main", "verification": {"verified": True}}
    second = f"{commits_url(99)}&page=2"
    github = github_with(99)
    github.responses[commits_url(99)] = ok([first], link=f'<{second}>; rel="next"')
    github.responses[second] = ok(commits)
    (found,) = read_from(github).pull_requests
    assert found.state == "parsed"


def test_without_a_token_nothing_is_requested():
    github = FakeGitHub({})
    with pytest.raises(Unavailable, match="No token in SDLC_GITHUB_TOKEN"):
        read_from(github, token=None)
    assert github.requests == []


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            refused(403, "Resource not accessible by personal access token"),
            "The token lacks the Pull requests: read permission",
        ),
        (
            refused(404, "Not Found"),
            "The repository or its pull requests aren't visible to the token: it may lack "
            "Pull requests: read",
        ),
        (refused(401, "Bad credentials"), "GitHub rejected the token"),
        (
            refused(403, "API rate limit exceeded", **{"x-ratelimit-remaining": "0"}),
            "GitHub's rate limit was reached",
        ),
        (Response(502, {}, b"<html>Bad gateway</html>"), "GitHub answered 502."),
        (Response(200, {}, b"not json"), "GitHub's answer isn't JSON"),
        (ok({"message": "not a list"}), "isn't a list of pull requests"),
        (ok([{"number": 75}]), "isn't a list of pull requests"),
        (
            Response(302, {"location": "https://example.com/pulls"}, b""),
            "GitHub redirected to https://example.com/pulls, outside its API",
        ),
        (TimeoutError("timed out"), "GitHub's API couldn't be reached: timed out."),
        (
            ok([], link='<https://example.com/pulls?page=2>; rel="next"'),
            "outside its API",
        ),
        (ok([], link=f'<{PULLS_URL}>; rel="next"'), "links back to a page already read"),
    ],
)
def test_prs_that_cannot_be_listed_say_why(response, expected):
    with pytest.raises(Unavailable) as error:
        read_from(FakeGitHub({PULLS_URL: response}))
    assert expected in str(error.value)


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(number="75"),
        lambda p: p.update(number=True),
        lambda p: p.update(title=None),
        lambda p: p.update(body=["Updates"]),
        lambda p: p.update(user=None),
        lambda p: p["head"].update(sha="0a4a56b"),
        lambda p: p["head"].update(ref=None),
        lambda p: p.update(base=None),
        lambda p: p.update(html_url=None),
    ],
)
def test_a_malformed_pr_makes_the_prs_unavailable(change):
    pull = copy.deepcopy(captured(75)[0])
    change(pull)
    with pytest.raises(Unavailable, match="isn't a list of pull requests"):
        read_from(FakeGitHub({PULLS_URL: ok([pull])}))


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (refused(404, "Not Found"), "The repository or its pull requests aren't visible"),
        (ok([{"sha": "x"}]), "GitHub's answer isn't a list of commits."),
        (ok({"commit": {}}), "GitHub's answer isn't a list of commits."),
    ],
)
def test_a_pr_whose_commits_cannot_be_read_is_unparseable(response, expected):
    github = github_with(75, 99)
    github.responses[commits_url(99)] = response
    first, second = read_from(github).pull_requests
    assert first.state == "parsed"
    assert (second.number, second.state, second.updates) == (99, "unparseable", ())
    assert second.reason.startswith(f"its commits couldn't be read: {expected}")


def without_from_lines(*names):
    """Drops every text line that gives one of the names a from-version."""

    def change(body, message):
        def keep(text):
            return "\n".join(
                line
                for line in text.splitlines()
                if not any(n in line and " from " in line for n in names)
            )

        return keep(body), keep(message)

    return change


@pytest.mark.parametrize(
    ("number", "name", "expected"),
    [
        (99, AZBLOB, {FileVersion("proxy/go.mod", "1.8.1", "v1.8.1")}),
        (76, "library/golang", {FileVersion("proxy/Dockerfile", "1.25-alpine", "1.25-alpine")}),
        (76, "python", {FileVersion("mock-idp/Dockerfile", "3.12-alpine", "3.12-alpine")}),
        (
            75,
            "azure/login",
            {
                FileVersion(".github/workflows/allowlist.yml", "3.0.2", "v3.0.2"),
                FileVersion(".github/workflows/deploy.yml", "3.0.2", "v3.0.2"),
            },
        ),
    ],
)
def test_each_file_type_gives_the_version_its_diff_removes(number, name, expected):
    pull = corrupted(number, without_from_lines(name), lambda: changed_files(number))
    assert pull.state == "parsed", pull.reason
    (update,) = [u for u in pull.updates if u.name == name]
    assert (set(update.from_versions), update.from_source) == (expected, "diff")
    # One version, so it is the from-version, without the `v` some files write.
    assert update.from_version == next(iter(expected)).version
    assert update.update_type is not None


def test_a_text_that_disagrees_with_the_diff_is_unparseable():
    def change(body, message):
        return body, message.replace(
            "Scalar.AspNetCore from 2.17.9", "Scalar.AspNetCore from 2.17.8"
        )

    pull = corrupted(98, change, lambda: changed_files(98))
    assert (pull.state, pull.updates) == ("unparseable", ())
    assert pull.reason == "its text moves Scalar.AspNetCore from 2.17.8, its diff from 2.17.9"


def test_a_go_version_with_and_without_v_agrees():
    pull = corrupted(99, without_from_lines(AZBLOB), lambda: changed_files(99))
    (azcore,) = [u for u in pull.updates if u.name == AZCORE]
    assert (azcore.from_version, azcore.from_source) == ("1.23.1", "text")
    assert azcore.from_versions == (FileVersion("proxy/go.mod", "1.23.1", "v1.23.1"),)


def lock_file(patch, name="src/A/packages.lock.json"):
    lines = patch.splitlines()
    return {
        "filename": name,
        "patch": patch,
        "additions": sum(line.startswith("+") for line in lines),
        "deletions": sum(line.startswith("-") for line in lines),
    }


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda f: f.pop("patch"), "GitHub doesn't show the diff of src/ControlPlane/packages"),
        (
            lambda f: f.update(patch="\n".join(f["patch"].splitlines()[:20])),
            "GitHub shows the diff of src/ControlPlane/packages.lock.json cut short",
        ),
    ],
)
def test_a_missing_or_truncated_patch_is_unparseable(change, reason):
    files = changed_files(98)
    change(next(f for f in files if f["filename"] == "src/ControlPlane/packages.lock.json"))
    pull = parse(*captured(98), lambda: files)
    assert (pull.state, pull.updates) == ("unparseable", ())
    assert reason in pull.reason


def test_a_patch_of_a_file_the_scan_doesn_t_read_doesn_t_matter():
    files = [*changed_files(98), {"filename": "README.md", "additions": 9, "deletions": 9}]
    assert parse(*captured(98), lambda: files).state == "parsed"


def test_a_lock_file_line_is_tied_to_its_own_package():
    # Both packages move from 4.84.2; each resolved line belongs to the block it is in.
    patch = """@@ -135,18 +135,18 @@
       "Microsoft.Identity.Client": {
         "type": "Transitive",
-        "resolved": "4.84.2",
+        "resolved": "4.90.0",
         "dependencies": {
-          "Other.Package": "4.83.1"
+          "Other.Package": "4.90.0"
         }
       },
       "Microsoft.Identity.Client.Extensions.Msal": {
         "type": "Transitive",
-        "resolved": "4.84.2",
+        "resolved": "4.90.0",
         "dependencies": {
-          "Microsoft.Identity.Client": "4.83.1",
+          "Microsoft.Identity.Client": "4.90.0",
         }
       },
@@ -300,4 +300,4 @@
         "type": "Transitive",
-        "resolved": "1.0.0",
+        "resolved": "2.0.0",
       },"""
    names = {
        "Microsoft.Identity.Client",
        "Microsoft.Identity.Client.Extensions.Msal",
        "Other.Package",
    }
    reading = removed_versions([lock_file(patch)], names)
    assert reading.problems == []
    file = "src/A/packages.lock.json"
    assert reading.removed == {
        "Microsoft.Identity.Client": [FileVersion(file, "4.84.2", "4.84.2")],
        "Microsoft.Identity.Client.Extensions.Msal": [FileVersion(file, "4.84.2", "4.84.2")],
        # A dependency list's line isn't a resolved version, and the last hunk's resolved
        # line opens no block in sight: neither is guessed at.
        "Other.Package": [],
    }


PROPS = "Directory.Packages.props"
CSPROJ = "src/A/A.csproj"
CI = ".github/workflows/ci.yml"


@pytest.mark.parametrize(
    ("file", "line", "name", "version"),
    [
        (PROPS, '-    <PackageVersion Include="X.Y" Version="1.2.3" />', "x.y", "1.2.3"),
        (CSPROJ, '-  <PackageReference Include="X" VersionOverride="1.2.3" />', "X", "1.2.3"),
        (CSPROJ, '-  <PackageReference Include="X" Version="$(XVersion)" />', "X", None),
        (CSPROJ, '-  <PackageReference Include="X" />', "X", None),
        ("go.mod", "-require golang.org/x/net v0.58.0 // indirect", "golang.org/x/net", "v0.58.0"),
        ("go.mod", "-go 1.25.14", "go", None),
        ("build/Dockerfile.ci", "-FROM golang:${GO}-alpine", "golang", None),
        ("a.Dockerfile", "-from python:3.12-slim@sha256:abc123 as base", "python", "3.12-slim"),
        (CI, "-      - uses: actions/checkout@v4", "actions/checkout", "v4"),
        (CI, "-  uses: github/codeql-action/init@v3", "github/codeql-action", "v3"),
        (CI, f"-  uses: actions/checkout@{'a' * 40}", "actions/checkout", None),
        ("docs/ci.yml", "-  uses: actions/checkout@v4", "actions/checkout", None),
        ("go.mod", "+require golang.org/x/net v0.60.0", "golang.org/x/net", None),
    ],
)  # fmt: skip
def test_removed_lines_match_only_their_file_type_s_pattern(file, line, name, version):
    reading = removed_versions([{"filename": file, "patch": line, **counts(line)}], {name})
    expected = [FileVersion(file, bare(version), version)] if version else []
    assert reading.removed[name] == expected


def counts(line):
    return {"additions": int(line.startswith("+")), "deletions": int(line.startswith("-"))}


def test_reading_fetches_every_pr_s_diff():
    github = github_with(98)
    (pull,) = read_from(github).pull_requests
    assert pull.state == "parsed", pull.reason
    assert pull.updates[0].from_source == "diff"
    assert files_url(98) in [url for url, _ in github.requests]


def answering(number, **responses):
    github = github_with(number)
    github.responses |= {
        {"pull": pull_url(number), "files": files_url(number)}[k]: v for k, v in responses.items()
    }
    return github


def as_pull(number, **fields):
    return ok(captured(number)[0] | {"changed_files": len(changed_files(number))} | fields)


MOVED = {"head": {"sha": "f" * 40, "ref": "x"}}


@pytest.mark.parametrize(
    ("github", "reason"),
    [
        (lambda: answering(98, pull=as_pull(98, changed_files=3001)), "listed 13 of the 3001"),
        (lambda: answering(98, files=refused(404, "Not Found")), "aren't visible to the token"),
        (lambda: answering(98, files=ok([{"filename": "x"}])), "isn't a list of changed files"),
        (lambda: answering(98, pull=ok([])), "isn't a pull request"),
        (lambda: answering(98, pull=as_pull(98, changed_files=None)), "doesn't say how many files"),
        # The head moved before the files were read, or while they were.
        (lambda: answering(98, pull=as_pull(98, **MOVED)), "head moved from bc9839d to fffffff"),
        (lambda: answering(98, pull=[as_pull(98), as_pull(98, **MOVED)]), "head moved from"),
    ],
)  # fmt: skip
def test_a_diff_that_cannot_be_read_completely_is_unparseable(github, reason):
    (pull,) = read_from(github()).pull_requests
    assert (pull.state, pull.updates) == ("unparseable", ())
    assert pull.reason.startswith("its changed files couldn't be read: ")
    assert reason in pull.reason


GO_MOD_HUNK = """@@ -20,12 +20,12 @@ {heading}
 {first}
-\tgolang.org/x/net v0.58.0
+\tgolang.org/x/net v0.60.0
 )
 exclude (
-\tgolang.org/x/net v0.57.0
 )
 retract (
-\tv0.9.0
-\tgolang.org/x/net v0.56.0
 )
-exclude golang.org/x/net v0.55.0
-retract golang.org/x/net v0.54.0
-require golang.org/x/net v0.53.0 // indirect"""


@pytest.mark.parametrize(
    ("heading", "first", "expected"),
    [
        ("require (", "\tgolang.org/x/text v0.20.0", {"v0.58.0", "v0.53.0"}),
        ("", "require (", {"v0.58.0", "v0.53.0"}),
        # git names the block a hunk starts in: an exclude block's lines aren't requirements.
        ("exclude (", "\tgolang.org/x/text v0.20.0", {"v0.53.0"}),
        ("retract (", "\tv1.0.0", {"v0.53.0"}),
        ("replace (", "\tgolang.org/x/text => ../text", {"v0.53.0"}),
    ],
)
def test_go_mod_reads_only_requirements(heading, first, expected):
    patch = GO_MOD_HUNK.format(heading=heading, first=first)
    reading = removed_versions(
        [{"filename": "go.mod", "patch": patch, **counts_of(patch)}], {"golang.org/x/net"}
    )
    assert reading.problems == []
    assert {f.written for f in reading.removed["golang.org/x/net"]} == expected


def counts_of(patch):
    lines = patch.splitlines()
    return {
        "additions": sum(line.startswith("+") for line in lines),
        "deletions": sum(line.startswith("-") for line in lines),
    }
