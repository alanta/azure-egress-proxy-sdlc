"""Parity with Dependabot, on the PRs captured while `main` was at 064aa09 and that revision's
Renovate report and .NET listing."""

import copy
import dataclasses
import json
from pathlib import Path

import pytest

from sdlc import native, osv, policy, renovate
from sdlc.dependabot_prs import PullRequest, PullRequests, Update, parse
from sdlc.parity import (
    compare,
    lock_versions,
    name_key,
    present,
    same_version,
    version_order,
)
from sdlc.pr_diff import FileVersion, bare, removed_versions
from sdlc.record import validate_record

FIXTURES = Path(__file__).parents[1] / "fixtures" / "azure-egress-proxy"
PRS = FIXTURES / "prs"
TRIAL = Path(__file__).parents[1] / "policies" / "azure-egress-proxy.renovate.json5"
LOOKED_UP = "2026-10-07T18:40:00+00:00"
READ = "2026-10-07T18:42:07+00:00"
OPEN = (75, 76, 77, 98, 99)  # open at capture; 78, 88 and 89 were closed


def test_the_captured_prs_describe_the_scanned_revision():
    manifest = json.loads((PRS / "manifest.json").read_text())
    assert manifest["default_branch_commit"].startswith("064aa09")


@pytest.fixture(scope="module")
def scanned():
    """The inventory, candidates and match fields of a 064aa09 scan, lock drift included."""
    report = json.loads(
        (FIXTURES / "renovate" / "064aa09" / "report-with-scan-config.json").read_text()
    )
    inventory = renovate.normalize(report, looked_up_at=LOOKED_UP)
    listing = json.loads((FIXTURES / "native" / "064aa09" / "dotnet-list-package.json").read_text())
    drifted, drift_candidates = native.lock_drift(
        native.parse_dotnet(listing, Path("/src")), inventory.dependencies, looked_up_at=LOOKED_UP
    )
    dependencies = inventory.dependencies + drifted
    fields = osv.match_fields(dependencies) | renovate.match_fields(report)
    return renovate.Inventory(dependencies, inventory.candidates + drift_candidates), fields


def pull(number):
    def read(name):
        return json.loads((PRS / str(number) / name).read_text())

    return parse(read("pr.json"), read("commits.json"), lambda: read("files.json"))


def compared(
    scanned,
    *numbers,
    inventory=None,
    subject_policy=policy.NO_POLICY,
    pulls=None,
    checkout=None,
    branch="main",
    fields=None,
):
    inventory = inventory or scanned[0]
    if pulls is None:
        pulls = PullRequests(READ, [pull(n) for n in numbers])
    return compare(
        pulls,
        inventory.dependencies,
        inventory.candidates,
        fields or scanned[1],
        subject_policy,
        looked_up_at=LOOKED_UP,
        branch=branch,
        checkout=checkout,
    )


def results(section):
    return {(pr["number"], u["name"]): u for pr in section["pull_requests"] for u in pr["updates"]}


def without(inventory, dependency=None, candidate=None):
    """The inventory without an entry (and its candidates), or without some candidates."""
    return renovate.Inventory(
        [d for d in inventory.dependencies if d["id"] != dependency],
        [
            c
            for c in inventory.candidates
            if c["dependency"] != dependency and c["dependency"] != candidate
        ],
    )


def edited(inventory, dependency, **changes):
    entries = copy.deepcopy(inventory.dependencies)
    for entry in entries:
        if entry["id"] == dependency:
            entry.update(changes)
    return renovate.Inventory(entries, inventory.candidates)


def with_candidates(inventory, dependency, *versions):
    others = [c for c in inventory.candidates if c["dependency"] != dependency]
    return renovate.Inventory(
        inventory.dependencies,
        others
        + [
            {
                "dependency": dependency,
                "update_type": "minor",
                "version": v,
                "classification": "in_scope",
            }
            for v in versions
        ],
    )


def as_record(record_from, inventory, section, gaps=()):
    record = record_from(inventory)
    record["parity"] = section
    record["gaps"] += list(gaps)
    return record


AZCORE = "gomod:proxy/go.mod:github.com/Azure/azure-sdk-for-go/sdk/azcore"
GOLANG = "dockerfile:proxy/Dockerfile:docker.io/library/golang"
AZURE_CORE = "nuget:Directory.Packages.props:Azure.Core"


def test_every_open_pr_is_matched_at_the_revision_it_was_made_for(scanned, record_from):
    section = compared(scanned, *OPEN)
    assert section["complete"] is True
    assert "reasons" not in section
    assert (section["captured_at"], section["looked_up_at"]) == (READ, LOOKED_UP)
    assert [pr["state"] for pr in section["pull_requests"]] == ["current"] * 5
    assert {k: u["result"] for k, u in results(section).items()} == {
        (75, "azure/login"): "matched",
        (75, "docker/setup-buildx-action"): "matched",
        (75, "docker/setup-qemu-action"): "matched",
        (76, "library/golang"): "matched",
        (76, "python"): "matched",
        (77, "Microsoft.Extensions.Http"): "matched",
        (98, "Azure.Core"): "matched",
        (98, "coverlet.collector"): "matched",
        (98, "Scalar.AspNetCore"): "matched",
        (99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"): "matched",
        (99, "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"): "matched",
    }
    assert validate_record(as_record(record_from, scanned[0], section)) == []


def test_a_patch_is_matched_by_a_newer_candidate_with_both_versions(scanned):
    update = results(compared(scanned, 99))[99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"]
    assert update == {
        "name": "github.com/Azure/azure-sdk-for-go/sdk/azcore",
        "ecosystem": "gomod",
        "directory": "/proxy",
        "group": "gomod-minor-patch",
        "update_type": "patch",
        "update_type_derived": False,
        "from_source": "text",
        "from": "1.23.1",
        "from_versions": [{"file": "proxy/go.mod", "version": "1.23.1"}],
        "to": "1.23.2",
        "result": "matched",
        "dependencies": [AZCORE],
        "candidate": "v1.23.3",
    }


def test_the_closest_candidate_at_or_past_dependabot_s_is_named(scanned):
    inventory = with_candidates(scanned[0], AZCORE, "v1.24.0", "v1.23.2", "v1.22.0")
    update = results(compared(scanned, 99, inventory=inventory))[
        99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    ]
    assert update["candidate"] == "v1.23.2"


def test_lock_file_drift_is_matched_by_its_locked_entry(scanned):
    # #77 changes only AppHost's lock file: 10.0.11 there, where 10.0.12 is declared.
    update = results(compared(scanned, 77))[77, "Microsoft.Extensions.Http"]
    assert update["result"] == "matched"
    assert update["candidate"] == "10.0.12"
    assert update["dependencies"] == [
        "locked:src/AppHost/packages.lock.json:Microsoft.Extensions.Http"
    ]


def test_a_dependency_with_versions_in_several_files_is_checked_per_file(scanned):
    # #98's Azure.Core: 1.62.0 centrally, 1.53.0 and 1.55.0 in drifted lock files, and
    # 1.62.0 in lock files the inventory doesn't list because they resolve the central one.
    update = results(compared(scanned, 98))[98, "Azure.Core"]
    assert "from" not in update
    assert len(update["from_versions"]) == 11
    assert update["result"] == "matched"
    assert update["candidate"] == "1.63.0"
    assert update["dependencies"] == [
        AZURE_CORE,
        "locked:src/AppHost/AllowlistSeeder/packages.lock.json:Azure.Core",
        "locked:src/EgressProxy.Client.Tests/packages.lock.json:Azure.Core",
        "locked:src/EgressProxy.Client/packages.lock.json:Azure.Core",
    ]
    assert "reason" not in update


def test_a_file_that_moved_on_is_noted_but_doesnt_make_the_update_stale(scanned):
    locked = "locked:src/EgressProxy.Client/packages.lock.json:Azure.Core"
    inventory = edited(scanned[0], locked, current="1.60.0")
    update = results(compared(scanned, 98, inventory=inventory))[98, "Azure.Core"]
    assert update["result"] == "matched"
    assert update["reason"] == (
        "not stale, but src/EgressProxy.Client/packages.lock.json has 1.60.0, not 1.53.0"
    )


def lock_files(root, versions):
    """A checkout holding packages.lock.json files, each resolving packages at versions."""
    for file, packages in versions.items():
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        resolved = {name: {"type": "Transitive", "resolved": v} for name, v in packages.items()}
        path.write_text(json.dumps({"version": 1, "dependencies": {"net10.0": resolved}}))
    return root


def test_an_update_none_of_whose_files_has_its_from_version_is_stale(scanned, tmp_path):
    # Had the revision moved everything to 1.63.0, the drift entries would be gone too.
    inventory = edited(scanned[0], AZURE_CORE, current="1.63.0")
    for dep in [d["id"] for d in inventory.dependencies if d["id"].startswith("locked:")]:
        if dep.endswith(":Azure.Core"):
            inventory = without(inventory, dependency=dep)
    locks = {f.file for f in pull(98).updates[0].from_versions if f.file.endswith(".json")}
    checkout = lock_files(tmp_path, {file: {"Azure.Core": "1.63.0"} for file in locks})
    (checkout / "Directory.Packages.props").write_text("<Project />")
    section = compared(scanned, 98, inventory=inventory, checkout=checkout)
    update = results(section)[98, "Azure.Core"]
    assert update["result"] == "stale"
    assert "Directory.Packages.props has 1.63.0, not 1.62.0" in update["reason"]
    assert "src/EgressProxy.Client/packages.lock.json has 1.63.0, not 1.53.0" in update["reason"]
    # Its other updates still count: staleness is judged per update.
    (pr,) = section["pull_requests"]
    assert pr["state"] == "partly_stale"
    assert pr["reason"] == (
        "the revision no longer has what it updates for Azure.Core; its other updates are "
        "compared on their own"
    )
    assert {u["name"]: u["result"] for u in pr["updates"]} == {
        "Azure.Core": "stale",
        "coverlet.collector": "matched",
        "Scalar.AspNetCore": "matched",
    }


def test_a_pr_made_for_an_older_revision_is_stale(scanned, record_from):
    # #88 moved smokescreen off a pseudo-version; 064aa09 already requires v0.1.0 (#97).
    section = compared(scanned, 88)
    (pr,) = section["pull_requests"]
    assert pr["state"] == "stale"
    assert pr["reason"] == (
        "the revision no longer has what it updates for github.com/stripe/smokescreen"
    )
    (update,) = pr["updates"]
    assert update["result"] == "stale"
    assert update["reason"] == ("proxy/go.mod has 0.1.0, not 0.0.5-0.20260706062719-a3294a6cc4e4")
    assert "candidate" not in update
    # A stale PR is neither matched nor missed, and the comparison is still complete.
    assert section["complete"] is True
    assert validate_record(as_record(record_from, scanned[0], section)) == []


BUILDX = "docker/setup-buildx-action"


def moved(files):
    """#75 with its buildx update changing these files, as it did once rebased onto a later
    main that has a workflow 064aa09 doesn't: .github/workflows/images.yml."""
    pr = pull(75)
    updates = tuple(
        dataclasses.replace(
            u, from_versions=tuple(FileVersion(f, "4.3.0", "v4.3.0") for f in files)
        )
        if u.name == BUILDX
        else u
        for u in pr.updates
    )
    return PullRequests(READ, [dataclasses.replace(pr, updates=updates)])


def workflows(root, *names):
    for name in names:
        path = root / ".github" / "workflows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("on: push\n")
    return root


def test_an_update_to_a_file_the_revision_lacks_is_stale_not_missed(scanned, tmp_path):
    checkout = workflows(tmp_path, "allowlist.yml", "deploy.yml", "release.yml")
    section = compared(scanned, pulls=moved([".github/workflows/images.yml"]), checkout=checkout)
    update = results(section)[75, BUILDX]
    assert update["result"] == "stale"
    assert update["reason"] == ".github/workflows/images.yml is absent from the scanned revision"
    # One stale update doesn't hide the group's others.
    (pr,) = section["pull_requests"]
    assert pr["state"] == "partly_stale"
    assert [u["result"] for u in pr["updates"]] == ["matched", "stale", "matched"]
    assert section["complete"] is True


def test_a_pr_is_stale_only_when_every_update_is(record_from):
    old = entry("Old", "Directory.Packages.props", "2.0.0", lookup={"state": "current"})
    new = entry("New", "Directory.Packages.props", "1.0.0")
    candidates = [candidate(new, "1.1.0")]
    pulls = PullRequests(
        READ,
        [
            PullRequest(
                number=1,
                title="bump",
                url="https://github.com/alanta/demo/pull/1",
                head="b" * 40,
                base="main",
                state="parsed",
                updates=(
                    proposed("Old", "1.0.0", "2.0.0", ("Directory.Packages.props", "1.0.0")),
                    proposed("New", "1.0.0", "1.1.0", ("Directory.Packages.props", "1.0.0")),
                ),
            ),
            PullRequest(
                number=2,
                title="bump old",
                url="https://github.com/alanta/demo/pull/2",
                head="c" * 40,
                base="main",
                state="parsed",
                updates=(proposed("Old", "1.0.0", "2.0.0", ("Directory.Packages.props", "1.0.0")),),
            ),
        ],
    )
    fields = {
        d["id"]: {
            "depName": d["name"],
            "packageName": d["name"],
            "datasource": "nuget",
            "manager": "nuget",
        }
        for d in (old, new)
    }
    section = compare(
        pulls,
        [old, new],
        candidates,
        fields,
        policy.NO_POLICY,
        looked_up_at=LOOKED_UP,
        branch="main",
    )
    grouped, single = section["pull_requests"]
    assert [u["result"] for u in grouped["updates"]] == ["stale", "matched"]
    assert grouped["state"] == "partly_stale"
    assert single["state"] == "stale"
    record = as_record(record_from, renovate.Inventory([old, new], candidates), section)
    assert validate_record(record) == []
    # The PR's state can't contradict its updates'.
    grouped["state"] = "stale"
    single["state"] = "current"
    problems = validate_record(record)
    assert "$.parity.pull_requests[0]: stale, yet 1 of its 2 updates are stale" in problems
    assert "$.parity.pull_requests[1]: current, yet 1 of its 1 updates are stale" in problems


def test_a_file_the_revision_lacks_beside_one_it_has_is_noted_not_stale(scanned, tmp_path):
    checkout = workflows(tmp_path, "allowlist.yml", "deploy.yml", "release.yml")
    files = [".github/workflows/release.yml", ".github/workflows/images.yml"]
    update = results(compared(scanned, pulls=moved(files), checkout=checkout))[75, BUILDX]
    assert update["result"] == "matched"
    assert update["reason"] == (
        "not stale, but .github/workflows/images.yml is absent from the scanned revision"
    )


def test_a_file_the_revision_has_without_the_entry_is_missed(scanned, tmp_path):
    checkout = workflows(tmp_path, "release.yml", "images.yml")
    update = results(
        compared(scanned, pulls=moved([".github/workflows/images.yml"]), checkout=checkout)
    )[75, BUILDX]
    assert update["result"] == "missed"
    assert "not in the inventory in .github/workflows/images.yml" in update["reason"]


@pytest.mark.parametrize("with_checkout", [False, True])
def test_a_file_the_scan_cant_see_is_unknown_not_absent(scanned, tmp_path, with_checkout):
    # Without a checkout, or inside a submodule a checkout may lack, nothing says it's absent.
    checkout = None
    if with_checkout:
        checkout = workflows(tmp_path, "release.yml")
        (tmp_path / ".gitmodules").write_text('[submodule "ci"]\n\tpath = vendor/ci\n')
    files = ["vendor/ci/.github/workflows/images.yml"]
    update = results(compared(scanned, pulls=moved(files), checkout=checkout))[75, BUILDX]
    assert update["result"] == "missed"


def test_presence_is_unknown_outside_the_checkout(tmp_path):
    assert present(None, "x") is None
    assert present(tmp_path, "../x") is None
    assert present(workflows(tmp_path, "ci.yml"), ".github/workflows/ci.yml") is True
    assert present(tmp_path, ".github/workflows/images.yml") is False


def classified(scanned, subject_policy):
    """The scan's candidates as the policy classifies them, the way the scan does."""
    inventory, fields = scanned
    return renovate.Inventory(
        inventory.dependencies,
        policy.classify(inventory.candidates, None, fields, subject_policy),
    )


def test_what_the_policy_holds_is_held_not_missed(scanned, record_from):
    # #78 proposes Microsoft.OpenApi 3.x, which the trial policy keeps on 2.x.
    trial = policy.load(Path("."), TRIAL, validate=lambda text: [])
    section = compared(scanned, 78, inventory=classified(scanned, trial), subject_policy=trial)
    update = results(section)[78, "Microsoft.OpenApi"]
    assert update["result"] == "held_by_policy"
    assert update["held_by"] == "Microsoft.OpenApi stays on 2.x"
    assert validate_record(as_record(record_from, scanned[0], section)) == []


def test_a_hold_is_found_on_dependabot_s_update_not_only_on_the_scan_s_candidate(scanned, tmp_path):
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text(
        "{packageRules: [{description: 'Azure SDK for Go waits a week', "
        "matchPackageNames: ['github.com/Azure/**'], matchUpdateTypes: ['patch'], enabled: false}]}"
    )
    held = policy.load(tmp_path, trial, validate=lambda text: [])
    inventory = classified(scanned, held)
    # The scan's azcore candidate is v1.23.3, a patch the rule holds too, but not 1.23.2.
    assert {c["version"] for c in inventory.candidates if c["dependency"] == AZCORE} == {"v1.23.3"}
    by_name = results(compared(scanned, 99, inventory=inventory, subject_policy=held))
    assert {u["result"] for u in by_name.values()} == {"held_by_policy"}
    assert {u["held_by"] for u in by_name.values()} == {"Azure SDK for Go waits a week"}


def test_a_candidate_at_dependabot_s_version_decides_the_hold(scanned, tmp_path):
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text(
        "{packageRules: [{description: 'azcore patches wait', "
        "matchPackageNames: ['github.com/Azure/azure-sdk-for-go/sdk/azcore'], "
        "matchUpdateTypes: ['patch'], enabled: false}]}"
    )
    held = policy.load(tmp_path, trial, validate=lambda text: [])
    # Renovate classified a candidate at 1.23.2 as in scope: that counts, not the scan's rules.
    inventory = with_candidates(scanned[0], AZCORE, "v1.23.2")
    update = results(compared(scanned, 99, inventory=inventory, subject_policy=held))[
        99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    ]
    assert update["result"] == "matched"


def test_the_policy_sees_dependabot_s_version_as_the_entry_writes_it(scanned, tmp_path):
    # go.mod writes v1.23.2; Dependabot writes 1.23.2. A rule written for go.mod's form
    # must not hold Dependabot's.
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text(
        "{packageRules: [{description: 'azcore stays on 1.x', "
        "matchPackageNames: ['github.com/Azure/azure-sdk-for-go/sdk/azcore'], "
        "allowedVersions: '/^v1\\\\./'}]}"
    )
    held = policy.load(tmp_path, trial, validate=lambda text: [])
    assert policy.holds(scanned[1][AZCORE], "patch", "1.23.2", held) == ["azcore stays on 1.x"]
    update = results(compared(scanned, 99, subject_policy=held))[
        99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    ]
    assert update["result"] == "matched"


def test_a_removed_candidate_is_reported_as_missed(scanned):
    inventory = without(scanned[0], candidate=AZCORE)
    section = compared(scanned, 99, inventory=inventory)
    update = results(section)[99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"]
    assert update["result"] == "missed"
    assert update["reason"] == "the scan has no candidate in proxy/go.mod"
    assert update["dependencies"] == [AZCORE]
    assert section["complete"] is True


def test_a_missed_update_cites_a_failed_lookup(scanned):
    inventory = without(
        edited(
            scanned[0],
            AZCORE,
            lookup={"state": "unknown", "reason": "Rate limited by proxy.golang.org."},
        ),
        candidate=AZCORE,
    )
    update = results(compared(scanned, 99, inventory=inventory))[
        99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    ]
    assert update["result"] == "missed"
    assert update["reason"] == (
        "the lookup in proxy/go.mod is unknown: Rate limited by proxy.golang.org."
    )


def test_a_missed_update_says_the_scan_s_candidate_is_older(scanned):
    inventory = with_candidates(scanned[0], AZCORE, "v1.23.2-beta.1")
    update = results(compared(scanned, 99, inventory=inventory))[
        99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    ]
    assert update["result"] == "missed"
    assert update["reason"] == (
        "the scan's newest in-scope candidate in proxy/go.mod is v1.23.2-beta.1, older than 1.23.2"
    )


def test_a_dependency_missing_from_the_inventory_is_missed(scanned):
    inventory = without(scanned[0], dependency=AZCORE)
    update = results(compared(scanned, 99, inventory=inventory))[
        99, "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    ]
    assert update["result"] == "missed"
    assert update["reason"] == (
        "github.com/Azure/azure-sdk-for-go/sdk/azcore is not in the inventory in proxy/go.mod"
    )
    assert "dependencies" not in update


def test_image_tags_match_only_with_the_same_suffix(scanned):
    def golang(*versions):
        inventory = with_candidates(scanned[0], GOLANG, *versions)
        return results(compared(scanned, 76, inventory=inventory))[76, "library/golang"]

    assert golang("1.27-alpine")["candidate"] == "1.27-alpine"
    assert golang("1.28-alpine")["candidate"] == "1.28-alpine"
    for other in ("1.27", "1.27-bookworm", "1.28-alpine3.22"):
        update = golang(other)
        assert update["result"] == "missed", other
        assert update["reason"] == (
            f"the scan's candidates in proxy/Dockerfile ({other}) can't be compared with "
            "1.27-alpine"
        )
    assert golang("1.26-alpine")["result"] == "missed"


def test_scan_only_lists_in_scope_candidates_no_pr_proposes(scanned, record_from):
    section = compared(scanned, *OPEN)
    scan_only = section["scan_only"]
    assert "regex:mock-idp/Dockerfile:PyJWT" in scan_only
    assert "regex:.devcontainer/Dockerfile:Aspire.Cli" in scan_only
    assert "locked:src/AppHost/packages.lock.json:OpenTelemetry.Extensions.Hosting" in scan_only
    # Entries an update maps to aren't, even the lock files that only follow a central version.
    covered = {d for u in results(section).values() for d in u.get("dependencies", [])}
    assert not covered & set(scan_only)
    assert "locked:src/EgressProxy.Client/packages.lock.json:Azure.Core" not in scan_only
    # Without a policy, the .NET 11 images and Microsoft.OpenApi 3.x count too.
    assert len(scan_only) == len(set(scan_only)) == 23
    assert validate_record(as_record(record_from, scanned[0], section)) == []


def test_held_candidates_are_not_scan_only(scanned):
    inventory = scanned[0]
    held = renovate.Inventory(
        inventory.dependencies,
        [
            c | {"classification": "held_by_policy", "held_by": "a rule"}
            if c["dependency"] == "regex:mock-idp/Dockerfile:PyJWT"
            else c
            for c in inventory.candidates
        ],
    )
    assert (
        "regex:mock-idp/Dockerfile:PyJWT"
        not in compared(scanned, inventory=held, pulls=PullRequests(READ, []))["scan_only"]
    )


def test_an_unparseable_pr_makes_the_comparison_incomplete(scanned, record_from):
    def read(name):
        return json.loads((PRS / "99" / name).read_text())

    commits = read("commits.json")
    commits[-1]["commit"]["message"] = "Bump things\n"
    broken = parse(read("pr.json"), commits, lambda: read("files.json"))
    section = compared(scanned, pulls=PullRequests(READ, [pull(75), broken]))
    assert section["complete"] is False
    assert section["reasons"] == [
        "#99 is unparseable: no commit message has an updated-dependencies block"
    ]
    assert section["pull_requests"][1] == {
        "number": 99,
        "title": broken.title,
        "head": broken.head,
        "base": "main",
        "state": "unparseable",
        "reason": "no commit message has an updated-dependencies block",
        "updates": [],
    }
    assert validate_record(as_record(record_from, scanned[0], section)) == []


def test_unread_prs_compare_nothing_and_never_look_like_none(scanned, record_from):
    inventory = scanned[0]
    section = compare(
        None,
        inventory.dependencies,
        inventory.candidates,
        scanned[1],
        policy.NO_POLICY,
        looked_up_at=LOOKED_UP,
        branch="main",
        unavailable="GitHub answered 403.",
    )
    assert section == {
        "baseline": "dependabot",
        "looked_up_at": LOOKED_UP,
        "complete": False,
        "reasons": ["Dependabot's open PRs couldn't be read: GitHub answered 403."],
        "pull_requests": [],
        "scan_only": [],
    }
    gap = {"kind": "unavailable_source", "subject": "dependabot-prs", "reason": "403"}
    assert validate_record(as_record(record_from, inventory, section, [gap])) == []
    # A record that read nothing can't claim a complete comparison.
    claimed = section | {"complete": True, "scan_only": [inventory.candidates[0]["dependency"]]}
    del claimed["reasons"]
    problems = validate_record(as_record(record_from, inventory, claimed, [gap]))
    assert any("a gap says the PRs weren't read" in p for p in problems)


def test_an_allowed_versions_the_scan_cant_evaluate_falls_back_to_renovate(scanned, tmp_path):
    trial = tmp_path / "trial.renovate.json5"
    trial.write_text(
        "{packageRules: [{description: 'Go images stay on 1.25', matchDatasources: ['docker'], "
        "matchPackageNames: ['docker.io/library/golang'], allowedVersions: '<1.26'}]}"
    )
    held = policy.load(tmp_path, trial, validate=lambda text: [])
    # Renovate held 1.27-alpine, so its classification says which rule.
    inventory = scanned[0]
    by_renovate = renovate.Inventory(
        inventory.dependencies,
        [
            c | {"classification": "held_by_policy", "held_by": "Go images stay on 1.25"}
            if c["dependency"] == GOLANG
            else c
            for c in inventory.candidates
        ],
    )
    section = compared(scanned, 76, inventory=by_renovate, subject_policy=held)
    assert results(section)[76, "library/golang"]["held_by"] == "Go images stay on 1.25"
    assert section["complete"] is True
    # Without a candidate at that version nothing says, so the comparison is incomplete.
    section = compared(
        scanned, 76, inventory=without(inventory, candidate=GOLANG), subject_policy=held
    )
    update = results(section)[76, "library/golang"]
    assert update["result"] == "missed"
    assert update["reason"].startswith(
        "whether the policy holds library/golang 1.27-alpine is unknown"
    )
    assert section["complete"] is False
    assert section["reasons"][0].startswith("#76: whether the policy holds library/golang")


@pytest.mark.parametrize(
    ("ecosystem", "a", "b", "order"),
    [
        ("gomod", "v1.23.3", "1.23.2", 1),
        ("gomod", "v0.1.0", "0.0.5-0.20260706062719-a3294a6cc4e4", 1),
        ("gomod", "1.2.0-beta.2", "1.2.0-beta.11", -1),
        ("gomod", "1.2.0-beta", "1.2.0-beta.1", -1),
        ("gomod", "1.2.0-alpha.1", "1.2.0-1", 1),
        ("nuget", "10.0.12", "10.0.12.0", 0),
        ("nuget", "1.63.0", "1.63.0-beta.1", 1),
        ("github-actions", "v3.1.0", "3.1.0", 0),
        ("docker", "1.28-alpine", "1.27-alpine", 1),
        ("docker", "1.27-alpine", "1.27-bookworm", None),
        ("docker", "1.27", "1.27-alpine", None),
        ("docker", "latest", "1.27-alpine", None),
        ("pip", "2.15.1", "2.15.1rc1", 1),
        ("nuget", "not-a-version", "1.0.0", None),
    ],
)
def test_versions_compare_per_ecosystem(ecosystem, a, b, order):
    assert version_order(ecosystem, a, b) == order


@pytest.mark.parametrize(
    ("ecosystem", "a", "b"),
    [
        ("docker", "library/golang", "docker.io/library/golang"),
        ("docker", "golang", "index.docker.io/library/golang"),
        ("nuget", "azure.core", "Azure.Core"),
        ("github-actions", "github/codeql-action", "github/codeql-action/init"),
        ("pip", "PyJWT", "pyjwt"),
    ],
)
def test_names_compare_per_ecosystem(ecosystem, a, b):
    assert name_key(ecosystem, a) == name_key(ecosystem, b)


def test_go_module_paths_are_exact():
    assert name_key("gomod", "github.com/Azure/x") != name_key("gomod", "github.com/azure/x")


# Small inventories of their own, for what the captured revision doesn't show.


def entry(name, file, current, *, ecosystem="nuget", origin="declared", lookup=None):
    manager = {"nuget": "nuget", "docker": "dockerfile"}.get(ecosystem, ecosystem)
    prefix = "locked" if origin == "locked" else manager
    return {
        "id": f"{prefix}:{file}:{name}",
        "ecosystem": ecosystem,
        "name": name,
        "current": current,
        "origin": origin,
        **({"locked_because": "drift"} if origin == "locked" else {}),
        "location": {"file": file},
        "lookup": lookup or {"state": "outdated", "datasource": ecosystem},
    }


def candidate(dep, version, update_type="minor"):
    return {
        "dependency": dep["id"],
        "update_type": update_type,
        "version": version,
        "classification": "in_scope",
    }


def proposing(*updates, base="main"):
    return PullRequests(
        READ,
        [
            PullRequest(
                number=1,
                title="bump",
                url="https://github.com/alanta/demo/pull/1",
                head="b" * 40,
                base=base,
                state="parsed",
                updates=tuple(updates),
            )
        ],
    )


def proposed(name, old, new, *files, ecosystem="nuget", directory=None):
    return Update(
        name=name,
        from_version=old,
        to_version=new,
        update_type="minor",
        update_type_derived=False,
        ecosystem=ecosystem,
        directory=directory,
        group=None,
        from_source="diff" if files else "text",
        from_versions=tuple(FileVersion(f, bare(v), v) for f, v in files),
    )


def own(dependencies, candidates, update, *, checkout=None, branch="main", base="main"):
    def fields(d):
        manager = {"nuget": "nuget", "docker": "dockerfile", "devcontainers": "devcontainer"}
        datasource = "docker" if d["ecosystem"] == "devcontainers" else d["ecosystem"]
        return {
            "depName": d["name"],
            "packageName": d["name"],
            "datasource": datasource,
            "manager": manager.get(d["ecosystem"], d["ecosystem"]),
        }

    section = compare(
        proposing(update, base=base),
        dependencies,
        candidates,
        {d["id"]: fields(d) for d in dependencies},
        policy.NO_POLICY,
        looked_up_at=LOOKED_UP,
        branch=branch,
        checkout=checkout,
    )
    return section, section["pull_requests"][0]["updates"]


def test_a_lock_file_follows_only_the_entry_that_governs_it():
    # A declares X 1.0.0 and B 2.0.0. A PR made when B was on 1.0.0 is stale, even though
    # A still has 1.0.0 and a candidate past 1.5.0.
    a = entry("X", "A/A.csproj", "1.0.0")
    b = entry("X", "B/B.csproj", "2.0.0")
    update = proposed(
        "X", None, "1.5.0", ("B/B.csproj", "1.0.0"), ("B/packages.lock.json", "1.0.0")
    )
    _, (result,) = own([a, b], [candidate(a, "2.0.0")], update)
    assert result["result"] == "stale"
    assert result["reason"] == "B/B.csproj has 2.0.0, not 1.0.0"
    # The entry the lock file follows is only listed when the update changes its file.
    assert result["dependencies"] == [b["id"]]


def test_a_lock_file_without_a_project_version_follows_the_nearest_central_one(tmp_path):
    central = entry("X", "Directory.Packages.props", "1.0.0")
    nested = entry("X", "src/Directory.Packages.props", "1.2.0")
    update = proposed("X", "1.2.0", "1.3.0", ("src/App/packages.lock.json", "1.2.0"))
    # The root's candidate doesn't reach for src/, whose own central version has none.
    _, (result,) = own([central, nested], [candidate(central, "1.3.0")], update)
    assert result["result"] == "missed"
    assert result["reason"] == "the scan has no candidate in src/Directory.Packages.props"
    _, (result,) = own([central, nested], [candidate(nested, "1.3.0")], update)
    assert (result["result"], result["candidate"]) == ("matched", "1.3.0")
    assert "dependencies" not in result


def test_every_file_the_update_changes_needs_a_candidate():
    unknown = {"state": "unknown", "reason": "Rate limited by Docker Hub."}
    a = entry("golang", "a/Dockerfile", "1.25-alpine", ecosystem="docker")
    b = entry("golang", "b/Dockerfile", "1.25-alpine", ecosystem="docker", lookup=unknown)
    update = proposed(
        "library/golang",
        "1.25-alpine",
        "1.27-alpine",
        ("a/Dockerfile", "1.25-alpine"),
        ("b/Dockerfile", "1.25-alpine"),
        ecosystem="docker",
    )
    _, (result,) = own([a, b], [candidate(a, "1.27-alpine")], update)
    assert result["result"] == "missed"
    assert result["reason"] == "the lookup in b/Dockerfile is unknown: Rate limited by Docker Hub."
    assert result["dependencies"] == [a["id"], b["id"]]


def test_a_lock_file_that_resolves_above_the_declared_version_is_read_from_the_checkout(
    tmp_path,
):
    central = entry("X", "Directory.Packages.props", "1.0.0")
    update = proposed("X", "1.2.0", "1.3.0", ("src/App/packages.lock.json", "1.2.0"))
    checkout = lock_files(tmp_path, {"src/App/packages.lock.json": {"x": "1.2.0"}})
    _, (result,) = own([central], [candidate(central, "1.3.0")], update, checkout=checkout)
    assert (result["result"], result["candidate"]) == ("matched", "1.3.0")
    # Moved on in the checkout: stale.
    lock_files(tmp_path, {"src/App/packages.lock.json": {"X": "1.3.0"}})
    _, (result,) = own([central], [candidate(central, "1.3.0")], update, checkout=checkout)
    assert result["result"] == "stale"
    assert result["reason"] == "src/App/packages.lock.json has 1.3.0, not 1.2.0"
    # Unreadable, or without the package: unknown, so not stale either.
    for broken in ("not json", json.dumps({"version": 1, "dependencies": {"net10.0": {}}})):
        (tmp_path / "src/App/packages.lock.json").write_text(broken)
        _, (result,) = own([central], [candidate(central, "1.3.0")], update, checkout=checkout)
        assert result["result"] == "matched"


def test_a_lock_file_outside_the_checkout_is_never_read(tmp_path):
    lock_files(tmp_path, {"outside/packages.lock.json": {"X": "1.2.0"}})
    (tmp_path / "checkout").mkdir()
    assert lock_versions(tmp_path / "checkout", "../outside/packages.lock.json", "X") is None
    assert lock_versions(tmp_path, "outside/packages.lock.json", "X") == {"1.2.0"}


def test_dependabot_s_image_names_leave_the_registry_out():
    sdk = entry("mcr.microsoft.com/dotnet/sdk", "Dockerfile", "10.0", ecosystem="docker")
    update = proposed("dotnet/sdk", "10.0", "10.1", ("Dockerfile", "10.0"), ecosystem="docker")
    _, (result,) = own([sdk], [candidate(sdk, "10.1")], update)
    assert (result["result"], result["dependencies"]) == ("matched", [sdk["id"]])
    # With a registry, only that registry's image is the one.
    ghcr = proposed(
        "ghcr.io/dotnet/sdk", "10.0", "10.1", ("Dockerfile", "10.0"), ecosystem="docker"
    )
    _, (result,) = own([sdk], [candidate(sdk, "10.1")], ghcr)
    assert result["reason"] == "ghcr.io/dotnet/sdk is not in the inventory in Dockerfile"
    # Docker Hub's image of the same path comes first; other registries can't be told apart.
    hub = entry("dotnet/sdk", "Dockerfile", "10.0", ecosystem="docker")
    _, (result,) = own([sdk, hub], [candidate(sdk, "10.1")], update)
    assert result["dependencies"] == [hub["id"]]
    other = entry("ghcr.io/dotnet/sdk", "Dockerfile", "10.0", ecosystem="docker")
    _, (result,) = own([sdk, other], [candidate(sdk, "10.1")], update)
    assert result["result"] == "missed"
    assert "dependencies" not in result


def test_the_diff_ties_an_image_line_to_dependabot_s_name_without_its_registry():
    patch = "@@ -1 +1 @@\n-FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build\n+FROM x:10.1"
    files = [{"filename": "Dockerfile", "patch": patch, "additions": 1, "deletions": 1}]
    found = removed_versions(files, {"dotnet/sdk", "ghcr.io/dotnet/sdk"}).removed
    assert [f.version for f in found["dotnet/sdk"]] == ["10.0"]
    assert found["ghcr.io/dotnet/sdk"] == []


def test_a_devcontainer_update_s_directory_holds_the_devcontainer_folder():
    feature = entry(
        "ghcr.io/devcontainers/features/node",
        ".devcontainer/devcontainer.json",
        "1.6.0",
        ecosystem="devcontainers",
    )
    update = proposed(
        "ghcr.io/devcontainers/features/node",
        "1.6.0",
        "1.7.0",
        ecosystem="devcontainers",
        directory="/",
    )
    _, (result,) = own([feature], [candidate(feature, "1.7.0")], update)
    assert (result["result"], result["dependencies"]) == ("matched", [feature["id"]])


def test_prs_for_another_branch_are_listed_but_not_compared(record_from):
    a = entry("X", "Directory.Packages.props", "1.0.0")
    update = proposed("X", None, "1.3.0", ("Directory.Packages.props", "1.0.0"))
    section, updates = own([a], [candidate(a, "1.3.0")], update, base="release/1.x")
    (pr,) = section["pull_requests"]
    assert (pr["state"], pr["base"], updates) == ("not_compared", "release/1.x", [])
    assert pr["reason"] == "it targets release/1.x, not main, which the scanned revision is on"
    # Not a gap in the comparison, and the scan's candidate counts as found by the scan only.
    assert section["complete"] is True
    assert section["scan_only"] == [a["id"]]
    inventory = renovate.Inventory([a], [candidate(a, "1.3.0")])
    assert validate_record(as_record(record_from, inventory, section)) == []
    pr["updates"] = [{"name": "X", "to": "1.3.0", "result": "missed", "reason": "r"}]
    problems = validate_record(as_record(record_from, inventory, section))
    assert any("not_compared needs a reason and no updates" in p for p in problems)


def test_nuget_prerelease_labels_ignore_case():
    assert version_order("nuget", "1.0.0-Beta.2", "1.0.0-beta.2") == 0
    assert version_order("nuget", "1.0.0-RC.1", "1.0.0-beta.2") == 1
    assert same_version("nuget", "1.0.0-Preview.1", "1.0.0-preview.1")
    assert not same_version("docker", "1.27", "1.27.0")


def test_a_miss_says_when_the_scan_only_has_an_advisory_s_fix():
    lock = "src/A/packages.lock.json"
    dep = entry(
        "Some.Transitive",
        lock,
        "2.0.0",
        origin="locked",
        lookup={"state": "outdated", "basis": "advisory_fix", "reason": "Not looked up."},
    )
    fix = candidate(dep, "2.0.1", "patch") | {"basis": "advisory_fix"}
    _, (update,) = own([dep], [fix], proposed("Some.Transitive", "2.0.0", "2.1.0", (lock, "2.0.0")))
    assert update["result"] == "missed"
    assert update["reason"] == (
        "the scan's newest in-scope candidate in src/A/packages.lock.json is 2.0.1, older than "
        "2.1.0 (it wasn't looked up; its candidates are its advisories' fixes)"
    )


def test_a_stale_update_leaves_its_entry_scan_only():
    dep = entry("Pkg", "Directory.Packages.props", "2.0.0")
    stale = proposed("Pkg", "1.0.0", "2.0.0", ("Directory.Packages.props", "1.0.0"))
    section, (update,) = own([dep], [candidate(dep, "2.1.0")], stale)
    assert update["result"] == "stale"
    assert section["scan_only"] == [dep["id"]]
