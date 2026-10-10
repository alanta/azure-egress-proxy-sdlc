"""Command-line entry point: `sdlc <command>`."""

import argparse
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from sdlc import (
    consistency,
    coverage,
    dependabot,
    dependabot_prs,
    govulncheck,
    lifecycle,
    native,
    osv,
    parity,
    policy,
    renovate,
)
from sdlc.subject import Revision, SubjectError, checkout, default_branch, resolve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sdlc",
        description="Keep a subject repository up to date.",
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    scan = commands.add_parser(
        "scan",
        help="Scan a pinned revision of a subject repository for dependencies and updates.",
        description=(
            "Inventory the dependencies of a subject repository at a pinned revision, "
            "find update candidates, and compare the result with open Dependabot PRs. "
            "Read-only: nothing is written to the subject repository. Lookups use the "
            "read-only token in SDLC_GITHUB_TOKEN when it is set."
        ),
    )
    scan.add_argument("--repo", required=True, help="Subject repository, as owner/name.")
    scan.add_argument(
        "--ref", default="main", help="Branch, tag or commit to scan (default: main)."
    )
    scan.add_argument(
        "--trial-policy",
        type=Path,
        help="Update policy to use instead of the one in the subject, for trying one out.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return scan(args.repo, args.ref, args.trial_policy)
    return 2


def scan(repository: str, ref: str, trial_policy: Path | None = None) -> int:
    try:
        revision = resolve(repository, ref)
        print(f"{repository}@{ref} is {revision.commit}")
        looked_up_at = datetime.now(UTC).isoformat(timespec="seconds")
        token = os.environ.get("SDLC_GITHUB_TOKEN")
        with checkout(revision) as path:
            subject_policy = policy.load(path, trial_policy, validate=renovate.validate)
            print(f"policy: {describe(subject_policy)}")
            report, baseline = run_renovate(path, subject_policy, token)
            # The inventory comes from the run without the policy's holds, so a dependency
            # the policy disables still shows what its lookup found.
            inventory = renovate.normalize(baseline, looked_up_at=looked_up_at, checkout=path)
            fields = renovate.match_fields(baseline)
            # A lookup that failed in only one of the runs makes that dependency unknown.
            inventory, with_policy = policy.reconcile(
                inventory,
                renovate.normalize(report, looked_up_at=looked_up_at),
                fields,
                subject_policy,
            )
            candidates = policy.classify(inventory.candidates, with_policy, fields, subject_policy)
            gaps = coverage.gaps(path, baseline)
            native_updates = []
            for query, label in (
                (native.dotnet_updates, "dotnet list package"),
                (native.go_updates, "go list -m -u"),
            ):
                try:
                    native_updates += query(path)
                except native.NativeError as error:
                    gaps.append(
                        {"kind": "unavailable_source", "subject": label, "reason": str(error)}
                    )
            disagreements = native.cross_check(native_updates, inventory.dependencies, candidates)
            drifted, drift_candidates = native.lock_drift(
                native_updates, inventory.dependencies, looked_up_at=looked_up_at, checkout=path
            )
            # Renovate never sees lock-file drift, so only the policy's rules classify it.
            drift_candidates = policy.classify(
                drift_candidates,
                None,
                {
                    d["id"]: {
                        "depName": d["name"],
                        "packageName": d["name"],
                        "datasource": "nuget",
                        "manager": "nuget",
                    }
                    for d in drifted
                },
                subject_policy,
            )
            inventory = renovate.Inventory(
                inventory.dependencies + drifted, candidates + drift_candidates
            )
            found, inventory = find_vulnerabilities(
                path, inventory, renovate.indirect(baseline), subject_policy, gaps
            )
            runs = govulncheck.scan(path)
            reached = govulncheck.apply(
                runs,
                found.vulnerabilities if found else [],
                inventory.dependencies,
                inventory.candidates,
                toolchains=renovate.go_toolchains(baseline),
                indirect=renovate.indirect(baseline),
                looked_up_at=datetime.now(UTC).isoformat(timespec="seconds"),
                classify=lambda candidates, fields: policy.classify(
                    candidates, None, fields, subject_policy
                ),
                checkout=path,
            )
            gaps += reached.gaps
            updated = {d["id"]: d for d in reached.updated}
            inventory = renovate.Inventory(
                [updated.get(d["id"], d) for d in inventory.dependencies] + reached.dependencies,
                inventory.candidates + reached.candidates,
            )
            alerts, vulnerabilities = read_alerts(
                revision, token, reached.vulnerabilities, inventory.dependencies, gaps
            )
            # Read in the same run as the lookups: parity holds only at a point in time.
            pulls = read_pull_requests(revision, token, gaps)
            # Renovate's own fields for its entries; the scan's locked entries by their name.
            fields = osv.match_fields(inventory.dependencies) | renovate.match_fields(baseline)
            compared = parity.compare(
                pulls,
                inventory.dependencies,
                inventory.candidates,
                fields,
                subject_policy,
                looked_up_at=looked_up_at,
                # PRs for another branch propose changes to another revision.
                branch=revision.branch or default_branch(revision.repository),
                checkout=path,
                unavailable=next(
                    (g["reason"] for g in gaps if g["subject"] == dependabot_prs.SUBJECT), None
                ),
            )
            declared = consistency.check(baseline, inventory.dependencies)
            gaps += declared.gaps
            lifecycles = lifecycle.check(
                baseline, inventory.dependencies, scanned_at=datetime.fromisoformat(looked_up_at)
            )
            gaps += lifecycles.gaps
    except (SubjectError, renovate.RenovateError, policy.PolicyError) as error:
        print(f"error: {error}; no record written", file=sys.stderr)
        return 1

    states = Counter(d["lookup"]["state"] for d in inventory.dependencies)
    print(
        f"{len(inventory.dependencies)} dependencies "
        f"({', '.join(f'{n} {s}' for s, n in sorted(states.items()))}), "
        f"{len(inventory.candidates)} update candidates, {len(gaps)} coverage gaps"
    )
    for gap in gaps:
        print(f"  gap: {gap['subject']}: {gap['reason']}")
    for dep in drifted:
        print(f"  lock drift: {dep['location']['file']}: {dep['name']} {dep['current']}")
    held = [c for c in inventory.candidates if c["classification"] == "held_by_policy"]
    print(
        f"{len(inventory.candidates) - len(held)} candidates in scope, {len(held)} held by policy"
    )
    for c in held:
        print(f"  held: {c['dependency']} {c['update_type']} {c['version']}: {c['held_by']}")
    print(f"{len(disagreements)} disagreements with the package managers")
    for d in disagreements:
        print(
            f"  {d['source']}: {d['name']} {d['current']} -> {d['native_latest']}, "
            f"scan has {d['scan_candidates'] or 'nothing'}"
        )
    for run in runs:
        if run.platforms is not None:
            db, modified = run.database or ("?", "?")
            print(
                f"govulncheck {govulncheck.VERSION} on {run.go_mod} with {run.go_version} "
                f"for {', '.join(run.platforms)}, database {db} modified {modified}"
            )
    if found is None:
        # govulncheck's own findings still count, but no total may suggest that's all.
        print("vulnerabilities: unknown, OSV-Scanner didn't run (see its gap)")
        if vulnerabilities:
            print_vulnerabilities(vulnerabilities, inventory, found)
    else:
        print_vulnerabilities(vulnerabilities, inventory, found)
    print_alerts(alerts, vulnerabilities, revision.commit)
    print_consistency(declared, inventory.dependencies)
    print_lifecycle(lifecycles)
    print_pull_requests(pulls, compared)
    print_scan_only(compared, inventory.dependencies, fields)
    # The record and its report arrive with task 6.1.
    print("error: the scan stops here for now; no record written", file=sys.stderr)
    return 1


def find_vulnerabilities(
    path: Path,
    inventory: renovate.Inventory,
    indirect: set[str],
    subject_policy: policy.Policy,
    gaps: list[dict],
) -> tuple[osv.Findings | None, renovate.Inventory]:
    """OSV-Scanner's findings, and the inventory with the locked entries they add.

    No findings when OSV-Scanner fails: the failure is a gap, and the scan carries on
    without claiming anything about vulnerabilities.
    """
    scanned_at = datetime.now(UTC).isoformat(timespec="seconds")
    files = osv.lock_files(path)
    try:
        output = osv.run(path, files)
    except osv.OsvError as error:
        gaps.append({"kind": "unavailable_source", "subject": "osv-scanner", "reason": str(error)})
        return None, inventory
    found = osv.findings(
        output,
        inventory.dependencies,
        inventory.candidates,
        indirect=indirect,
        looked_up_at=scanned_at,
        scanned=files,
        classify=lambda candidates, fields: policy.classify(
            candidates, None, fields, subject_policy
        ),
        checkout=path,
    )
    gaps += found.gaps
    updated = {d["id"]: d for d in found.updated}
    return found, renovate.Inventory(
        [updated.get(d["id"], d) for d in inventory.dependencies] + found.dependencies,
        inventory.candidates + found.candidates,
    )


def read_alerts(
    revision: Revision,
    token: str | None,
    vulnerabilities: list[dict],
    dependencies: list[dict],
    gaps: list[dict],
) -> tuple[dict | None, list[dict]]:
    """The Dependabot alerts section, and the vulnerabilities with the alerts that match them.

    No section when the alerts can't be read: a gap says why, and nothing is claimed about them.
    """
    try:
        alerts = dependabot.read(revision.repository, token)
    except dependabot.Unavailable as error:
        gaps.append(
            {"kind": "unavailable_source", "subject": dependabot.SUBJECT, "reason": str(error)}
        )
        return None, vulnerabilities
    return dependabot.compare(alerts, vulnerabilities, dependencies, revision.commit)


def read_pull_requests(
    revision: Revision, token: str | None, gaps: list[dict]
) -> dependabot_prs.PullRequests | None:
    """Dependabot's open PRs with their proposed updates, or None and a gap saying why not.

    None never means there are no open PRs: it means nothing is known about them.
    """
    try:
        return dependabot_prs.read(revision.repository, token)
    except dependabot.Unavailable as error:
        gaps.append(
            {"kind": "unavailable_source", "subject": dependabot_prs.SUBJECT, "reason": str(error)}
        )
        return None


RESULTS = {
    "matched": "matched",
    "held_by_policy": "held by policy",
    "missed": "missed",
    "stale": "stale",
}


def print_pull_requests(pulls: dependabot_prs.PullRequests | None, compared: dict) -> None:
    if pulls is None:
        print(
            "Dependabot PRs: unavailable (see its gap), so nothing is known about them, "
            "and nothing is compared with them"
        )
        return
    states = Counter(p["state"] for p in compared["pull_requests"])
    parsed = [
        p
        for p, r in zip(pulls.pull_requests, compared["pull_requests"], strict=True)
        if r["state"] in ("current", "stale")
    ]
    other = f"; {states['not_compared']} for another branch" if states["not_compared"] else ""
    print(
        f"Dependabot PRs: {len(pulls.pull_requests)} open (read at {pulls.read_at}){other}; "
        f"{len(parsed)} parsed, proposing {sum(len(p.updates) for p in parsed)} updates; "
        f"{states['unparseable']} unparseable"
        + (", so the comparison with them is incomplete" if states["unparseable"] else "")
    )
    results = Counter(u["result"] for p in compared["pull_requests"] for u in p["updates"])
    print(
        f"parity with Dependabot (lookups at {compared['looked_up_at']}): "
        + ", ".join(f"{results[r]} {label}" for r, label in RESULTS.items())
        + ("" if compared["complete"] else "; incomplete")
    )
    for pull, result in zip(pulls.pull_requests, compared["pull_requests"], strict=True):
        if result["state"] == "not_compared":
            print(f"  not compared #{pull.number} at {pull.head[:7]}: {result['reason']}")
            continue
        if pull.state == "unparseable":
            print(f"  unparseable #{pull.number} at {pull.head[:7]}: {pull.reason}")
            continue
        print(
            f"  #{pull.number} at {pull.head[:7]} on {pull.base}, {result['state']}: {pull.title}"
        )
        for u, r in zip(pull.updates, result["updates"], strict=True):
            kind = u.update_type or "unknown type"
            if u.update_type_derived:
                kind += ", derived"
            where = " ".join(
                part for part in (u.ecosystem, u.directory, u.group and f"group {u.group}") if part
            )
            old = u.from_version or " or ".join(sorted({f.version for f in u.from_versions}))
            if u.from_source == "diff":
                old += f" (from the diff of {len(u.from_versions)} files)"
            detail = {
                "matched": f"scan has {r.get('candidate')}",
                "held_by_policy": r.get("held_by"),
            }.get(r["result"])
            detail = "; ".join(d for d in (detail, r.get("reason")) if d)
            print(
                f"    {RESULTS[r['result']]}: {u.name} {old} -> {u.to_version} ({kind}) {where}"
                + (f": {detail}" if detail else "")
            )
    for reason in compared.get("reasons", []):
        print(f"  incomplete: {reason}")


def print_scan_only(compared: dict, dependencies: list[dict], fields: dict) -> None:
    """Scan-only entries by manager, with their distinct names: the list itself is long."""
    if "captured_at" not in compared:  # the PRs weren't read
        print("scan only: unknown, without Dependabot's PRs")
        return
    entries = {d["id"]: d for d in dependencies}
    groups: dict[str, list[str]] = {}
    for dep_id in compared["scan_only"]:
        dep = entries[dep_id]
        group = fields[dep_id]["manager"] + (" lock files" if dep["origin"] == "locked" else "")
        groups.setdefault(group, []).append(dep["name"])
    print(
        f"scan only: {entries_count(len(compared['scan_only']))} with in-scope candidates that "
        "no open Dependabot PR proposes"
    )
    for group, names in sorted(groups.items()):
        distinct = list(dict.fromkeys(names))
        shown = ", ".join(distinct[:5]) + (
            f" and {len(distinct) - 5} more" if len(distinct) > 5 else ""
        )
        print(f"  {group}: {entries_count(len(names))}: {shown}")


def entries_count(count: int) -> str:
    return f"{count} {'entry' if count == 1 else 'entries'}"


def print_consistency(result: consistency.Result, dependencies: list[dict]) -> None:
    entries = {d["id"]: d for d in dependencies}
    flagged = {i["dependency"] for i in result.inconsistencies}
    summary = []
    for name, compared in result.compared.items():
        if len(compared) < 2:
            summary.append(f"{name} compared {'once' if compared else 'nowhere'}")
        else:
            state = "inconsistent" if name in flagged else "consistent"
            summary.append(f"{name} {state} across {len(compared)} declarations")
    print(
        f"consistency: {len(flagged)} of {len(result.compared)} logical dependencies "
        f"declared inconsistently ({', '.join(summary)})"
    )
    for inconsistency in result.inconsistencies:
        print(f"  inconsistent: {inconsistency['dependency']}")
        for d in inconsistency["declarations"]:
            location = d["location"]
            where = ":".join(str(location[k]) for k in ("file", "line") if k in location)
            dep = entries[d["dependency"]]
            print(f"    {where}: {dep['name']} {dep['current']} declares {d['version']}")


def print_lifecycle(result: lifecycle.Result) -> None:
    states = Counter(e["state"] for e in result.lifecycle)
    fetched = [t["url"].rsplit("/", 1)[1] for t in result.tools]
    source = (
        f"{lifecycle.API}: {', '.join(fetched)}, fetched at {result.tools[0]['fetched_at']}"
        if result.tools
        else "nothing read from endoflife.date"
    )
    print(
        f"lifecycle ({source}): {len(result.lifecycle)} lines in use, "
        + ", ".join(
            f"{states[s]} {s.replace('_', ' ')}"
            for s in ("end_of_life", "nearing_end_of_life", "supported", "unknown")
        )
    )
    for state in ("end_of_life", "nearing_end_of_life", "supported", "unknown"):
        for e in (e for e in result.lifecycle if e["state"] == state):
            where = ", ".join(
                ":".join(str(loc[k]) for k in ("file", "line") if k in loc)
                for loc in e["locations"][:3]
            )
            if len(e["locations"]) > 3:
                where += f" and {len(e['locations']) - 3} more"
            if state == "unknown":
                detail = e["reason"]
            else:
                ends = e.get("end_of_life")
                verb = "ended" if state == "end_of_life" else "ends"
                detail = f"{verb} {ends}" if ends else e.get("reason", "no end date published")
                lines = e.get("supported_lines")
                if state != "supported":
                    detail += f"; supported: {', '.join(lines) if lines else 'none'}"
            print(f"  {state.replace('_', ' ')}: {e['product']} {e['line']}: {detail} ({where})")


def print_alerts(section: dict | None, vulnerabilities: list[dict], commit: str) -> None:
    if section is None:
        print("Dependabot alerts: unavailable (see its gap), so nothing is known from them")
        return
    alerts = section["alerts"]
    results = Counter(a["result"] for a in alerts)
    unmatched = [a for a in alerts if a["result"] == "unmatched"]
    head = f"{section['ref']} at {section['commit'][:7]}"
    if section["is_scanned_commit"]:
        about = f"{head}, the scanned commit"
    else:
        # Later parity work must not count the branch's differences as misses of the scan.
        about = (
            f"{head}, NOT the scanned commit {commit[:7]}: a difference may be the branch's, "
            "not the scan's"
        )
    print(
        f"Dependabot alerts: {len(alerts)} open on {about} (read at {section['read_at']}); "
        f"{results['matched']} match the scan's advisories in the same file, "
        f"{results['matched_elsewhere']} only in another file, {results['unmatched']} don't; "
        f"{sum('dependabot_alerts' not in v for v in vulnerabilities)} of the scan's "
        f"{len(vulnerabilities)} advisories have no open alert"
    )
    for a in unmatched:
        fix = f"fixed in {a['fixed_version']}" if a["fixed_version"] else "no fixed version"
        listed = "" if "dependency" in a else ", not in the inventory there"
        print(
            f"  unmatched alert #{a['number']}: {a['advisory']} on {a['package']} "
            f"({a['manifest']}{listed}), {fix}"
        )


def print_vulnerabilities(
    vulnerabilities: list[dict], inventory: renovate.Inventory, found: osv.Findings | None
) -> None:
    by_dependency: dict[str, list[dict]] = {}
    for v in vulnerabilities:
        by_dependency.setdefault(v["dependency"], []).append(v)
    sources = Counter(v["source"] for v in vulnerabilities)
    reachability = Counter(v["reachability"] for v in vulnerabilities)
    unchecked = f", {len(found.gaps)} packages OSV-Scanner couldn't check" if found else ""
    print(
        f"{len(vulnerabilities)} advisories on {len(by_dependency)} dependencies "
        f"({', '.join(f'{n} from {s}' for s, n in sorted(sources.items())) or 'none'})"
        f"{unchecked}; reachability: "
        + ", ".join(
            f"{reachability[r]} {r.replace('_', ' ')}"
            for r in ("reachable", "not_reachable", "unknown")
        )
    )
    entries = {d["id"]: d for d in inventory.dependencies}
    for dep_id, advisories in by_dependency.items():
        dep = entries[dep_id]
        candidates = [
            c["version"] + (" (held)" if c["classification"] == "held_by_policy" else "")
            for c in inventory.candidates
            if c["dependency"] == dep_id
        ]
        print(
            f"  vulnerable: {dep['name']} {dep['current']} ({dep['origin']}, "
            f"{dep['location']['file']}), candidates {', '.join(candidates) or 'none'}"
        )
        for v in advisories:
            reach = v["reachability"].replace("_", " ")
            if "dependabot_alerts" in v:
                numbers = ", ".join(f"#{n}" for n in v["dependabot_alerts"])
                reach += f", Dependabot alert {numbers}"
            if v["fixed_version"]:
                fix = f"fixed in {v['fixed_version']}"
            elif "last_affected" in v:
                fix = f"fixed after {v['last_affected']}"
            else:
                print(f"    {v['advisory']} ({v['source']}, {reach}): no fixed version")
                continue
            reached = {True: "yes", False: "no"}.get(v["fix_reached_by_candidate"], "unknown")
            held = f", only held candidates do ({v['fix_held_by']})" if "fix_held_by" in v else ""
            print(
                f"    {v['advisory']} ({v['source']}, {reach}): {fix}, "
                f"an in-scope candidate reaches it: {reached}{held}"
            )


def describe(subject_policy: policy.Policy) -> str:
    source = subject_policy.source
    if source["source"] == "none":
        return "none found, so every candidate is in scope"
    where = "trial file" if source["source"] == "trial" else "the subject's"
    return f"{where} {source['path']}"


def run_renovate(path: Path, subject_policy: policy.Policy, token: str | None) -> tuple[dict, dict]:
    """Renovate's reports with the whole policy and without its holds, run side by side."""
    if subject_policy.baseline == subject_policy.content:
        report = renovate.run(path, policy=subject_policy.content, token=token)
        return report, report
    with ThreadPoolExecutor(max_workers=2) as pool:
        main, baseline = (
            pool.submit(renovate.run, path, policy=text, token=token)
            for text in (subject_policy.content, subject_policy.baseline)
        )
        return main.result(), baseline.result()
