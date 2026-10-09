"""Command-line entry point: `sdlc <command>`."""

import argparse
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from sdlc import coverage, native, osv, policy, renovate
from sdlc.subject import SubjectError, checkout, resolve


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
            candidates = policy.classify(
                inventory.candidates,
                renovate.normalize(report, looked_up_at=looked_up_at),
                renovate.match_fields(baseline),
                subject_policy,
            )
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
    if found is None:
        print("vulnerabilities: unknown, OSV-Scanner didn't run (see its gap)")
    else:
        print_vulnerabilities(found, inventory)
    # Lifecycle, consistency and parity arrive with the rest of slice 1; a
    # record without them would claim there was nothing to find.
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


def print_vulnerabilities(found: osv.Findings, inventory: renovate.Inventory) -> None:
    by_dependency: dict[str, list[dict]] = {}
    for v in found.vulnerabilities:
        by_dependency.setdefault(v["dependency"], []).append(v)
    print(
        f"{len(found.vulnerabilities)} advisories on {len(by_dependency)} dependencies "
        f"from OSV-Scanner, {len(found.gaps)} packages it couldn't check; reachability unknown"
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
            if v["fixed_version"]:
                fix = f"fixed in {v['fixed_version']}"
            elif "last_affected" in v:
                fix = f"fixed after {v['last_affected']}"
            else:
                print(f"    {v['advisory']}: no fixed version")
                continue
            reached = {True: "yes", False: "no"}.get(v["fix_reached_by_candidate"], "unknown")
            held = f", only held candidates do ({v['fix_held_by']})" if "fix_held_by" in v else ""
            print(f"    {v['advisory']}: {fix}, an in-scope candidate reaches it: {reached}{held}")


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
