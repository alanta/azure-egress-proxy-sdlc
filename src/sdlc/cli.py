"""Command-line entry point: `sdlc <command>`."""

import argparse
import os
import sys
import traceback
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from sdlc import (
    consistency,
    coverage,
    dependabot,
    govulncheck,
    lifecycle,
    native,
    osv,
    outputs,
    policy,
    renovate,
    selection,
)
from sdlc.record import SCHEMA_VERSION, assembled_problems
from sdlc.report import count
from sdlc.subject import Revision, SubjectError, checkout, resolve


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
            "find update candidates, and check them against advisories and lifecycle data. "
            "Writes a JSON record and a Markdown report rendered from it to a run directory "
            "under --out. Read-only: nothing is written to the subject repository. Lookups "
            "use the read-only token in SDLC_GITHUB_TOKEN when it is set."
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
    scan.add_argument(
        "--out",
        type=Path,
        default=Path("runs"),
        help="Where to write the record and report, each scan in "
        "<out>/<owner>/<name>/<commit>/<time>/ (default: runs).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return scan(args.repo, args.ref, args.trial_policy, args.out)
    return 2


def scan(
    repository: str, ref: str, trial_policy: Path | None = None, out: Path = Path("runs")
) -> int:
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
                (native.dotnet_updates, native.LABELS["dotnet"]),
                (native.go_updates, native.LABELS["go"]),
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
            declared = consistency.check(baseline, inventory.dependencies)
            gaps += declared.gaps
            lifecycles = lifecycle.check(
                baseline, inventory.dependencies, scanned_at=datetime.fromisoformat(looked_up_at)
            )
            gaps += lifecycles.gaps
    except (SubjectError, renovate.RenovateError, policy.PolicyError) as error:
        print(f"error: {error}; no record written", file=sys.stderr)
        return 1

    record = {
        "schema_version": SCHEMA_VERSION,
        "subject": {"repository": repository, "ref": ref, "commit": revision.commit},
        "scanned_at": looked_up_at,
        "tools": [
            renovate.tool_entry(),
            *native.tool_entries(),
            osv.tool_entry(),
            *(govulncheck.tool_entries(runs) if runs else []),
            *lifecycles.tools,
        ],
        "policy": subject_policy.source,
        "inventory": inventory.dependencies,
        "candidates": inventory.candidates,
        "vulnerabilities": vulnerabilities,
        # Absent when they weren't read: a gap says why, and the record claims nothing.
        **({"dependabot_alerts": alerts} if alerts is not None else {}),
        "lifecycle": lifecycles.lifecycle,
        "consistency": [
            {"dependency": name, "compared": ids} for name, ids in declared.compared.items()
        ],
        "inconsistencies": declared.inconsistencies,
        "cross_checks": disagreements,
        "gaps": gaps,
    }
    directory = outputs.run_directory(out, repository, revision.commit, looked_up_at)
    # The selection is only made from a record that holds together; if making it fails, the
    # record is kept without one, with the reason, like any record that fails validation.
    problems = assembled_problems(record)
    if not problems:
        try:
            record["selection"] = selection.select(
                record,
                subject_policy,
                datetime.fromisoformat(looked_up_at).astimezone(UTC).date(),
            )
        except Exception as error:  # a bug in the selection must not lose the scan
            problems = [f"$.selection: it couldn't be made: {error!r}"]
    try:
        if problems:
            outputs.reject(record, directory, problems)
        record_path, report_path = outputs.write(record, directory)
    except outputs.InvalidRecord as error:
        print("error: the record fails its schema, so no report was written:", file=sys.stderr)
        for problem in error.problems:
            print(f"  {problem}", file=sys.stderr)
        print_kept(error, "invalid")
        return 1
    except outputs.Unrendered as error:
        print(f"error: {error}; no report was written", file=sys.stderr)
        traceback.print_exception(error.error, file=sys.stderr)
        print_kept(error, "valid")
        return 1
    except OSError as error:
        print(f"error: {error}; no record written", file=sys.stderr)
        return 1
    print(f"record: {record_path}")
    print(f"report: {report_path}")
    for line in summary(record):
        print(line)
    return 0


def print_kept(error: outputs.Unwritten, what: str) -> None:
    if error.kept:
        print(f"the {what} record is kept as {error.kept}", file=sys.stderr)
    else:
        print(f"the {what} record couldn't be kept either: {error.not_kept}", file=sys.stderr)


def summary(record: dict) -> list[str]:
    """A few lines on the terminal; the report has the rest."""
    unread = {g["subject"] for g in record["gaps"] if g["kind"] == "unavailable_source"}
    states = Counter(d["lookup"]["state"] for d in record["inventory"])
    held = sum(c["classification"] == "held_by_policy" for c in record["candidates"])
    lines = [
        f"{len(record['inventory'])} dependencies "
        f"({', '.join(f'{n} {s}' for s, n in sorted(states.items()))}), "
        f"{len(record['candidates'])} update candidates "
        f"({len(record['candidates']) - held} in scope, {held} held by policy), "
        f"{len(record['gaps'])} coverage gaps"
    ]
    lifecycle = Counter(e["state"] for e in record["lifecycle"])
    lines.append(
        f"lifecycle: {lifecycle['end_of_life']} end of life, "
        f"{lifecycle['nearing_end_of_life']} nearing it, {lifecycle['unknown']} unknown"
    )
    vulnerabilities = record["vulnerabilities"]
    reach = Counter(v["reachability"] for v in vulnerabilities)
    found = (
        "unknown, OSV-Scanner didn't run"
        if "osv-scanner" in unread
        else f"{len(vulnerabilities)} advisories"
    )
    lines.append(
        f"vulnerabilities: {found}; {reach['reachable']} reachable, "
        f"{reach['unknown']} with reachability unknown"
    )
    lines.append(f"inconsistent declarations: {len(record['inconsistencies'])}")
    units = record["selection"]["units"]
    lines.append(
        f"would prepare: {count(len(units), 'unit')} "
        f"({sum(u['breaking'] for u in units)} breaking), "
        f"{count(len(record['selection']['not_prepared']), 'reason')} not prepared"
    )
    return lines


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
