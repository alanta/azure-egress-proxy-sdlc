"""Command-line entry point: `sdlc <command>`."""

import argparse
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sdlc import renovate
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
        with checkout(revision) as path:
            report = renovate.run(
                path, trial_policy=trial_policy, token=os.environ.get("SDLC_GITHUB_TOKEN")
            )
            inventory = renovate.normalize(report, looked_up_at=looked_up_at, checkout=path)
    except (SubjectError, renovate.RenovateError) as error:
        print(f"error: {error}; no record written", file=sys.stderr)
        return 1

    states = Counter(d["lookup"]["state"] for d in inventory.dependencies)
    print(
        f"{len(inventory.dependencies)} dependencies "
        f"({', '.join(f'{n} {s}' for s, n in sorted(states.items()))}), "
        f"{len(inventory.candidates)} update candidates"
    )
    # Policy, vulnerabilities, lifecycle, consistency and parity arrive with the rest of
    # slice 1; a record without them would claim there was nothing to find.
    print("error: the scan stops here for now; no record written", file=sys.stderr)
    return 1
