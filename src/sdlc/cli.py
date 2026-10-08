"""Command-line entry point: `sdlc <command>`."""

import argparse
import sys

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
            "Read-only: nothing is written to the subject repository."
        ),
    )
    scan.add_argument("--repo", required=True, help="Subject repository, as owner/name.")
    scan.add_argument(
        "--ref", default="main", help="Branch, tag or commit to scan (default: main)."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return scan(args.repo, args.ref)
    return 2


def scan(repository: str, ref: str) -> int:
    try:
        revision = resolve(repository, ref)
        with checkout(revision):
            print(f"{repository}@{ref} is {revision.commit}")
            # Inventory, lookups and the record arrive with the rest of slice 1.
            print("error: the scan stops here for now; no record written", file=sys.stderr)
            return 1
    except SubjectError as error:
        print(f"error: {error}; no record written", file=sys.stderr)
        return 1
