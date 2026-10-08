"""Find what the scan can't cover, so silence from a tool is never mistaken for "nothing here".

Renovate reports what it understands and says nothing about the rest: a Packer template it
has no manager for, or a lock file it never parses in lookup mode. This module looks at the
checkout itself and reports those as gaps.
"""

import json
import re
import subprocess
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SourceType:
    patterns: tuple[str, ...]
    label: str


# File types that declare dependencies but that Renovate has no manager for. One of these
# missing from Renovate's report is an unsupported source. File types Renovate does read
# (Dockerfiles, project files, workflows, ...) are trusted: when Renovate reports nothing for
# such a file, the file declares nothing, like a .csproj with only project references.
DEPENDENCY_FILES = (
    SourceType(("*.pkr.hcl", "*.pkr.json"), "Packer template"),
    SourceType(("cloud-init*.yaml", "cloud-init*.yml", "cloud-config*.yaml"), "cloud-init config"),
)

# Lock files the scan checks it can read; Renovate's lookup mode doesn't parse them.
LOCK_FILES = ("packages.lock.json", "package-lock.json", "go.sum", "uv.lock", "poetry.lock")

# Lines installing a package without a version anyone could track.
UNPINNED_INSTALLS = (
    (re.compile(r"\bpip3?\s+install\b(?!.*==)"), "pip install without a pinned version"),
    (
        re.compile(r"\bnpm\s+(?:i|install)\s+(?:-g\s+)?(?![^\s@]+@\d)[a-z@]"),
        "npm install without a pinned version",
    ),
    (re.compile(r"\bgo\s+install\s+\S+@latest\b"), "go install @latest"),
)
INSTALL_LINE_FILES = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "*.sh", "*.yml", "*.yaml")


def tracked_files(checkout: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607 - git from PATH
        cwd=checkout,
        capture_output=True,
        check=True,
    )
    return sorted(f for f in result.stdout.decode().split("\0") if f)


def covered_files(report: dict) -> set[str]:
    """Files Renovate read: its package files and the lock files it attached to them."""
    repositories = report.get("repositories") or {}
    covered: set[str] = set()
    for repository in repositories.values():
        for entries in (repository.get("packageFiles") or {}).values():
            for entry in entries:
                covered.add(entry["packageFile"])
                covered.update(entry.get("lockFiles") or [])
    return covered


def gaps(checkout: Path, report: dict) -> list[dict[str, Any]]:
    files = tracked_files(checkout)
    covered = covered_files(report)
    found: list[dict[str, Any]] = []

    for file in files:
        name = Path(file).name
        source = next(
            (s for s in DEPENDENCY_FILES if any(fnmatch(name, p) for p in s.patterns)), None
        )
        if source and file not in covered:
            found.append(
                {
                    "kind": "unsupported_source",
                    "subject": file,
                    "reason": f"{source.label} that no scan adapter reads.",
                }
            )

        if name in LOCK_FILES:
            problem = _lock_file_problem(checkout / file)
            if problem:
                found.append({"kind": "unparseable_source", "subject": file, "reason": problem})

        if any(fnmatch(name, p) for p in INSTALL_LINE_FILES):
            found += _unpinned_installs(checkout, file)

    for problem in _renovate_problems(report):
        found.append(problem)
    return found


def _lock_file_problem(path: Path) -> str | None:
    text = path.read_text(errors="replace")
    if path.name.endswith(".json"):
        try:
            json.loads(text)
        except json.JSONDecodeError as error:
            return f"Not valid JSON: {error}."
        return None
    if path.name == "go.sum":
        for number, line in enumerate(text.splitlines(), 1):
            if line and len(line.split()) != 3:
                return f"Line {number} isn't 'module version hash'."
    return None


def _unpinned_installs(checkout: Path, file: str) -> list[dict[str, Any]]:
    found = []
    for number, line in enumerate((checkout / file).read_text(errors="replace").splitlines(), 1):
        for pattern, label in UNPINNED_INSTALLS:
            if pattern.search(line):
                found.append(
                    {
                        "kind": "unsupported_source",
                        "subject": f"{file}:{number}",
                        "reason": f"{label}, so there is no version to compare or update.",
                    }
                )
    return found


def _renovate_problems(report: dict) -> list[dict[str, Any]]:
    found = []
    for repository in (report.get("repositories") or {}).values():
        for problem in repository.get("problems") or []:
            found.append(
                {
                    "kind": "unparseable_source",
                    "subject": problem.get("file") or "renovate",
                    "reason": problem.get("message") or "Renovate reported a problem.",
                }
            )
    return found
