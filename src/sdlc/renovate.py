"""Run Renovate in lookup mode and turn its report into inventory entries and candidates.

Renovate only reads: it runs on the scan's throwaway checkout with `--dry-run=lookup`, and
the token it gets can only read. Its report file, not its log, is the contract (see
docs/tooling-spike.md).
"""

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

VERSION = "44.145.1"
IMAGE = (
    f"docker.io/renovate/renovate:{VERSION}"
    "@sha256:6f1f3e2d9d0c3f99aa1f61f7509d302185de7deb173ac8c5ff88a5ce283ec435"
)

# Skip reasons that mean "we couldn't find out", as opposed to "there is nothing to look up".
UNKNOWN_SKIP_REASONS = {"github-token-required", "rate-limited", "unknown-registry"}

SKIP_REASON_TEXT = {
    "disabled": "Not looked up: Renovate skips this kind of dependency by default.",
    "github-token-required": "Lookup needs a GitHub token, and none was available.",
    "invalid-value": "The declared value isn't a version, so it can't be compared.",
    "invalid-version": "The declared value isn't a version, so it can't be compared.",
    "unspecified-version": "No version is pinned, so there is nothing to compare.",
}

# Renovate update types that are not a newer version: pinning to a digest, for instance.
NOT_AN_UPDATE = {"pin", "pinDigest"}
UPDATE_TYPES = {"patch", "minor", "major", "digest"}


class RenovateError(Exception):
    """Renovate didn't produce a usable report."""


@dataclass(frozen=True)
class Inventory:
    dependencies: list[dict[str, Any]]
    candidates: list[dict[str, Any]]


def tool_entry() -> dict[str, str]:
    return {"name": "renovate", "version": VERSION, "image": IMAGE}


def scan_config() -> Path:
    """Renovate configuration applied to every subject, shipped with the package."""
    return Path(str(files("sdlc").joinpath("config/scan.renovate.json5")))


def run(checkout: Path, *, trial_policy: Path | None = None, token: str | None = None) -> dict:
    """Run Renovate on a throwaway checkout and return its report."""
    if trial_policy is not None:
        # Local mode only reads tracked files, so the trial policy is committed into the
        # throwaway checkout. The subject repository itself is never touched.
        target = checkout / ".github" / "renovate.json5"
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(trial_policy, target)
        _git(checkout, "add", ".github/renovate.json5")
        _git(
            checkout,
            "-c",
            "user.name=sdlc scan",
            "-c",
            "user.email=scan@localhost",
            "commit",
            "--quiet",
            "--message",
            "Trial policy for this scan only",
        )

    # The throwaway checkout is private to this user (0700); Renovate's container user
    # needs to read it.
    os.chmod(checkout, 0o755)  # noqa: S103 - a temporary copy of a public repository

    runtime = os.environ.get("SDLC_CONTAINER_RUNTIME", "docker")
    config = scan_config()
    with tempfile.TemporaryDirectory(prefix="sdlc-renovate-") as out:
        os.chmod(out, 0o777)  # noqa: S103 - Renovate's container user writes the report here
        command = [
            runtime,
            "run",
            "--rm",
            "--env",
            "LOG_LEVEL=warn",
            "--env",
            "RENOVATE_ONBOARDING=false",
            "--env",
            "RENOVATE_REQUIRE_CONFIG=optional",
            "--env",
            f"RENOVATE_CONFIG_FILE=/config/{config.name}",
            "--volume",
            f"{config.parent}:/config:ro,Z",
            "--volume",
            f"{checkout}:/usr/src/app:ro,Z",
            "--volume",
            f"{out}:/out:Z",
            "--workdir",
            "/usr/src/app",
        ]
        env = dict(os.environ)
        if token:
            # Passed by name, so the value never appears on a command line.
            env["GITHUB_COM_TOKEN"] = token
            command += ["--env", "GITHUB_COM_TOKEN"]
        command += [
            IMAGE,
            "renovate",
            "--platform=local",
            "--dry-run=lookup",
            "--report-type=file",
            "--report-path=/out/report.json",
        ]
        result = subprocess.run(  # noqa: S603 - fixed command; values are data
            command, env=env, capture_output=True, text=True, check=False
        )
        report_path = Path(out) / "report.json"
        if result.returncode != 0 or not report_path.exists():
            output = (result.stdout + result.stderr)[-3000:]
            raise RenovateError(f"Renovate failed ({result.returncode}):\n{output}")
        return json.loads(report_path.read_text())


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603 - fixed git command
        ["git", *args],  # noqa: S607 - git from PATH
        cwd=cwd,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
        check=True,
        capture_output=True,
    )


def normalize(report: dict, *, looked_up_at: str, checkout: Path | None = None) -> Inventory:
    """Turn a Renovate report into inventory entries and candidates for the scan record.

    `looked_up_at` is when Renovate ran: its report doesn't time individual lookups. With a
    checkout, each entry also gets the line it is declared on.
    """
    repositories = report.get("repositories") or {}
    if len(repositories) != 1:
        raise RenovateError(f"expected one repository in the report, found {len(repositories)}")
    package_files = next(iter(repositories.values())).get("packageFiles") or {}

    dependencies: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    lines = _LineFinder(checkout)

    for manager, entries in sorted(package_files.items()):
        for entry in entries:
            file = entry["packageFile"]
            for dep in entry.get("deps") or []:
                name = dep.get("depName") or dep.get("packageName") or "?"
                base_id = f"{manager}:{file}:{name}"
                seen[base_id] = seen.get(base_id, 0) + 1
                dep_id = base_id if seen[base_id] == 1 else f"{base_id}#{seen[base_id]}"

                location: dict[str, Any] = {"file": file}
                line = lines.find(file, dep.get("replaceString")) or lines.find_unique(file, name)
                if line:
                    location["line"] = line

                lookup, dep_candidates = _lookup(dep, dep_id, looked_up_at)
                dependencies.append(
                    {
                        "id": dep_id,
                        "ecosystem": dep.get("datasource") or manager,
                        "name": name,
                        "current": dep.get("currentValue") or dep.get("currentDigest"),
                        "origin": "declared",
                        "location": location,
                        "lookup": lookup,
                    }
                )
                candidates += dep_candidates

    return Inventory(dependencies, candidates)


def _lookup(dep: dict, dep_id: str, looked_up_at: str) -> tuple[dict, list[dict]]:
    lookup: dict[str, Any] = {}
    if dep.get("datasource"):
        lookup["datasource"] = dep["datasource"]

    skip = dep.get("skipReason")
    if skip:
        state = "unknown" if skip in UNKNOWN_SKIP_REASONS else "skipped"
        reason = SKIP_REASON_TEXT.get(skip, f"Renovate skipped it: {skip}.")
        return {"state": state, "reason": reason, **lookup}, []

    lookup["looked_up_at"] = looked_up_at
    warnings = [w.get("message", "") for w in dep.get("warnings") or []]
    updates = [u for u in dep.get("updates") or [] if u.get("updateType") not in NOT_AN_UPDATE]
    unsupported = sorted({u.get("updateType") for u in updates} - UPDATE_TYPES, key=str)
    if unsupported:
        reason = f"Renovate reported update types the scan doesn't handle: {unsupported}."
        return {"state": "unknown", "reason": reason, **lookup}, []

    if not updates:
        if warnings:
            return {"state": "unknown", "reason": "; ".join(warnings), **lookup}, []
        return {"state": "current", **lookup}, []

    candidates = [
        {
            "dependency": dep_id,
            "update_type": update["updateType"],
            "version": update.get("newValue") or update.get("newVersion") or update["newDigest"],
            "classification": "in_scope",
        }
        for update in updates
    ]
    return {"state": "outdated", **lookup}, candidates


class _LineFinder:
    """Find the line a dependency is declared on, from the text Renovate would replace."""

    def __init__(self, checkout: Path | None):
        self.checkout = checkout
        self.cache: dict[str, list[str]] = {}
        self.used: dict[tuple[str, str], int] = {}

    def _lines(self, file: str) -> list[str]:
        if self.checkout is None:
            return []
        if file not in self.cache:
            path = self.checkout / file
            self.cache[file] = (
                path.read_text(errors="replace").splitlines() if path.exists() else []
            )
        return self.cache[file]

    def find(self, file: str, text: str | None) -> int | None:
        if not text:
            return None
        # The same text can appear more than once (one action used in several jobs): the
        # n-th dependency with that text gets the n-th line containing it.
        nth = self.used.get((file, text), 0)
        matches = [i for i, line in enumerate(self._lines(file), 1) if text in line]
        self.used[(file, text)] = nth + 1
        return matches[nth] if nth < len(matches) else None

    def find_unique(self, file: str, name: str) -> int | None:
        """The line naming the dependency, when the report gives no text and exactly one does."""
        matches = [i for i, line in enumerate(self._lines(file), 1) if f'"{name}"' in line]
        return matches[0] if len(matches) == 1 else None
