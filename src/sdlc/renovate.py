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
from collections.abc import Iterator
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

POLICY_PATH = ".github/renovate.json5"
# Every file Renovate reads its configuration from (config/app-strings.js), apart from
# package.json, which is source: only its `renovate` key is configuration.
CONFIG_FILES = [
    f"{base}{ext}"
    for base in (
        "renovate.json",
        ".github/renovate.json",
        ".gitlab/renovate.json",
        ".renovaterc.json",
    )
    for ext in ("", "c", "5")
] + [".renovaterc"]


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


def run(checkout: Path, *, policy: str | None = None, token: str | None = None) -> dict:
    """Run Renovate on a copy of the checkout, with exactly this policy, and return its report.

    Each run gets its own copy, so runs with different policies can't see each other's.
    """
    with tempfile.TemporaryDirectory(prefix="sdlc-renovate-") as work:
        subject = Path(work) / "subject"
        shutil.copytree(checkout, subject, symlinks=True)
        _commit_policy(subject, policy)
        # The temporary directories are private to this user (0700); Renovate's container
        # user needs to read the copy and write the report.
        os.chmod(subject, 0o755)  # noqa: S103 - a temporary copy of a public repository
        out = Path(work) / "out"
        out.mkdir()
        os.chmod(out, 0o777)  # noqa: S103 - Renovate's container user writes the report here

        runtime = os.environ.get("SDLC_CONTAINER_RUNTIME", "docker")
        config = scan_config()
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
            f"{subject}:/usr/src/app:ro,Z",
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
        report_path = out / "report.json"
        if result.returncode != 0 or not report_path.exists():
            output = (result.stdout + result.stderr)[-3000:]
            raise RenovateError(f"Renovate failed ({result.returncode}):\n{output}")
        return json.loads(report_path.read_text())


def _commit_policy(subject: Path, policy: str | None) -> None:
    """Make the policy the only Renovate configuration in the copy.

    Local mode only reads tracked files, so the policy is committed. Configuration elsewhere
    in the copy, including the `renovate` key of the root package.json, is removed, so
    Renovate can't read another file than the one the record names. The subject repository
    itself is never touched.
    """
    _git(subject, "rm", "--quiet", "--ignore-unmatch", "--", *CONFIG_FILES)
    package_json = subject / "package.json"
    try:
        package = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        package = None
    if isinstance(package, dict) and "renovate" in package:
        del package["renovate"]
        package_json.write_text(json.dumps(package, indent=2) + "\n")
        _git(subject, "add", "package.json")
    if policy is not None:
        target = subject / POLICY_PATH
        target.parent.mkdir(exist_ok=True)
        target.write_text(policy)
        _git(subject, "add", POLICY_PATH)
    _git(
        subject,
        "-c",
        "user.name=sdlc scan",
        "-c",
        "user.email=scan@localhost",
        "commit",
        "--quiet",
        "--allow-empty",
        "--message",
        "Update policy for this scan only",
    )


def validate(policy: str) -> list[str]:
    """Check a policy with Renovate's own validator; return the problems it reports.

    The validator decides which options exist and how they combine, so the scan doesn't
    keep its own copy of Renovate's rules. `--strict` also rejects options Renovate would
    silently migrate, which the scan's own rule matching wouldn't see.
    """
    runtime = os.environ.get("SDLC_CONTAINER_RUNTIME", "docker")
    with tempfile.TemporaryDirectory(prefix="sdlc-policy-") as work:
        (Path(work) / "renovate.json5").write_text(policy)
        os.chmod(work, 0o755)  # noqa: S103 - the validator's container user reads it
        os.chmod(Path(work) / "renovate.json5", 0o644)
        result = subprocess.run(  # noqa: S603 - fixed command; values are data
            [
                runtime,
                "run",
                "--rm",
                "--env",
                "LOG_FORMAT=json",
                "--volume",
                f"{work}:/policy:ro,Z",
                IMAGE,
                "renovate-config-validator",
                "--strict",
                "--no-global",
                "/policy/renovate.json5",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode == 0:
        return []
    problems = validator_problems(result.stdout + result.stderr)
    if not problems:
        output = (result.stdout + result.stderr)[-3000:]
        raise RenovateError(f"Renovate's validator failed ({result.returncode}):\n{output}")
    return problems


def validator_problems(log: str) -> list[str]:
    """The errors and warnings in the validator's JSON log."""
    problems = []
    for line in log.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or entry.get("level", 0) < 40:
            continue
        found = [p.get("message", "") for p in entry.get("errors") or []]
        found += [p.get("message", "") for p in entry.get("warnings") or []]
        if not found and "file" in entry:
            error = (entry.get("err") or {}).get("message")
            found = [f"{entry.get('msg')}: {error}" if error else entry.get("msg", "")]
        problems += [p for p in found if p]
    return problems


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
    dependencies: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    lines = _LineFinder(checkout)

    for manager, file, dep, dep_id in _dependencies(report):
        name = _name(dep)
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


def match_fields(report: dict) -> dict[str, dict[str, Any]]:
    """Per dependency id, the fields Renovate's package rules match on."""
    return {
        dep_id: {
            "depName": dep.get("depName"),
            "packageName": dep.get("packageName"),
            "datasource": dep.get("datasource"),
            "manager": manager,
        }
        for manager, _, dep, dep_id in _dependencies(report)
    }


def indirect(report: dict) -> set[str]:
    """Ids of the Go modules go.mod requires only indirectly.

    Renovate lists them but skips them by default. They record what the build resolved, not
    what the repository asks for, so the scan treats them like lock-file entries.
    """
    return {
        dep_id
        for manager, _, dep, dep_id in _dependencies(report)
        if manager == "gomod" and dep.get("depType") == "indirect"
    }


def go_toolchains(report: dict) -> dict[str, str]:
    """Per go.mod, the id of the directive that sets its Go toolchain.

    That is the `toolchain` directive when there is one, otherwise the `go` directive.
    Renovate names both `go`; their dependency type tells them apart. `toolchain default`
    means no toolchain directive, as for govulncheck: Renovate's pattern doesn't take it
    today, and if it ever does, it still won't count.
    """
    toolchains: dict[str, str] = {}
    for manager, file, dep, dep_id in _dependencies(report):
        if manager != "gomod":
            continue
        if (dep.get("depType") == "toolchain" and dep.get("currentValue") != "default") or (
            dep.get("depType") == "golang" and file not in toolchains
        ):
            toolchains[file] = dep_id
    return toolchains


def _dependencies(report: dict) -> Iterator[tuple[str, str, dict, str]]:
    """Each dependency in the report with its manager, file and id, in report order."""
    repositories = report.get("repositories") or {}
    if len(repositories) != 1:
        raise RenovateError(f"expected one repository in the report, found {len(repositories)}")
    package_files = next(iter(repositories.values())).get("packageFiles") or {}

    seen: dict[str, int] = {}
    for manager, entries in sorted(package_files.items()):
        for entry in entries:
            file = entry["packageFile"]
            for dep in entry.get("deps") or []:
                base_id = f"{manager}:{file}:{_name(dep)}"
                seen[base_id] = seen.get(base_id, 0) + 1
                yield (
                    manager,
                    file,
                    dep,
                    base_id if seen[base_id] == 1 else f"{base_id}#{seen[base_id]}",
                )


def _name(dep: dict) -> str:
    return dep.get("depName") or dep.get("packageName") or "?"


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
