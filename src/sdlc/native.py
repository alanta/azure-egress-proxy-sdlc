"""Ask the package managers themselves what is outdated, to catch what Renovate misses.

`dotnet list package --outdated` and `go list -m -u` run in pinned containers on the scan's
throwaway checkout. Where they report a newer version of a direct dependency that the scan
has no candidate for, the record says so (design decision 3).
"""

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

DOTNET_IMAGE = (
    "mcr.microsoft.com/dotnet/sdk:10.0"
    "@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317"
)
GO_IMAGE = (
    "docker.io/library/golang:1.27-alpine"
    "@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414"
)


# Scratch space inside the container, not on the host.
CONTAINER_TMP = "/tmp"  # noqa: S108


class NativeError(Exception):
    """A package manager query couldn't run."""


@dataclass(frozen=True)
class NativeUpdate:
    source: str  # "dotnet" or "go"
    name: str
    current: str
    latest: str
    direct: bool
    location: str  # project file or go.mod


def tool_entries() -> list[dict[str, str]]:
    return [
        {"name": "dotnet", "version": "10.0", "image": DOTNET_IMAGE},
        {"name": "go", "version": "1.27", "image": GO_IMAGE},
    ]


def _container(image: str, workdir: str, checkout: Path, env: dict[str, str], *command: str) -> str:
    runtime = os.environ.get("SDLC_CONTAINER_RUNTIME", "docker")
    version = subprocess.run(  # noqa: S603 - the configured container runtime
        [runtime, "--version"], capture_output=True, text=True, check=False
    ).stdout
    # Files the tool writes (obj/, caches) must stay owned by us, so the throwaway
    # checkout can be deleted afterwards.
    if "podman" in version.lower():
        user = ["--userns=keep-id"]
    else:
        user = ["--user", f"{os.getuid()}:{os.getgid()}"]
    args = [runtime, "run", "--rm", *user, "--env", f"HOME={CONTAINER_TMP}"]
    for key, value in env.items():
        args += ["--env", f"{key}={value}"]
    args += ["--volume", f"{checkout}:/src:Z", "--workdir", workdir, image, *command]
    result = subprocess.run(  # noqa: S603 - fixed command; values are data
        args, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise NativeError(result.stderr.strip()[-1500:] or result.stdout.strip()[-1500:])
    return result.stdout


def dotnet_updates(checkout: Path) -> list[NativeUpdate]:
    solutions = sorted(checkout.glob("*.slnx")) + sorted(checkout.glob("*.sln"))
    if not solutions:
        return []
    solution = solutions[0].name
    output = _container(
        DOTNET_IMAGE,
        "/src",
        checkout,
        {
            "DOTNET_CLI_HOME": CONTAINER_TMP,
            "NUGET_PACKAGES": f"{CONTAINER_TMP}/nuget",
            "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        },
        "sh",
        "-c",
        # Restore exactly what the lock files pin, then ask what is newer.
        f'dotnet restore "{solution}" --locked-mode >/tmp/restore.log 2>&1 '
        "|| { tail -20 /tmp/restore.log >&2; exit 1; }; "
        f'dotnet list "{solution}" package --outdated --include-transitive '
        "--format json --output-version 1",
    )
    return parse_dotnet(json.loads(output), checkout)


def parse_dotnet(listing: dict[str, Any], checkout: Path) -> list[NativeUpdate]:
    updates = []
    for project in listing.get("projects") or []:
        path = project["path"].removeprefix("/src/")
        if path.startswith(str(checkout)):
            path = str(Path(path).relative_to(checkout))
        for framework in project.get("frameworks") or []:
            for direct, key in ((True, "topLevelPackages"), (False, "transitivePackages")):
                for package in framework.get(key) or []:
                    updates.append(
                        NativeUpdate(
                            "dotnet",
                            package["id"],
                            package["resolvedVersion"],
                            package["latestVersion"],
                            direct,
                            path,
                        )
                    )
    return updates


def go_updates(checkout: Path) -> list[NativeUpdate]:
    updates = []
    for go_mod in sorted(checkout.glob("**/go.mod")):
        module_dir = go_mod.parent.relative_to(checkout)
        output = _container(
            GO_IMAGE,
            f"/src/{module_dir}",
            checkout,
            {
                "GOPATH": f"{CONTAINER_TMP}/go",
                "GOCACHE": f"{CONTAINER_TMP}/gocache",
                "GOTOOLCHAIN": "local",
                # Read-only intent: report, never rewrite go.mod or go.sum.
                "GOFLAGS": "-mod=readonly",
            },
            "go",
            "list",
            "-m",
            "-u",
            "-json",
            "all",
        )
        updates += parse_go(output, str(module_dir / "go.mod"))
    return updates


def parse_go(output: str, location: str) -> list[NativeUpdate]:
    decoder = json.JSONDecoder()
    updates, index = [], 0
    while index < len(output):
        if output[index].isspace():
            index += 1
            continue
        module, index = decoder.raw_decode(output, index)
        if module.get("Main") or not module.get("Update"):
            continue
        updates.append(
            NativeUpdate(
                "go",
                module["Path"],
                module["Version"],
                module["Update"]["Version"],
                not module.get("Indirect", False),
                location,
            )
        )
    return updates


def cross_check(
    native: list[NativeUpdate],
    dependencies: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Direct dependencies the package manager says are outdated, but the scan doesn't agree."""
    ecosystem = {"dotnet": "nuget", "go": "go"}
    by_dep: dict[str, set[str]] = {}
    for candidate in candidates:
        by_dep.setdefault(candidate["dependency"], set()).add(candidate["version"].lstrip("v"))

    disagreements = []
    seen = set()
    for update in native:
        if not update.direct or (update.source, update.name) in seen:
            continue
        seen.add((update.source, update.name))
        matching = [
            d
            for d in dependencies
            if d["name"] == update.name and d["ecosystem"] == ecosystem[update.source]
        ]
        scan_versions = sorted({v for d in matching for v in by_dep.get(d["id"], set())})
        if update.latest.lstrip("v") in scan_versions:
            continue
        disagreements.append(
            {
                "source": update.source,
                "name": update.name,
                "location": update.location,
                "current": update.current,
                "native_latest": update.latest,
                "scan_candidates": scan_versions,
            }
        )
    return disagreements


def lock_drift(
    native: list[NativeUpdate],
    dependencies: list[dict[str, Any]],
    *,
    looked_up_at: str,
    checkout: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Locked entries older than the version the repository declares (design decision 3a).

    Returns inventory entries and their candidates. The candidate is the declared version:
    the drift is fixed by resolving what the repository already declares.
    """
    declared: dict[str, Version] = {}
    for dep in dependencies:
        if dep["ecosystem"] != "nuget" or dep["origin"] != "declared" or not dep["current"]:
            continue
        try:
            version = Version(dep["current"])
        except InvalidVersion:
            continue
        declared[dep["name"]] = max(version, declared.get(dep["name"], version))

    entries: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    seen = set()
    for update in native:
        if update.source != "dotnet" or update.direct or update.name not in declared:
            continue
        try:
            locked = Version(update.current)
        except InvalidVersion:
            continue
        target = declared[update.name]
        lock_file = str(Path(update.location).parent / "packages.lock.json")
        if locked >= target or (lock_file, update.name) in seen:
            continue
        seen.add((lock_file, update.name))

        dep_id = f"locked:{lock_file}:{update.name}"
        location: dict[str, Any] = {"file": lock_file}
        line = _line_naming(checkout, lock_file, update.name)
        if line:
            location["line"] = line
        entries.append(
            {
                "id": dep_id,
                "ecosystem": "nuget",
                "name": update.name,
                "current": update.current,
                "origin": "locked",
                "location": location,
                "lookup": {
                    "state": "outdated",
                    "datasource": "nuget",
                    "looked_up_at": looked_up_at,
                },
            }
        )
        candidates.append(
            {
                "dependency": dep_id,
                "update_type": update_type(locked, target),
                "version": str(target),
                "classification": "in_scope",
            }
        )
    return entries, candidates


def update_type(current: Version, target: Version) -> str:
    if target.major != current.major:
        return "major"
    if target.minor != current.minor:
        return "minor"
    return "patch"


def _line_naming(checkout: Path | None, file: str, name: str) -> int | None:
    if checkout is None or not (checkout / file).exists():
        return None
    for number, line in enumerate((checkout / file).read_text().splitlines(), 1):
        if f'"{name}": {{' in line:
            return number
    return None
