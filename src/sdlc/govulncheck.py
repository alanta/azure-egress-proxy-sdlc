"""Find out with govulncheck whether a Go module's code reaches its vulnerabilities.

OSV-Scanner says which advisories match a version; govulncheck says whether the module's code
calls the vulnerable functions. It runs per `go.mod` in the pinned Go image, read-only, on the
packages of the module (tests excluded, as govulncheck does by default), once per platform in
`PLATFORMS`, and its findings come at three levels:
- a **symbol** finding traces a call from the module's code to a vulnerable function:
  `reachable`;
- a **package** finding: a vulnerable package is imported, but no vulnerable function is
  called; a **module** finding: the module is required at an affected version, nothing more.
  Both are `not_reachable`.
The most precise level on any platform counts.

Advisories on the Go standard library depend on the toolchain, so govulncheck runs with the
one `go.mod` declares: its `toolchain` directive, or else its `go` directive. The pinned image
builds govulncheck with its own Go, then `GOTOOLCHAIN` makes the `go` command download that
exact toolchain from the Go module proxy, checked against the checksum database. OSV-Scanner
doesn't report the standard library, so its advisories are added here, against the inventory
entry for that directive. An advisory on another module that OSV-Scanner didn't report is
added the way OSV-Scanner's are, with a locked entry if the inventory has none for it.

Every other ecosystem has no reachability analysis, so its findings stay `unknown`.
"""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sdlc import osv
from sdlc.native import CONTAINER_TMP, GO_IMAGE, NativeError, container, go_mods

VERSION = "v1.8.0"
PACKAGE = "golang.org/x/vuln/cmd/govulncheck"
SOURCE = "govulncheck"
STDLIB = "stdlib"

# A released Go toolchain name, as `GOTOOLCHAIN` takes it.
_TOOLCHAIN = re.compile(r"go1(\.\d+){1,2}((rc|beta)\d+)?")

# The platforms the analysis covers. Which code is built, and so which calls exist, depends on
# GOOS and GOARCH, and the container's own would make the result depend on the host. These are
# the platforms the subject releases for (its release.yml), with cgo off as it builds them.
GOOS = "linux"
PLATFORMS = ("amd64", "arm64")

# Written between the platforms' JSON streams, to tell them apart.
_MARKER = "sdlc_platform"

# govulncheck is built once, with the image's own Go, which it requires (1.26 or later), for
# the container's platform. GOFLAGS is cleared for the build: it is meant for the subject.
# Then it runs once per platform; GOARCH only changes the target, not the toolchain the go
# command downloads.
_SCRIPT = (
    f"GOTOOLCHAIN=local GOFLAGS= go install {PACKAGE}@{VERSION} >&2 || exit 1; "
    f"for arch in {' '.join(PLATFORMS)}; do "
    f'printf \'{{"{_MARKER}": "{GOOS}/%s"}}\\n\' "$arch"; '
    f"GOARCH=$arch {CONTAINER_TMP}/go/bin/govulncheck -format json ./... || exit 1; "
    "done"
)

_LEVELS = {"module": 0, "package": 1, "symbol": 2}


class GovulncheckError(Exception):
    """govulncheck didn't produce a usable result for a module."""


@dataclass(frozen=True)
class Run:
    go_mod: str  # relative to the checkout
    toolchain: str | None  # what go.mod declares, such as go1.25.14
    # govulncheck's JSON stream per platform, such as linux/amd64; None if it failed.
    platforms: dict[str, list[dict[str, Any]]] | None
    error: str | None = None

    @property
    def messages(self) -> list[dict[str, Any]]:
        return [m for messages in (self.platforms or {}).values() for m in messages]

    @property
    def go_version(self) -> str | None:
        """The toolchain govulncheck says it used."""
        return _config(self.messages).get("go_version")

    @property
    def database(self) -> tuple[str, str] | None:
        """The vulnerability database and when it was last modified, as govulncheck read it."""
        config = _config(self.messages)
        return (config.get("db", "?"), config.get("db_last_modified", "?")) if config else None


@dataclass(frozen=True)
class Reachability:
    vulnerabilities: list[dict[str, Any]]  # the given ones with reachability, then added ones
    gaps: list[dict[str, Any]]
    # As in osv.Findings: locked entries, indirect entries taken over, and fix candidates
    # for advisories only govulncheck reported.
    dependencies: list[dict[str, Any]]
    updated: list[dict[str, Any]]
    candidates: list[dict[str, Any]]


def tool_entries(runs: list[Run]) -> list[dict[str, str]]:
    """govulncheck itself, and per module the toolchain, platforms and database it used."""
    entries = [{"name": "govulncheck", "version": VERSION, "image": GO_IMAGE}]
    for run in runs:
        if run.platforms is None:
            continue
        entries.append(
            {
                "name": f"go toolchain for govulncheck ({run.go_mod}, {', '.join(run.platforms)})",
                "version": run.go_version or "?",
            }
        )
        if run.database:
            db, modified = run.database
            entries.append({"name": f"govulncheck database {db}", "version": modified})
    # One database for every module: list it once.
    unique = []
    for entry in entries:
        if entry not in unique:
            unique.append(entry)
    return unique


def toolchain(go_mod: str) -> str | None:
    """The toolchain a go.mod asks for: its `toolchain` directive, or else its `go` directive.

    From Go 1.21 on, `go 1.N` names a language version whose first release is go1.N.0, which
    is the toolchain the line requires at least. None when go.mod declares neither.
    """
    directives = {}
    for line in go_mod.splitlines():
        words = line.split("//", 1)[0].split()
        if len(words) == 2 and words[0] in ("go", "toolchain"):
            directives.setdefault(words[0], words[1])
    named = directives.get("toolchain")
    if named and named != "default":
        return named
    version = directives.get("go")
    if not version:
        return None
    parts = version.split(".")
    if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) >= 21:
        version += ".0"
    return f"go{version}"


def run(checkout: Path, go_mod: str, toolchain_name: str) -> str:
    """Run govulncheck on the module for each platform and return its output as text."""
    if not _TOOLCHAIN.fullmatch(toolchain_name):
        raise GovulncheckError(f"{go_mod} declares {toolchain_name}, which isn't a Go release")
    module_dir = Path(go_mod).parent
    # Vendored sources are what the build compiles, and may be patched: analyse those.
    vendored = (checkout / module_dir / "vendor" / "modules.txt").exists()
    try:
        return container(
            GO_IMAGE,
            f"/src/{module_dir}",
            checkout,
            {
                "GOPATH": f"{CONTAINER_TMP}/go",
                "GOCACHE": f"{CONTAINER_TMP}/gocache",
                "GOTOOLCHAIN": toolchain_name,
                # The module on its own: a go.work around it would change what is built.
                "GOWORK": "off",
                "GOOS": GOOS,
                "CGO_ENABLED": "0",
                # Read-only intent: report, never rewrite go.mod or go.sum.
                "GOFLAGS": "-mod=vendor" if vendored else "-mod=readonly",
            },
            "sh",
            "-c",
            _SCRIPT,
            read_only=True,
        )
    except NativeError as error:
        raise GovulncheckError(str(error)) from error


def parse(output: str, toolchain_name: str) -> dict[str, list[dict[str, Any]]]:
    """govulncheck's messages per platform; an error unless every platform ran, with the
    requested toolchain."""
    decoder = json.JSONDecoder()
    platforms: dict[str, list[dict[str, Any]]] = {}
    messages: list[dict[str, Any]] | None = None
    index = 0
    try:
        while index < len(output):
            if output[index].isspace():
                index += 1
                continue
            message, index = decoder.raw_decode(output, index)
            if _MARKER in message:
                messages = platforms.setdefault(message[_MARKER], [])
            elif messages is None:
                raise GovulncheckError("govulncheck's output names no platform")
            else:
                messages.append(message)
    except ValueError as error:
        raise GovulncheckError(f"govulncheck's output isn't JSON: {error}") from error
    expected = [f"{GOOS}/{arch}" for arch in PLATFORMS]
    if list(platforms) != expected:
        raise GovulncheckError(f"govulncheck ran for {list(platforms)}, not {expected}")
    for platform, found in platforms.items():
        used = _config(found).get("go_version")
        if used != toolchain_name:
            # Standard library findings would then be about another version than go.mod's.
            raise GovulncheckError(
                f"govulncheck ran with {used} for {platform}, not {toolchain_name}"
            )
    return platforms


def scan(checkout: Path) -> list[Run]:
    """govulncheck's result for every go.mod in the checkout; a failure is kept, not raised."""
    runs = []
    for go_mod in go_mods(checkout):
        name = toolchain((checkout / go_mod).read_text())
        if name is None:
            runs.append(Run(go_mod, None, None, "go.mod declares no Go version"))
            continue
        try:
            runs.append(Run(go_mod, name, parse(run(checkout, go_mod, name), name)))
        except GovulncheckError as error:
            runs.append(Run(go_mod, name, None, str(error)))
    return runs


def apply(
    runs: list[Run],
    vulnerabilities: list[dict[str, Any]],
    dependencies: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    *,
    toolchains: dict[str, str],
    indirect: set[str],
    looked_up_at: str,
    classify: Callable[[list[dict], dict[str, dict]], list[dict]] = lambda c, fields: c,
    checkout: Path | None = None,
) -> Reachability:
    """Set the reachability of the Go vulnerabilities, and add those only govulncheck found.

    A vulnerability takes its reachability from govulncheck's findings for the same advisory
    (by id or alias) on the same module and version in the same go.mod. `toolchains` maps each
    go.mod to the inventory entry of the directive that sets its toolchain, which the standard
    library's advisories refer to. Advisories on other modules go through `osv.findings`, as
    if OSV-Scanner had reported them, which is what the remaining options are for.
    """
    entries = {d["id"]: d for d in dependencies}
    by_entry: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        by_entry.setdefault(candidate["dependency"], []).append(candidate)

    result = [dict(v) for v in vulnerabilities]
    added: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    locked: list[dict[str, Any]] = []
    updated: list[dict[str, Any]] = []
    new_candidates: list[dict[str, Any]] = []
    for run in runs:
        if run.platforms is None:
            gaps.append(
                {
                    "kind": "unavailable_source",
                    "subject": f"govulncheck: {run.go_mod}",
                    "reason": "govulncheck didn't run, so the reachability of this module's "
                    "Go advisories is unknown and its standard library advisories weren't "
                    f"checked: {run.error}",
                }
            )
            continue
        records = {m["osv"]["id"]: m["osv"] for m in run.messages if "osv" in m}
        reach = _levels(run.messages)
        matched: set[tuple[str, str]] = set()  # (govulncheck id, module) given to a finding

        for vulnerability in result:
            module = _module(entries.get(vulnerability["dependency"]), toolchains, run.go_mod)
            if module is None:
                continue
            names = {vulnerability["advisory"], *vulnerability.get("aliases", [])}
            levels = []
            for (vuln_id, found_module, version), level in reach.items():
                if (
                    found_module == module
                    and _bare(version) == _bare(vulnerability["affected_version"])
                    and names & _names(vuln_id, records)
                ):
                    levels.append(level)
                    matched.add((vuln_id, module))
            # No finding for an advisory OSV-Scanner matched: govulncheck's database doesn't
            # have it, or judges this version unaffected. Either way its output says nothing
            # about whether the code reaches it, so it stays `unknown`.
            if levels:
                vulnerability["reachability"] = _reachability(max(levels))

        others: dict[tuple[str, str], list[str]] = {}  # (module, version): advisories
        for (vuln_id, module, version), level in sorted(reach.items()):
            if (vuln_id, module) in matched:
                continue
            if module != STDLIB:
                others.setdefault((module, version), []).append(vuln_id)
                continue
            entry = next((d for d in dependencies if d["id"] == toolchains.get(run.go_mod)), None)
            if entry is None:
                gaps.append(
                    {
                        "kind": "unavailable_source",
                        "subject": f"govulncheck: {run.go_mod}: {STDLIB}",
                        "reason": f"govulncheck reported {vuln_id} on the standard library, "
                        "but the inventory has no go or toolchain directive for it to refer to.",
                    }
                )
                continue
            record = records.get(vuln_id, {"id": vuln_id})
            advisory = osv.Advisory(vuln_id, sorted(set(record.get("aliases") or [])), [record])
            added.append(
                osv.vulnerability(
                    entry,
                    by_entry.get(entry["id"], []),
                    advisory,
                    "Go",
                    STDLIB,
                    _bare(version),
                    source=SOURCE,
                    reachability=_reachability(level),
                )
            )

        if others:
            found = osv.findings(
                _as_osv_scanner_output(run.go_mod, others, records),
                dependencies + locked,
                candidates + new_candidates,
                indirect=indirect,
                looked_up_at=looked_up_at,
                classify=classify,
                checkout=checkout,
            )
            levels_by = {(v, m): level for (v, m, _), level in reach.items()}
            names_by = {
                d["id"]: d["name"]
                for d in dependencies + locked + found.dependencies + found.updated
            }
            for vulnerability in found.vulnerabilities:
                level = levels_by[
                    (vulnerability["advisory"], names_by[vulnerability["dependency"]])
                ]
                vulnerability |= {"source": SOURCE, "reachability": _reachability(level)}
                added.append(vulnerability)
            locked += found.dependencies
            updated += found.updated
            new_candidates += found.candidates
            gaps += found.gaps
    return Reachability(result + added, gaps, locked, updated, new_candidates)


def _as_osv_scanner_output(
    go_mod: str, advisories: dict[tuple[str, str], list[str]], records: dict[str, dict]
) -> dict[str, Any]:
    """govulncheck's findings on modules, in the shape of OSV-Scanner's output."""
    packages = [
        {
            "package": {"ecosystem": "Go", "name": module, "version": _bare(version)},
            "vulnerabilities": [records.get(i, {"id": i}) for i in ids],
            "groups": [{"ids": [i]} for i in ids],
        }
        for (module, version), ids in advisories.items()
    ]
    return {"results": [{"source": {"path": f"/src/{go_mod}"}, "packages": packages}]}


def _levels(messages: list[dict[str, Any]]) -> dict[tuple[str, str, str], int]:
    """Per advisory, module and version, the most precise level govulncheck found it at."""
    levels: dict[tuple[str, str, str], int] = {}
    for message in messages:
        finding = message.get("finding")
        if not finding or not finding.get("trace"):
            continue
        # The first frame is the vulnerable symbol, package or module itself.
        frame = finding["trace"][0]
        level = (
            _LEVELS["symbol"]
            if frame.get("function")
            else _LEVELS["package"]
            if frame.get("package")
            else _LEVELS["module"]
        )
        key = (finding["osv"], frame.get("module", ""), frame.get("version", ""))
        levels[key] = max(level, levels.get(key, level))
    return levels


def _reachability(level: int) -> str:
    return "reachable" if level == _LEVELS["symbol"] else "not_reachable"


def _names(vuln_id: str, records: dict[str, dict[str, Any]]) -> set[str]:
    return {vuln_id, *((records.get(vuln_id) or {}).get("aliases") or [])}


def _module(entry: dict[str, Any] | None, toolchains: dict[str, str], go_mod: str) -> str | None:
    """The module govulncheck names for an inventory entry of this go.mod, if it is one."""
    if entry is None:
        return None
    if entry["id"] == toolchains.get(go_mod):
        return STDLIB
    if entry["ecosystem"] == "go" and entry["location"]["file"] == go_mod:
        return entry["name"]
    return None


def _config(messages: list[dict[str, Any]]) -> dict[str, Any]:
    return next((m["config"] for m in messages if "config" in m), {})


def _bare(version: str) -> str:
    return version.removeprefix("v")
