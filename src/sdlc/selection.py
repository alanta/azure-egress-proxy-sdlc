"""Decide which updates to prepare for a scanned revision, why, and to which versions.

The selection is a pure function of the scan record, the update policy the scan used and the
scan's date (update-selection, design decision 1). It keeps nothing between scans: an update
that hasn't been merged is selected again for as long as its reason holds. Everything it
needs is in the record, decided by the scan: each candidate's classification and group, each
vulnerability's fix and whether a candidate reaches it, and each version line's lifecycle.

It returns a JSON-serialisable section for the record, in a stable order:
- `date`: the scan's date, which the batch window and release ages are measured against;
- `defaults`: the batch window and minimum release age in use;
- `batch_window`: whether the window is open on that date, and when the next one opens;
- `units`: what to prepare, each with its name, reasons, targets, breaking mark and evidence;
- `not_prepared`: every reason that didn't become a unit, and why.

Only in-scope candidates are ever targets, whatever the reason, so the policy's holds always
win, security fixes included.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sdlc import lifecycle, native, osv
from sdlc.policy import Policy

# The batch window: these days of every month, inclusive.
BATCH_WINDOW_FIRST_DAY = 1
BATCH_WINDOW_LAST_DAY = 7
# How old a batch update's release must be, in days, on the scan's date.
MINIMUM_RELEASE_AGE_DAYS = 7

SECURITY = "security"
LIFECYCLE = "lifecycle"
BATCH = "batch"
REASONS = (SECURITY, LIFECYCLE, BATCH)

# The lifecycle states that select a line's move, as the scan recorded them (90 days ahead).
ENDING = ("nearing_end_of_life", "end_of_life")

# What the selection reports instead of a unit, in the order it reports them.
FIX_HELD = "fix_held"  # vulnerable, but only candidates the policy holds reach the fix
NO_ROUTE = "no_route"  # the record gives no fixed version
NO_CANDIDATE = "no_candidate"  # there is a fix, but no candidate reaches it
EARLY_WARNING = "early_warning"  # a line is ending, but no in-scope candidate leaves it
NOT_EVALUATED = "not_evaluated"  # data the decision needs is missing
WAITING = "waiting"  # a batch update too young for this window
KINDS = (FIX_HELD, NO_ROUTE, NO_CANDIDATE, EARLY_WARNING, NOT_EVALUATED, WAITING)

# Update types from smallest to largest. A digest only re-pins the same version, so it never
# reaches a fix (the scan doesn't judge digests against advisories either).
SIZES = ("digest", "patch", "minor", "major")

# Unit names are used as branch names as they are, so they are kept to a length a branch
# name and a prefix such as `sdlc/` comfortably fit in.
NAME_LENGTH = 100

# Unavailable sources that give no security reason. Every other one, such as OSV-Scanner, a
# lock file it returned nothing for, govulncheck or the Dependabot alerts, may hide one, so
# its reasons are reported as not evaluated. Like the report's NOT_ABOUT_VULNERABILITIES,
# but the alerts count here: they are evidence of a vulnerability, not only a comparison.
NOT_ABOUT_SECURITY = {lifecycle.SUBJECT, *native.LABELS.values()}


class SelectionError(Exception):
    """The inputs don't belong together, so no selection can be made from them."""


@dataclass
class _Fix:
    """A declaration's security fix: its advisories, and the in-scope candidates that reach
    the fix of every one of them, smallest first."""

    advisories: list[dict[str, Any]]
    reaching: list[dict[str, Any]]

    @property
    def target(self) -> dict[str, Any]:
        return self.reaching[0]

    @property
    def versions(self) -> set[str]:
        return {c["version"] for c in self.reaching}


def select(record: dict[str, Any], policy: Policy, today: date) -> dict[str, Any]:
    """The units to prepare for the scanned revision, and what can't be prepared.

    The policy's holds and groups are read from the record, where the scan recorded them per
    candidate, so the policy is only checked to be the one the record names.
    """
    if policy.source != record["policy"]:
        raise SelectionError(
            f"the record was classified with policy {record['policy']}, not {policy.source}"
        )
    entries = {d["id"]: d for d in record["inventory"]}
    candidates: dict[str, list[dict[str, Any]]] = {}
    for candidate in record["candidates"]:
        candidates.setdefault(candidate["dependency"], []).append(candidate)

    not_prepared: list[dict[str, Any]] = []
    fixes = _security_fixes(record, entries, candidates, not_prepared)
    # A lifecycle unit takes over the security fixes of its dependencies, so it goes first.
    units = _lifecycle_units(record, entries, candidates, fixes, today, not_prepared)
    units += _security_units(fixes, entries, today)
    in_units = {t["dependency"] for unit in units for t in unit["targets"]}
    units += _batch_units(entries, candidates, in_units, today, not_prepared)
    units = _named(units)

    return {
        "date": today.isoformat(),
        "defaults": {
            "batch_window": {
                "first_day": BATCH_WINDOW_FIRST_DAY,
                "last_day": BATCH_WINDOW_LAST_DAY,
            },
            "minimum_release_age_days": MINIMUM_RELEASE_AGE_DAYS,
        },
        "batch_window": batch_window(today),
        "units": sorted(units, key=lambda u: (REASONS.index(u["reasons"][0]), u["name"])),
        "not_prepared": sorted(not_prepared, key=_report_order),
    }


def batch_window(today: date) -> dict[str, Any]:
    """Whether the batch window is open on the date, and the first day of the next one."""
    is_open = BATCH_WINDOW_FIRST_DAY <= today.day <= BATCH_WINDOW_LAST_DAY
    this_month = today.replace(day=BATCH_WINDOW_FIRST_DAY)
    if today < this_month:
        next_opens = this_month
    elif today.month == 12:
        next_opens = date(today.year + 1, 1, BATCH_WINDOW_FIRST_DAY)
    else:
        next_opens = date(today.year, today.month + 1, BATCH_WINDOW_FIRST_DAY)
    return {"open": is_open, "next_opens": next_opens.isoformat()}


def _security_fixes(
    record: dict[str, Any],
    entries: dict[str, dict[str, Any]],
    candidates: dict[str, list[dict[str, Any]]],
    not_prepared: list[dict[str, Any]],
) -> dict[str, _Fix]:
    """Per vulnerable declaration, the in-scope candidates that reach the fix of every one of
    its advisories that a candidate reaches; every other advisory, and every unread source,
    is reported.

    The scan compared each candidate with the advisory's affected ranges and recorded those
    that are outside them as `fix_reached_by` (design decision 3), so no version is compared
    here: above the fixed version isn't enough where a later range affects a version again.
    """
    reached: dict[str, list[dict[str, Any]]] = {}
    for vulnerability in record["vulnerabilities"]:
        dep_id = vulnerability["dependency"]
        report = {
            "reason": SECURITY,
            "dependency": dep_id,
            "advisory": vulnerability["advisory"],
        }
        fixed = vulnerability["fixed_version"]
        last_affected = vulnerability.get("last_affected")
        if fixed is None and last_affected is None:
            # The scan records no fixed version both when the advisory names none and when
            # it can't read one from the advisory's ranges, so this doesn't say which.
            not_prepared.append(
                report
                | {
                    "kind": NO_ROUTE,
                    "detail": "The record gives no fixed version for the advisory: it names "
                    "none, or the scan couldn't read one from its ranges.",
                }
            )
            continue
        fix = f"the fixed version {fixed}" if fixed else f"a version above {last_affected}"
        outcome = vulnerability["fix_reached_by_candidate"]
        if outcome == "unknown":
            detail = _unknown(entries[dep_id], candidates.get(dep_id, []), fix)
            not_prepared.append(report | {"kind": NOT_EVALUATED, "detail": detail})
        elif outcome is False and "fix_held_by" in vulnerability:
            not_prepared.append(
                report
                | {
                    "kind": FIX_HELD,
                    "held_by": vulnerability["fix_held_by"],
                    "detail": f"Vulnerable, fix held by policy: only candidates that rule "
                    f"holds reach {fix}.",
                }
            )
        elif outcome is False:
            not_prepared.append(
                report | {"kind": NO_CANDIDATE, "detail": f"No candidate reaches {fix}."}
            )
        elif "fix_reached_by" not in vulnerability:
            not_prepared.append(
                report
                | {
                    "kind": NOT_EVALUATED,
                    "detail": f"The record says an in-scope candidate reaches {fix}, but not "
                    "which one, so there is no target.",
                }
            )
        else:
            reached.setdefault(dep_id, []).append(vulnerability)

    fixes: dict[str, _Fix] = {}
    for dep_id, advisories in reached.items():
        # One update fixes them all, or the declaration is reported rather than guessed at.
        common = set.intersection(*(set(v["fix_reached_by"]) for v in advisories))
        reaching = sorted(
            (
                c
                for c in candidates.get(dep_id, [])
                if c["classification"] == "in_scope"
                and c["update_type"] != "digest"
                and c["version"] in common
            ),
            key=_size,
        )
        if reaching:
            fixes[dep_id] = _Fix(advisories, reaching)
            continue
        each = "; ".join(f"{v['advisory']}: {', '.join(v['fix_reached_by'])}" for v in advisories)
        not_prepared.append(
            {
                "kind": NO_CANDIDATE,
                "reason": SECURITY,
                "dependency": dep_id,
                "advisories": [v["advisory"] for v in advisories],
                "detail": f"No single in-scope candidate reaches the fix of every advisory on "
                f"it ({each}).",
            }
        )

    not_prepared += _unread_sources(record)
    not_prepared += _unmatched_alerts(record)
    return fixes


def _unknown(entry: dict[str, Any], candidates: list[dict[str, Any]], fix: str) -> str:
    """Why the scan couldn't tell whether a candidate reaches the fix."""
    lookup = entry["lookup"]
    if lookup["state"] in ("unknown", "skipped"):
        return (
            f"Whether a candidate reaches {fix} is unknown: the lookup of "
            f"{entry['name']} is {lookup['state']}. {lookup['reason']}"
        )
    if not candidates:
        return f"Whether a candidate reaches {fix} is unknown: the record has no candidates for it."
    if all(c["update_type"] == "digest" for c in candidates):
        return (
            f"Whether a candidate reaches {fix} is unknown: its only candidates are digest "
            "updates, which the scan doesn't judge against advisories."
        )
    return (
        f"Whether a candidate reaches {fix} is unknown: the scan couldn't evaluate the "
        "advisory's ranges for its candidates."
    )


def _unread_sources(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The sources of security reasons the scan couldn't read, in whole or for one file or
    package: what they would say isn't evaluated."""
    return [
        {
            "kind": NOT_EVALUATED,
            "reason": SECURITY,
            "source": gap["subject"],
            "detail": gap["reason"],
        }
        for gap in record["gaps"]
        if gap["kind"] == "unavailable_source" and gap["subject"] not in NOT_ABOUT_SECURITY
    ]


def _unmatched_alerts(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Dependabot alerts the scan's advisories don't match.

    An alert is evidence of a vulnerability, but the scan compared no candidate with it, so
    whether one fixes it isn't known. A matched alert is already part of the vulnerability it
    matches.
    """
    section = record.get("dependabot_alerts")
    if section is None:
        return []
    described = (
        f"{section['ref']} at the scanned commit"
        if section["is_scanned_commit"]
        else f"{section['ref']} at {section['commit'][:7]}, not the scanned commit"
    )
    reports = []
    for alert in section["alerts"]:
        if alert["result"] != "unmatched":
            continue
        report = {
            "kind": NOT_EVALUATED,
            "reason": SECURITY,
            "alert": alert["number"],
            "advisory": alert["advisory"],
            "package": alert["package"],
            "manifest": alert["manifest"],
        }
        if "dependency" in alert:
            report["dependency"] = alert["dependency"]
        report["detail"] = (
            f"Dependabot alert {alert['number']} on {alert['package']} in "
            f"{alert['manifest'] or 'an unnamed manifest'} ({described}) matches none of the "
            "scan's advisories, so no candidate was compared with its fix."
        )
        reports.append(report)
    return reports


def _security_units(
    fixes: dict[str, _Fix], entries: dict[str, dict[str, Any]], today: date
) -> list[dict[str, Any]]:
    """One unit per package, covering each of its declarations with a fix, in any file."""
    packages: dict[tuple[str, str], list[str]] = {}
    for dep_id in fixes:
        packages.setdefault(_package(entries[dep_id]), []).append(dep_id)
    units = []
    for (ecosystem, _), dep_ids in packages.items():
        dep_ids.sort()
        name = entries[dep_ids[0]]["name"]
        units.append(
            {
                "name": f"security-{ecosystem}-{name}",
                "reasons": [SECURITY],
                "subject": {"ecosystem": ecosystem, "name": name},
                "targets": [_target(fixes[d].target, entries[d], today) for d in dep_ids],
                "evidence": {
                    "advisories": sorted(
                        (_advisory(v) for d in dep_ids for v in fixes[d].advisories),
                        key=lambda a: (a["dependency"], a["advisory"]),
                    )
                },
            }
        )
    return units


def _lifecycle_units(
    record: dict[str, Any],
    entries: dict[str, dict[str, Any]],
    candidates: dict[str, list[dict[str, Any]]],
    fixes: dict[str, _Fix],
    today: date,
    not_prepared: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """One unit per line nearing or past its end of life, covering its dependencies.

    Each dependency's target is its smallest in-scope candidate on another line that is still
    supported. One without such a candidate is an early warning, and the unit keeps the others.
    A dependency with a security fix brings it along: the unit carries both reasons, and the
    target must also reach every fix; without such a candidate the dependency is an early
    warning, and its fix stays a unit of its own (design decision 4). A dependency on several
    ending lines is in one unit, which carries all of them, and its target must leave each.
    A line whose state is unknown is reported as not evaluated.
    """
    ending = []
    for line in sorted(record["lifecycle"], key=lambda e: (e["product"], e["line"])):
        if line["state"] == "unknown":
            not_prepared.append(
                {
                    "kind": NOT_EVALUATED,
                    "reason": LIFECYCLE,
                    "product": line["product"],
                    "line": line["line"],
                    "dependencies": line["dependencies"],
                    "detail": line["reason"],
                }
            )
        elif line["state"] in ENDING:
            ending.append(line)
    on: dict[str, list[dict[str, Any]]] = {}
    for line in ending:
        for dep_id in line["dependencies"]:
            on.setdefault(dep_id, []).append(line)

    def home(lines: list[dict[str, Any]]) -> dict[str, Any]:
        # The line with the most dependencies, so that declarations that belong together,
        # such as everything that names the Go toolchain, stay in one unit.
        return min(lines, key=lambda e: (-len(e["dependencies"]), e["product"], e["line"]))

    units: list[dict[str, Any]] = []
    for line in ending:
        targets, advisories, carried = [], [], []
        for dep_id in line["dependencies"]:
            lines = on[dep_id]
            if home(lines) is not line:
                continue
            fix = fixes.get(dep_id)
            target, problem = _leaving(candidates.get(dep_id, []), entries[dep_id], lines, fix)
            if target is None:
                not_prepared.append({"reason": LIFECYCLE, "dependency": dep_id} | problem)
                continue
            if fix is not None:
                del fixes[dep_id]
                advisories += [_advisory(v) for v in fix.advisories]
            carried += [other for other in lines if other is not line and other not in carried]
            targets.append(_target(target, entries[dep_id], today))
        if not targets:
            continue
        carried.sort(key=lambda e: (e["product"], e["line"]))
        evidence: dict[str, Any] = {"lifecycle": [_line_evidence(e) for e in [line, *carried]]}
        if advisories:
            evidence["advisories"] = sorted(
                advisories, key=lambda a: (a["dependency"], a["advisory"])
            )
        units.append(
            {
                "name": f"lifecycle-{line['product']}-{line['line']}",
                "reasons": [LIFECYCLE, SECURITY] if advisories else [LIFECYCLE],
                "subject": {"product": line["product"], "line": line["line"]},
                "targets": sorted(targets, key=lambda t: t["dependency"]),
                "evidence": evidence,
            }
        )
    return units


def _leaving(
    candidates: list[dict[str, Any]],
    entry: dict[str, Any],
    lines: list[dict[str, Any]],
    fix: _Fix | None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """The smallest in-scope candidate on another supported line of each of the ending
    lines, which also reaches the fix when there is one, or else what to report instead."""
    about = [{"product": e["product"], "line": e["line"]} for e in lines]
    lookup = entry["lookup"]
    if lookup["state"] in ("unknown", "skipped"):
        return None, {
            "kind": NOT_EVALUATED,
            "lines": about,
            "detail": f"Whether a candidate leaves {_named_lines(lines)} is unknown: the lookup "
            f"of {entry['name']} is {lookup['state']}. {lookup['reason']}",
        }
    held, left = [], set()
    for candidate in sorted(candidates, key=_size):
        if candidate["update_type"] == "digest":
            continue
        found = [
            lifecycle.candidate_line(e["product"], e["line"], entry, candidate["version"])
            for e in lines
        ]
        leaves = [i for i, (e, on) in enumerate(zip(lines, found, strict=True)) if on in _others(e)]
        if candidate["classification"] != "in_scope":
            if len(leaves) == len(lines):
                held.append(candidate)
            continue
        left |= set(leaves)
        if fix is not None and candidate["version"] not in fix.versions:
            continue
        if None in found:
            # This candidate might be the target, so a line that can't be read stops here.
            unread = _named_lines([e for e, on in zip(lines, found, strict=True) if on is None])
            return None, {
                "kind": NOT_EVALUATED,
                "lines": about,
                "detail": f"The {unread} line of candidate {candidate['version']} can't be "
                "read from the record.",
            }
        if len(leaves) == len(lines):
            return candidate, {}

    stuck = [e for i, e in enumerate(lines) if i not in left]
    if stuck:
        detail = "No in-scope candidate is on another supported line of " + " or ".join(
            f"{e['product']} {e['line']} ({', '.join(_others(e)) or 'none'})" for e in stuck
        )
        about = [{"product": e["product"], "line": e["line"]} for e in stuck]
    elif len(lines) > 1:
        detail = f"No single in-scope candidate leaves {_named_lines(lines)} at once"
    else:
        detail = (
            f"No in-scope candidate both leaves {_named_lines(lines)} and reaches the fix of "
            "every advisory on it, so its security fix is a unit of its own"
        )
    problem: dict[str, Any] = {"kind": EARLY_WARNING, "lines": about, "detail": detail + "."}
    if held:
        rules = sorted({c["held_by"] for c in held})
        problem["held_by"] = "; ".join(rules)
        versions = ", ".join(c["version"] for c in held)
        them = "it" if len(held) == 1 else "them"
        problem["detail"] += f" {versions} would, but the policy holds {them}: {'; '.join(rules)}."
    return None, problem


def _others(line: dict[str, Any]) -> list[str]:
    """The supported lines a dependency on this one can move to."""
    return [s for s in line.get("supported_lines", []) if s != line["line"]]


def _named_lines(lines: list[dict[str, Any]]) -> str:
    return " and ".join(f"{e['product']} {e['line']}" for e in lines)


def _line_evidence(line: dict[str, Any]) -> dict[str, Any]:
    keys = ("product", "line", "state", "end_of_life", "supported_lines", "source")
    return {k: line[k] for k in keys if k in line}


def _batch_units(
    entries: dict[str, dict[str, Any]],
    candidates: dict[str, list[dict[str, Any]]],
    in_units: set[str],
    today: date,
    not_prepared: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Inside the batch window, every other dependency's newest in-scope candidate, if it is
    old enough, in units by the group the scan recorded for it.

    A candidate without a release date counts as old enough, and its age is unknown. One that
    is too young waits for the next window, even when an older candidate would be old enough
    (design decision 5). The updates of a package in no group form one unit across files.
    """
    window = batch_window(today)
    if not window["open"]:
        return []
    batched: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for dep_id in sorted(candidates):
        if dep_id in in_units:
            continue
        in_scope = [c for c in candidates[dep_id] if c["classification"] == "in_scope"]
        if not in_scope:
            continue
        newest = max(in_scope, key=_size)
        age = _age(newest, today)
        if age is not None and age < MINIMUM_RELEASE_AGE_DAYS:
            ready = datetime.fromisoformat(newest["released_at"]).astimezone(UTC).date()
            ready += timedelta(days=MINIMUM_RELEASE_AGE_DAYS)
            not_prepared.append(
                {
                    "kind": WAITING,
                    "reason": BATCH,
                    "dependency": dep_id,
                    "version": newest["version"],
                    "update_type": newest["update_type"],
                    "released_at": newest["released_at"],
                    "age_days": age,
                    "old_enough_on": ready.isoformat(),
                    "detail": f"{newest['version']} is {age} days old, younger than "
                    f"{MINIMUM_RELEASE_AGE_DAYS}, so it waits for the next window, which opens "
                    f"on {window['next_opens']}.",
                }
            )
            continue
        entry = entries[dep_id]
        key = ("group", newest["group"]) if "group" in newest else ("package", *_package(entry))
        batched.setdefault(key, []).append(_target(newest, entry, today))

    units = []
    for key, batch in batched.items():
        if key[0] == "group":
            name, subject = key[1], {"group": key[1]}
        else:
            entry = entries[batch[0]["dependency"]]
            name = f"{entry['ecosystem']}-{entry['name']}"
            subject = {"ecosystem": entry["ecosystem"], "name": entry["name"]}
        units.append(
            {
                "name": name,
                "reasons": [BATCH],
                "subject": subject,
                "targets": batch,
                "evidence": {
                    "batch_window": {
                        "first_day": BATCH_WINDOW_FIRST_DAY,
                        "last_day": BATCH_WINDOW_LAST_DAY,
                    },
                    "minimum_release_age_days": MINIMUM_RELEASE_AGE_DAYS,
                },
            }
        )
    return units


def _named(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each unit with a name safe for a branch, and its breaking mark.

    A name comes only from the unit's reason and its group, package or line, never from its
    targets, so the same unit keeps its name across scans. Two units whose names end up the
    same once made safe, such as a group named after a package, both get a suffix from
    their own reason and subject, and are marked as such, rather than one taking the other's
    name.
    """
    names: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        names.setdefault(branch_name(unit["name"]), []).append(unit)
    named = []
    for name, same in names.items():
        for unit in same:
            finished = {"name": name, "reasons": unit["reasons"], "subject": unit["subject"]}
            if len(same) > 1:
                identity = json.dumps([unit["reasons"][0], unit["subject"]], sort_keys=True)
                finished["name"] = branch_name(f"{unit['name']}-{_digest(identity)}")
                finished["name_collision"] = True
            # A lifecycle move changes the platform under the code, whatever its update type.
            finished["breaking"] = LIFECYCLE in unit["reasons"] or any(
                t["update_type"] == "major" for t in unit["targets"]
            )
            named.append(finished | {"targets": unit["targets"], "evidence": unit["evidence"]})
    return named


def branch_name(text: str) -> str:
    """The text made safe for a git branch name, as one path component.

    Lower case, with every run of characters outside `a-z 0-9 . _ -` and every run of
    separators made one `-`, so there is no `..`; no separator at either end, so it can't
    start like an option or a hidden file; no `.lock` at the end, which git refuses; and at
    most NAME_LENGTH characters, a longer one ending in a digest of the whole text so that
    it stays distinct.
    """
    name = re.sub(r"[^a-z0-9._-]+", "-", text.lower())
    name = re.sub(r"[._-]{2,}", "-", name).strip("._-")
    if name.endswith(".lock"):
        name = name.removesuffix(".lock") + "-lock"
    if len(name) > NAME_LENGTH or not name:
        name = f"{name[: NAME_LENGTH - 9].rstrip('._-')}-{_digest(text)}".lstrip("-")
    return name


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:8]


def _package(entry: dict[str, Any]) -> tuple[str, str]:
    """A package across files: its ecosystem and name. NuGet ids ignore case."""
    name = entry["name"]
    return entry["ecosystem"], name.casefold() if entry["ecosystem"] == "nuget" else name


def _target(candidate: dict[str, Any], entry: dict[str, Any], today: date) -> dict[str, Any]:
    """A unit's target: the declaration, the candidate it moves to, and how old that is."""
    target = {
        "dependency": entry["id"],
        "current": entry["current"],
        "version": candidate["version"],
        "update_type": candidate["update_type"],
    }
    age = _age(candidate, today)
    if age is not None:
        target["released_at"] = candidate["released_at"]
    target["age_days"] = "unknown" if age is None else age
    return target


def _age(candidate: dict[str, Any], today: date) -> int | None:
    """Whole days from the candidate's release to the scan's date; None when the source
    published no date. Negative for a date after the scan's, which upstream data can claim."""
    if "released_at" not in candidate:
        return None
    released = datetime.fromisoformat(candidate["released_at"]).astimezone(UTC).date()
    return (today - released).days


def _advisory(vulnerability: dict[str, Any]) -> dict[str, Any]:
    """An advisory as a unit's evidence."""
    keys = (
        "advisory",
        "aliases",
        "dependency",
        "fixed_version",
        "last_affected",
        "reachability",
        "source",
        "dependabot_alerts",
    )
    return {k: vulnerability[k] for k in keys if k in vulnerability}


def _size(candidate: dict[str, Any]) -> tuple:
    """Smaller update types first; within one, the lower version."""
    version = osv.version_order(candidate["version"])
    return SIZES.index(candidate["update_type"]), version is not None, version or ()


def _report_order(report: dict[str, Any]) -> tuple:
    return (
        KINDS.index(report["kind"]),
        REASONS.index(report["reason"]),
        report.get("dependency", ""),
        report.get("advisory", ""),
        json.dumps(report, sort_keys=True),
    )
