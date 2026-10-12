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

import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from sdlc import dependabot, osv
from sdlc.policy import Policy

# The batch window: these days of every month, inclusive.
BATCH_WINDOW_FIRST_DAY = 1
BATCH_WINDOW_LAST_DAY = 7
# How old a batch update's release must be, in days, on the scan's date.
MINIMUM_RELEASE_AGE_DAYS = 7

SECURITY = "security"
REASONS = (SECURITY,)

# What the selection reports instead of a unit, in the order it reports them.
FIX_HELD = "fix_held"  # vulnerable, but only candidates the policy holds reach the fix
NO_ROUTE = "no_route"  # no fixed version, or no candidate reaches it
NOT_EVALUATED = "not_evaluated"  # data the decision needs is missing
KINDS = (FIX_HELD, NO_ROUTE, NOT_EVALUATED)

# Update types from smallest to largest. A digest only re-pins the same version, so it never
# reaches a fix (the scan doesn't judge digests against advisories either).
SIZES = ("digest", "patch", "minor", "major")

# The sources of security reasons: when one couldn't be read, its reasons aren't evaluated.
SECURITY_SOURCES = ("osv-scanner", dependabot.SUBJECT)
GOVULNCHECK = "govulncheck: "


class SelectionError(Exception):
    """The inputs don't belong together, so no selection can be made from them."""


@dataclass
class _Fix:
    """A declaration's security fix: its target and the advisories the target resolves."""

    target: dict[str, Any]
    advisories: list[dict[str, Any]] = field(default_factory=list)


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
    units = _security_units(fixes, entries, today)

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
    """Per vulnerable declaration, the in-scope candidate that fixes all its advisories that
    one can fix; every other advisory, and every unread source, is reported.

    The scan has already compared each advisory with the candidates: `fix_reached_by_candidate`
    says whether an in-scope one is outside it (design decision 3). Which one is the smallest
    is found by the scan's own version order, against the fixed version or the last affected
    one: the advisory's ranges themselves aren't in the record.
    """
    fixes: dict[str, _Fix] = {}
    for vulnerability in record["vulnerabilities"]:
        dep_id = vulnerability["dependency"]
        entry = entries[dep_id]
        report = {
            "reason": SECURITY,
            "dependency": dep_id,
            "advisory": vulnerability["advisory"],
        }
        fixed = vulnerability["fixed_version"]
        last_affected = vulnerability.get("last_affected")
        if fixed is None and last_affected is None:
            not_prepared.append(
                report | {"kind": NO_ROUTE, "detail": "The advisory names no fixed version."}
            )
            continue
        fix = f"the fixed version {fixed}" if fixed else f"a version above {last_affected}"
        reached = vulnerability["fix_reached_by_candidate"]
        if reached == "unknown":
            not_prepared.append(report | {"kind": NOT_EVALUATED, "detail": _unknown(entry, fix)})
            continue
        if reached is False:
            if "fix_held_by" in vulnerability:
                not_prepared.append(
                    report
                    | {
                        "kind": FIX_HELD,
                        "held_by": vulnerability["fix_held_by"],
                        "detail": f"Vulnerable, fix held by policy: only candidates that rule "
                        f"holds reach {fix}.",
                    }
                )
            else:
                not_prepared.append(
                    report | {"kind": NO_ROUTE, "detail": f"No candidate reaches {fix}."}
                )
            continue
        target = _smallest_past(candidates.get(dep_id, []), fixed, last_affected)
        if target is None:
            not_prepared.append(
                report
                | {
                    "kind": NOT_EVALUATED,
                    "detail": f"The scan found an in-scope candidate outside the advisory, but "
                    f"no candidate's version compares as reaching {fix}.",
                }
            )
            continue
        found = fixes.setdefault(dep_id, _Fix(target))
        # One update fixes them all: the highest of the advisories' targets.
        found.target = max(found.target, target, key=_size)
        found.advisories.append(vulnerability)

    not_prepared += _unread_sources(record)
    not_prepared += _unmatched_alerts(record)
    return fixes


def _unknown(entry: dict[str, Any], fix: str) -> str:
    """Why the scan couldn't tell whether a candidate reaches the fix."""
    lookup = entry["lookup"]
    if lookup["state"] in ("unknown", "skipped"):
        return (
            f"Whether a candidate reaches {fix} is unknown: the lookup of "
            f"{entry['name']} is {lookup['state']}. {lookup['reason']}"
        )
    return (
        f"Whether a candidate reaches {fix} is unknown: the scan couldn't evaluate the "
        "advisory's ranges for its candidates."
    )


def _smallest_past(
    candidates: list[dict[str, Any]], fixed: str | None, last_affected: str | None
) -> dict[str, Any] | None:
    """The in-scope candidate of the smallest update type at or past the fix, if any."""
    bound = osv.version_order(fixed or last_affected or "")
    if bound is None:
        return None
    for candidate in sorted(candidates, key=_size):
        if candidate["classification"] != "in_scope" or candidate["update_type"] == "digest":
            continue
        version = osv.version_order(candidate["version"])
        if version is None:
            continue
        if (fixed and version >= bound) or (not fixed and version > bound):
            return candidate
    return None


def _unread_sources(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The security sources the scan couldn't read: what they would say isn't evaluated."""
    return [
        {
            "kind": NOT_EVALUATED,
            "reason": SECURITY,
            "source": gap["subject"],
            "detail": gap["reason"],
        }
        for gap in record["gaps"]
        if gap["kind"] == "unavailable_source"
        and (gap["subject"] in SECURITY_SOURCES or gap["subject"].startswith(GOVULNCHECK))
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
