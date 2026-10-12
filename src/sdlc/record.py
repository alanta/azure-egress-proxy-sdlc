"""The scan record: its JSON Schema and the checks a schema can't express."""

import json
from datetime import UTC, datetime
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_VERSION = "3"


@cache
def schema(version: str = SCHEMA_VERSION) -> dict[str, Any]:
    text = files("sdlc").joinpath(f"schemas/scan-record.v{version}.json").read_text()
    return json.loads(text)


def validate_record(record: Any, version: str = SCHEMA_VERSION) -> list[str]:
    """Return every problem with a scan record; an empty list means it is valid.

    A version 1 record is checked against its own schema, but its `parity` section, which no
    scan writes any more, gets no checks beyond that schema.
    """
    validator = Draft202012Validator(
        schema(version), format_checker=Draft202012Validator.FORMAT_CHECKER
    )
    problems = [
        f"{error.json_path}: {error.message}"
        for error in sorted(validator.iter_errors(record), key=lambda e: e.json_path)
    ]
    if problems:
        return problems
    return _consistency_problems(record)


def _consistency_problems(record: dict[str, Any]) -> list[str]:
    problems = []

    # jsonschema only checks date-time when an optional package is installed; check here.
    timestamps = [("$.scanned_at", record["scanned_at"])]
    timestamps += [
        (f"$.inventory[{i}].lookup.looked_up_at", d["lookup"]["looked_up_at"])
        for i, d in enumerate(record["inventory"])
        if "looked_up_at" in d["lookup"]
    ]
    timestamps += [
        (f"$.tools[{i}].fetched_at", t["fetched_at"])
        for i, t in enumerate(record["tools"])
        if "fetched_at" in t
    ]
    timestamps += [
        (f"$.candidates[{i}].released_at", c["released_at"])
        for i, c in enumerate(record["candidates"])
        if "released_at" in c
    ]
    selection = record.get("selection", {"units": [], "not_prepared": []})  # none before 3
    timestamps += [
        (f"$.selection.units[{i}].targets[{j}].released_at", t["released_at"])
        for i, unit in enumerate(selection["units"])
        for j, t in enumerate(unit["targets"])
        if "released_at" in t
    ]
    timestamps += [
        (f"$.selection.not_prepared[{i}].released_at", r["released_at"])
        for i, r in enumerate(selection["not_prepared"])
        if "released_at" in r
    ]
    if "dependabot_alerts" in record:
        timestamps.append(("$.dependabot_alerts.read_at", record["dependabot_alerts"]["read_at"]))
    for path, value in timestamps:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            problems.append(f"{path}: {value!r} is not an ISO 8601 timestamp")
            continue
        if parsed.tzinfo is None:
            problems.append(f"{path}: {value!r} has no time zone")

    ids = [d["id"] for d in record["inventory"]]
    seen: set[str] = set()
    for dep_id in ids:
        if dep_id in seen:
            problems.append(f"$.inventory: duplicate dependency id {dep_id!r}")
        seen.add(dep_id)

    lookup_state = {d["id"]: d["lookup"]["state"] for d in record["inventory"]}
    references = [
        (f"$.candidates[{i}].dependency", c["dependency"])
        for i, c in enumerate(record["candidates"])
    ]
    references += [
        (f"$.vulnerabilities[{i}].dependency", v["dependency"])
        for i, v in enumerate(record["vulnerabilities"])
    ]
    alerts = record.get("dependabot_alerts", {}).get("alerts", [])
    references += [
        (f"$.dependabot_alerts.alerts[{i}].dependency", a["dependency"])
        for i, a in enumerate(alerts)
        if "dependency" in a
    ]
    references += [
        (f"$.consistency[{i}].compared[{j}]", dep_id)
        for i, alias in enumerate(record["consistency"])
        for j, dep_id in enumerate(alias["compared"])
    ]
    for path, dep_id in references:
        if dep_id not in lookup_state:
            problems.append(f"{path}: unknown dependency id {dep_id!r}")

    with_candidates = {c["dependency"] for c in record["candidates"]}
    for dep_id, state in lookup_state.items():
        if state == "outdated" and dep_id not in with_candidates:
            problems.append(f"$.inventory: {dep_id!r} is outdated but has no candidates")
        if state != "outdated" and dep_id in with_candidates:
            problems.append(f"$.candidates: {dep_id!r} has candidates but its lookup is {state!r}")

    problems += _advisory_fix_problems(record)
    problems += _reached_by_problems(record)
    problems += _alert_problems(record)
    problems += _inconsistency_problems(record)
    problems += _lifecycle_problems(record)
    problems += _selection_problems(record)

    return problems


def _advisory_fix_problems(record: dict[str, Any]) -> list[str]:
    """A candidate taken from an advisory is a fixed version of one; an entry nobody looked up
    has only such candidates."""
    problems = []
    fixed = {
        (v["dependency"], v["fixed_version"])
        for v in record["vulnerabilities"]
        if v["fixed_version"] is not None
    }
    from_advisory = {
        d["id"] for d in record["inventory"] if d["lookup"].get("basis") == "advisory_fix"
    }
    for i, c in enumerate(record["candidates"]):
        path = f"$.candidates[{i}]"
        if c.get("basis") == "advisory_fix":
            if (c["dependency"], c["version"]) not in fixed:
                problems.append(
                    f"{path}: no advisory on {c['dependency']!r} names {c['version']!r} as fixed"
                )
        elif c["dependency"] in from_advisory:
            problems.append(
                f"{path}: {c['dependency']!r} wasn't looked up, so its candidates come from "
                "advisories, yet this one doesn't say so"
            )
    return problems


def _reached_by_problems(record: dict[str, Any]) -> list[str]:
    """The candidates said to reach a fix are in-scope candidates of the same dependency."""
    in_scope = {
        (c["dependency"], c["version"])
        for c in record["candidates"]
        if c["classification"] == "in_scope" and c["update_type"] != "digest"
    }
    return [
        f"$.vulnerabilities[{i}].fix_reached_by: {version!r} isn't an in-scope candidate of "
        f"{v['dependency']!r}"
        for i, v in enumerate(record["vulnerabilities"])
        for version in v.get("fix_reached_by", [])
        if (v["dependency"], version) not in in_scope
    ]


def _inconsistency_problems(record: dict[str, Any]) -> list[str]:
    """A flagged alias lists what was compared for it, each where its inventory entry is."""
    problems = []
    compared = {a["dependency"]: a["compared"] for a in record["consistency"]}
    files = {d["id"]: d["location"]["file"] for d in record["inventory"]}
    for i, inconsistency in enumerate(record["inconsistencies"]):
        path = f"$.inconsistencies[{i}]"
        ids = [d["dependency"] for d in inconsistency["declarations"]]
        if compared.get(inconsistency["dependency"]) != ids:
            problems.append(f"{path}: its declarations aren't what $.consistency compared")
        for j, d in enumerate(inconsistency["declarations"]):
            dep_id = d["dependency"]
            if dep_id not in files:
                problems.append(f"{path}.declarations[{j}]: unknown dependency id {dep_id!r}")
            elif d["location"]["file"] != files[dep_id]:
                problems.append(f"{path}.declarations[{j}].location: not the file of {dep_id!r}")
    return problems


def _lifecycle_problems(record: dict[str, Any]) -> list[str]:
    """Each line lists its inventory entries with their locations, in the same order."""
    problems = []
    entries = {d["id"]: d for d in record["inventory"]}
    for i, line in enumerate(record["lifecycle"]):
        path = f"$.lifecycle[{i}]"
        if len(line["dependencies"]) != len(line["locations"]):
            problems.append(f"{path}: its dependencies and locations don't pair up")
        for j, (dep_id, location) in enumerate(
            zip(line["dependencies"], line["locations"], strict=False)
        ):
            if dep_id not in entries:
                problems.append(f"{path}.dependencies[{j}]: unknown dependency id {dep_id!r}")
            elif location != entries[dep_id]["location"]:
                problems.append(f"{path}.locations[{j}]: not the location of {dep_id!r}")
    return problems


def _selection_problems(record: dict[str, Any]) -> list[str]:
    """The selection only names dependencies of the inventory and in-scope candidates of them,
    on the scan's own date, and gives every unit a name of its own."""
    selection = record.get("selection")
    if selection is None:  # versions 1 and 2 have none
        return []
    problems = []
    entries = {d["id"]: d for d in record["inventory"]}
    in_scope = {
        (c["dependency"], c["version"]): c["update_type"]
        for c in record["candidates"]
        if c["classification"] == "in_scope"
    }
    try:
        scanned = datetime.fromisoformat(record["scanned_at"]).astimezone(UTC).date().isoformat()
    except ValueError:
        scanned = None  # reported with the timestamps
    if scanned is not None and selection["date"] != scanned:
        problems.append(f"$.selection.date: {selection['date']!r} isn't the scan's date {scanned}")

    names: set[str] = set()
    for i, unit in enumerate(selection["units"]):
        path = f"$.selection.units[{i}]"
        if unit["name"] in names:
            problems.append(f"{path}.name: duplicate unit name {unit['name']!r}")
        names.add(unit["name"])
        for j, target in enumerate(unit["targets"]):
            where = f"{path}.targets[{j}]"
            dep_id = target["dependency"]
            if dep_id not in entries:
                problems.append(f"{where}.dependency: unknown dependency id {dep_id!r}")
                continue
            if target["current"] != entries[dep_id]["current"]:
                problems.append(f"{where}.current: not the current version of {dep_id!r}")
            update_type = in_scope.get((dep_id, target["version"]))
            if update_type is None:
                problems.append(
                    f"{where}.version: {target['version']!r} isn't an in-scope candidate of "
                    f"{dep_id!r}"
                )
            elif update_type != target["update_type"]:
                problems.append(f"{where}.update_type: not the update type of the candidate")
        problems += _open_report_problems(unit, path, selection["not_prepared"])
        for j, advisory in enumerate(unit["evidence"].get("advisories", [])):
            if advisory["dependency"] not in entries:
                problems.append(
                    f"{path}.evidence.advisories[{j}].dependency: unknown dependency id "
                    f"{advisory['dependency']!r}"
                )

    for i, report in enumerate(selection["not_prepared"]):
        for dep_id in [report.get("dependency"), *report.get("dependencies", [])]:
            if dep_id is not None and dep_id not in entries:
                problems.append(f"$.selection.not_prepared[{i}]: unknown dependency id {dep_id!r}")
    return problems


def _open_report_problems(
    unit: dict[str, Any], path: str, not_prepared: list[dict[str, Any]]
) -> list[str]:
    """A batch unit names exactly the open security reports of its dependencies."""
    if "batch" not in unit["reasons"]:
        return []
    batched = {t["dependency"] for t in unit["targets"]}
    named = unit["evidence"].get("open_security_reports", [])
    problems = [
        f"{path}.evidence.open_security_reports[{j}]: no security report in not_prepared is "
        "about a dependency of the unit and says this"
        for j, reference in enumerate(named)
        if reference["dependency"] not in batched
        or not any(
            r["reason"] == "security" and all(r.get(k) == v for k, v in reference.items())
            for r in not_prepared
        )
    ]
    for i, report in enumerate(not_prepared):
        if report["reason"] != "security" or report.get("dependency") not in batched:
            continue
        if not any(all(report.get(k) == v for k, v in ref.items()) for ref in named):
            problems.append(
                f"{path}.evidence.open_security_reports: doesn't name $.selection."
                f"not_prepared[{i}] about {report['dependency']!r}"
            )
    return problems


def _alert_problems(record: dict[str, Any]) -> list[str]:
    """The alerts are either read or a gap says why not; matches point both ways."""
    problems = []
    unread = any(
        g["kind"] == "unavailable_source" and g["subject"] == "dependabot-alerts"
        for g in record["gaps"]
    )
    section = record.get("dependabot_alerts")
    if section is None and not unread:
        problems.append("$.dependabot_alerts: missing, and no gap says why the alerts weren't read")
    if section is not None and unread:
        problems.append("$.dependabot_alerts: present, but a gap says the alerts weren't read")

    if section is not None and section["is_scanned_commit"] != (
        section["commit"] == record["subject"]["commit"]
    ):
        problems.append("$.dependabot_alerts.is_scanned_commit: disagrees with the commits")

    results: dict[int, str] = {}
    for i, a in enumerate((section or {}).get("alerts", [])):
        if a["number"] in results:
            problems.append(f"$.dependabot_alerts.alerts[{i}]: duplicate alert {a['number']}")
        results[a["number"]] = a["result"]
    matched = ("matched", "matched_elsewhere")
    cited: set[int] = set()
    for i, v in enumerate(record["vulnerabilities"]):
        for number in v.get("dependabot_alerts", []):
            cited.add(number)
            if results.get(number) not in matched:
                problems.append(
                    f"$.vulnerabilities[{i}].dependabot_alerts: alert {number} isn't matched"
                )
    for number, result in results.items():
        if result in matched and number not in cited:
            problems.append(
                f"$.dependabot_alerts: alert {number} is matched but no vulnerability lists it"
            )
    return problems
