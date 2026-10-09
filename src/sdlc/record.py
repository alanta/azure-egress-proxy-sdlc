"""The scan record: its JSON Schema and the checks a schema can't express."""

import json
from datetime import datetime
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_VERSION = "1"


@cache
def schema() -> dict[str, Any]:
    text = files("sdlc").joinpath(f"schemas/scan-record.v{SCHEMA_VERSION}.json").read_text()
    return json.loads(text)


def validate_record(record: Any) -> list[str]:
    """Return every problem with a scan record; an empty list means it is valid."""
    validator = Draft202012Validator(schema(), format_checker=Draft202012Validator.FORMAT_CHECKER)
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
    if "captured_at" in record["parity"]:
        timestamps.append(("$.parity.captured_at", record["parity"]["captured_at"]))
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
    references += [
        (f"$.parity.scan_only[{i}]", dep_id)
        for i, dep_id in enumerate(record["parity"]["scan_only"])
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

    problems += _alert_problems(record)
    problems += _inconsistency_problems(record)

    pull_requests = record["parity"]["pull_requests"]
    if any(pr["state"] == "unparseable" for pr in pull_requests) and record["parity"]["complete"]:
        problems.append("$.parity.complete: true although a pull request is unparseable")

    return problems


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
