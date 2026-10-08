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
    for path, dep_id in references:
        if dep_id not in lookup_state:
            problems.append(f"{path}: unknown dependency id {dep_id!r}")

    with_candidates = {c["dependency"] for c in record["candidates"]}
    for dep_id, state in lookup_state.items():
        if state == "outdated" and dep_id not in with_candidates:
            problems.append(f"$.inventory: {dep_id!r} is outdated but has no candidates")
        if state != "outdated" and dep_id in with_candidates:
            problems.append(f"$.candidates: {dep_id!r} has candidates but its lookup is {state!r}")

    pull_requests = record["parity"]["pull_requests"]
    if any(pr["state"] == "unparseable" for pr in pull_requests) and record["parity"]["complete"]:
        problems.append("$.parity.complete: true although a pull request is unparseable")

    return problems
