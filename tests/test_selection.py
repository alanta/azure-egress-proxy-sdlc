import copy
import json
from datetime import date

import pytest

from sdlc.policy import NO_POLICY, Policy
from sdlc.selection import SelectionError, batch_window, select

TRIAL = Policy({"source": "trial", "path": "policies/trial.renovate.json5"}, "{}", "{}")
# A day outside the batch window, and one inside it.
OUTSIDE = date(2026, 10, 15)
INSIDE = date(2026, 11, 3)


class Record:
    """A scan record built up by hand, with only what the selection reads."""

    def __init__(self, policy: Policy = TRIAL):
        self.record = {
            "schema_version": "3",
            "scanned_at": "2026-10-15T09:00:00+00:00",
            "policy": policy.source,
            "inventory": [],
            "candidates": [],
            "vulnerabilities": [],
            "lifecycle": [],
            "gaps": [],
        }

    def dependency(
        self, dep_id, current, *, ecosystem="nuget", name=None, state="outdated", **lookup
    ):
        name = name or dep_id.rsplit(":", 1)[-1]
        self.record["inventory"].append(
            {
                "id": dep_id,
                "ecosystem": ecosystem,
                "name": name,
                "current": current,
                "origin": "declared",
                "location": {"file": dep_id.split(":")[1]},
                "lookup": {"state": state, **lookup},
            }
        )
        return self

    def candidate(self, dep_id, update_type, version, *, held_by=None, **fields):
        candidate = {"dependency": dep_id, "update_type": update_type, "version": version}
        if held_by:
            candidate |= {"classification": "held_by_policy", "held_by": held_by}
        else:
            candidate["classification"] = "in_scope"
        self.record["candidates"].append(candidate | fields)
        return self

    def vulnerability(self, dep_id, advisory, fixed, *, reached=True, **fields):
        affected = next(d["current"] for d in self.record["inventory"] if d["id"] == dep_id)
        vulnerability = {
            "advisory": advisory,
            "dependency": dep_id,
            "affected_version": affected,
            "fixed_version": fixed,
        }
        if fixed is not None or "last_affected" in fields:
            vulnerability["fix_reached_by_candidate"] = reached
        vulnerability |= {"source": "osv", "reachability": "unknown"} | fields
        self.record["vulnerabilities"].append(vulnerability)
        return self

    def lifecycle(self, product, line, state, dependencies, **fields):
        locations = [
            next(d["location"] for d in self.record["inventory"] if d["id"] == dep_id)
            for dep_id in dependencies
        ]
        self.record["lifecycle"].append(
            {"product": product, "line": line, "state": state}
            | fields
            | {"dependencies": list(dependencies), "locations": locations}
        )
        return self

    def select(self, today=OUTSIDE, policy=TRIAL):
        return select(copy.deepcopy(self.record), policy, today)


def test_the_same_scan_is_selected_the_same_way_twice():
    record = (
        Record()
        .dependency("nuget:Directory.Packages.props:Azure.Core", "1.62.0")
        .candidate("nuget:Directory.Packages.props:Azure.Core", "minor", "1.63.0")
    )
    first = record.select(INSIDE)
    assert record.select(INSIDE) == first
    # The selection goes into the record as it is.
    assert json.loads(json.dumps(first)) == first


def test_the_defaults_and_the_window_are_part_of_the_selection():
    selection = Record().select(OUTSIDE)
    assert selection["date"] == "2026-10-15"
    assert selection["defaults"] == {
        "batch_window": {"first_day": 1, "last_day": 7},
        "minimum_release_age_days": 7,
    }
    assert selection["batch_window"] == {"open": False, "next_opens": "2026-11-01"}
    assert selection["units"] == [] and selection["not_prepared"] == []


@pytest.mark.parametrize(
    ("today", "is_open", "next_opens"),
    [
        (date(2026, 11, 1), True, "2026-12-01"),
        (date(2026, 11, 7), True, "2026-12-01"),
        (date(2026, 11, 8), False, "2026-12-01"),
        (date(2026, 12, 31), False, "2027-01-01"),
    ],
)
def test_the_batch_window_is_the_first_seven_days_of_the_month(today, is_open, next_opens):
    assert batch_window(today) == {"open": is_open, "next_opens": next_opens}


def test_a_record_classified_with_another_policy_is_refused():
    with pytest.raises(SelectionError, match="classified with policy"):
        Record(TRIAL).select(policy=NO_POLICY)
