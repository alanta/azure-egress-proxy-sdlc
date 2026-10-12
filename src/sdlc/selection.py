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
"""

from datetime import date
from typing import Any

from sdlc.policy import Policy

# The batch window: these days of every month, inclusive.
BATCH_WINDOW_FIRST_DAY = 1
BATCH_WINDOW_LAST_DAY = 7
# How old a batch update's release must be, in days, on the scan's date.
MINIMUM_RELEASE_AGE_DAYS = 7


class SelectionError(Exception):
    """The inputs don't belong together, so no selection can be made from them."""


def select(record: dict[str, Any], policy: Policy, today: date) -> dict[str, Any]:
    """The units to prepare for the scanned revision, and what can't be prepared.

    The policy's holds and groups are read from the record, where the scan recorded them per
    candidate, so the policy is only checked to be the one the record names.
    """
    if policy.source != record["policy"]:
        raise SelectionError(
            f"the record was classified with policy {record['policy']}, not {policy.source}"
        )
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
        "units": [],
        "not_prepared": [],
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
