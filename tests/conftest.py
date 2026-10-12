"""Shared test helpers."""

import pytest

AT = "2026-10-08T09:00:00+00:00"


@pytest.fixture
def record_from():
    """Wrap inventory entries and candidates in an otherwise empty, valid scan record."""

    def as_record(inventory):
        return {
            "schema_version": "3",
            "subject": {
                "repository": "alanta/azure-egress-proxy",
                "ref": "main",
                "commit": "064aa099ecf7ffea9664b89df29f7d89d6859358",
            },
            "scanned_at": AT,
            "tools": [{"name": "renovate", "version": "44.145.1"}],
            "policy": {"source": "none"},
            "inventory": inventory.dependencies,
            "candidates": inventory.candidates,
            "vulnerabilities": [],
            "lifecycle": [],
            "consistency": [],
            "inconsistencies": [],
            "cross_checks": [],
            # Nothing is selected here: the tests that use this don't look at the selection.
            "selection": {
                "date": "2026-10-08",
                "defaults": {
                    "batch_window": {"first_day": 1, "last_day": 7},
                    "minimum_release_age_days": 7,
                },
                "batch_window": {"open": False, "next_opens": "2026-11-01"},
                "units": [],
                "not_prepared": [],
            },
            # A record either has the alerts or says why it doesn't.
            "gaps": [
                {
                    "kind": "unavailable_source",
                    "subject": "dependabot-alerts",
                    "reason": "Not read in this test.",
                }
            ],
        }

    return as_record
