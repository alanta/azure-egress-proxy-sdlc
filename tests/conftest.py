"""Shared test helpers."""

import pytest

AT = "2026-10-08T09:00:00+00:00"


@pytest.fixture
def record_from():
    """Wrap inventory entries and candidates in an otherwise empty, valid scan record."""

    def as_record(inventory):
        return {
            "schema_version": "1",
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
            "parity": {
                "baseline": "dependabot",
                "complete": True,
                "pull_requests": [],
                "scan_only": [],
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
