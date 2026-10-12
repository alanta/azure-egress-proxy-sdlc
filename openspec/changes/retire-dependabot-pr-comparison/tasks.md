# Tasks

## 1. Record schema

- [x] 1.1 Add `scan-record.v2.json`: version 1 without `parity` and its definitions, with `schema_version` 2. Leave `scan-record.v1.json` unchanged. Verify that the version 2 tests accept a valid record and reject one that still has `parity`, and that the version 1 tests still pass against the records they used before.

## 2. Remove the comparison

- [x] 2.1 Remove the comparison from the scan: `parity.py`, `pr_diff.py`, `dependabot_prs.py`, their calls in `cli.py`, the `parity` section and the `dependabot-prs` source in `record.py`, and the parity sections in `report.py`. The scan now writes version 2 records. Verify that `uv run pytest` and `uv run ruff check` pass, and that `grep -rn "parity\|dependabot_prs\|pr_diff" src` finds nothing.
- [x] 2.2 Remove `tests/test_parity.py`, `tests/test_dependabot_prs.py` and the parity parts of the other tests and of `tests/fixtures/records/valid.json`. Remove the captured PRs in `fixtures/azure-egress-proxy/prs` apart from #76's diff, which `tests/test_consistency.py` uses, and update that directory's README and manifest to match. Verify that `uv run pytest` passes, and that no test or fixture refers to a removed PR.

## 3. Documentation

- [x] 3.1 Update `docs/running-a-scan.md` and `docs/scan-coverage.md` so that they no longer describe the comparison with PRs, and drop `Pull requests: read` from the scan's permissions. Label `docs/end-to-end-run.md` as describing a version 1 record. Verify with `grep -n -i "parity\|Dependabot PR" docs/running-a-scan.md docs/scan-coverage.md` that only the Dependabot alerts are left.

## 4. End-to-end check

- [ ] 4.1 Run a scan of the subject's `main` with the trial policy. Verify that the record validates against version 2, and that the report has no parity section, but still has the Dependabot alerts.
