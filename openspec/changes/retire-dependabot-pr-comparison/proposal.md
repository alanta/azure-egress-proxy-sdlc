# Proposal

## Why

The scan compares its candidates with the open Dependabot PRs so that parity is measured rather than assumed. Slice 1 has shown that parity: on `main`, all 7 updates in Dependabot's three open PRs were matched, and none were missed ([end-to-end run](../../../docs/end-to-end-run.md)). Dependabot's version-update PRs are retired once slice 2 runs. After that there are no PRs to compare with, and the comparison is code, record schema and documentation that tell us nothing.

Removing the comparison now, before `update-selection`, means that change can build its record changes on a schema that no longer has the comparison section.

## What Changes

- **BREAKING:** the scan no longer reads open Dependabot PRs or compares its candidates with them. The record's `parity` section and the `dependabot-prs` source are removed, and the record moves to a new schema version.
- The report's "Parity with Dependabot" section and its "Missed Dependabot updates" summary are removed.
- Dependabot alerts are kept unchanged. The scan still reads them as a second source that confirms its vulnerability matches.
- The documentation stops describing the comparison as part of the scan. The end-to-end run stays as evidence from slice 1, labelled as describing the version 1 record.

## Capabilities

### New Capabilities

None.

### Modified Capabilities
- `dependency-scan`: removes the requirement "Compare with open Dependabot PRs" and its six scenarios, and drops the parity result from what the report contains. The requirement on unreadable advisory sources still covers Dependabot alerts.

## Impact

- **Code:** removes `src/sdlc/parity.py`, `src/sdlc/pr_diff.py` and `src/sdlc/dependabot_prs.py`, along with their parts in `cli.py`, `record.py` and `report.py`, and their tests and fixtures (`tests/test_parity.py`, `tests/test_dependabot_prs.py`, and the captured PRs in `fixtures/azure-egress-proxy/prs` apart from #76's diff, which the consistency tests use). `src/sdlc/dependabot.py`, which reads the alerts, stays.
- **Schema:** a new record schema version without `parity`. Version 1 records in `runs/` and in the docs stay valid under the version 1 schema, which is kept.
- **Token:** the scan no longer needs `Pull requests: read`. [running-a-scan.md](../../../docs/running-a-scan.md) drops it from the scan's permissions. `fork-mode-delivery` will need read access to PRs again, to read the system's own PRs and their checks, so the token can only be narrowed once that change has settled its credentials.
- **Docs:** [running-a-scan.md](../../../docs/running-a-scan.md) and [scan-coverage.md](../../../docs/scan-coverage.md) lose their sections on the comparison with PRs. The README already records the decision.
- **Subject:** none. Switching off Dependabot's version updates in the subject is the maintainer's step once slice 2 runs. It isn't part of this change.
