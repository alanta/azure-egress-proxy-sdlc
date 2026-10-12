# Design

## Context

The comparison with Dependabot's PRs is spread over the scan: three modules (`parity.py`, `pr_diff.py`, `dependabot_prs.py`), a section of the record (`parity`), a source that can be unavailable (`dependabot-prs`), a report section, fixtures of captured PRs, and the documentation. Dependabot alerts, read by `dependabot.py`, are a separate source and stay. The record's schema is `scan-record.v1.json`, and old records in `runs/` and in the docs conform to it.

## Goals / Non-Goals

**Goals:**
- Remove the comparison completely, so that no code, schema or documentation is left describing it.
- Keep every record written so far valid.

**Non-Goals:**
- Changing how Dependabot alerts are read or reported.
- Switching off Dependabot in the subject. That is the maintainer's step, once slice 2 runs.

## Decisions

### 1. A new schema version, and version 1 is kept

`parity` is a required property of a version 1 record, so removing it is a breaking change. The scan writes records under a new `scan-record.v2.json`. `scan-record.v1.json` stays in the repository unchanged, because the records already in `runs/` and in the docs conform to it.

**Alternative:** making `parity` optional in version 1. That would leave a schema that still describes a section no scan writes, and a reader couldn't tell from the version which kind of record it has.

### 2. The token keeps its PR permission in the docs until delivery has settled

The scan no longer reads PRs, so `running-a-scan.md` stops listing `Pull requests: read` for the scan. `fork-mode-delivery` will read the system's own PRs and their checks again, so the token itself is only narrowed once that change has settled its credentials.

## Risks / Trade-offs

- [A reader of the end-to-end run in the docs looks for the comparison section in a new record] → The end-to-end run says that it describes a version 1 record.
