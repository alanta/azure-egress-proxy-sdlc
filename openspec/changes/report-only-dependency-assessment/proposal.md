# Proposal

## Why

Dependency changes in `azure-egress-proxy` span package manifests, container build inputs, infrastructure modules, CI actions, and the planned Marketplace image pipeline, while current checks can be skipped for affected changes. Before granting an agent authority to edit, merge, or publish, the pilot needs a read-only assessment that shows what it found, what it could not verify, and which artifact-specific checks actually ran.

## What Changes

- Introduce a report-only dependency assessment for a selected repository revision and, when supplied, a dependency update or pull request.
- Inventory dependency sources and update coverage, including uncovered and unknown sources; correlate discovered or supplied candidate updates with affected components, release artifacts, and required checks.
- Summarize relevant version, advisory, release-note, and validation evidence with explicit provenance and uncertainty.
- Report check outcomes as `passed`, `failed`, `skipped`, `not applicable`, or `unknown`; never treat a skipped or unavailable check as a pass.
- Produce a human-readable report and machine-readable assessment result without editing the monitored repository, opening or updating PRs, merging changes, or publishing artifacts.

## Capabilities

### New Capabilities

- `dependency-update-assessment`: Read-only inventory, update assessment, impact mapping, validation-evidence reporting, and output of an auditable assessment for a repository revision or proposed dependency update.

### Modified Capabilities

None.

## Impact

- The separate agentic SDLC project: new assessment behavior, report format, and associated checks and tasks.
- `azure-egress-proxy` as the initial subject: its dependency declarations and update sources, CI and release checks, container and binary outputs, and the planned Marketplace VM image build and release path are assessment inputs only.
- No code, workflows, dependencies, PRs, or release artifacts in the subject repository are changed by this pilot.
