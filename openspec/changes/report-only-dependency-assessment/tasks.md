# Tasks

## 1. Assessment contract and dependency inventory

- [ ] 1.1 Define and validate the machine-readable assessment record, including subject repository and commit, candidate update, assessment time, evidence references, risk, and check states; verify valid fixtures pass and invalid or missing states are rejected.
- [ ] 1.2 Inventory dependency declarations and build inputs in a pinned subject revision, covering the source types present in `azure-egress-proxy`; verify a fixture reports NuGet, Go, Docker, GitHub Actions, Bicep, VMSS image, devcontainer, and any image-build inputs found in the selected revision.
- [ ] 1.3 Determine update coverage for each inventory entry from configured update mechanisms; verify the assessment exposes known gaps such as inline Python packages, Bicep modules, and OS/image inputs instead of claiming complete coverage.
- [ ] 1.4 Map inventory entries to owning components, release outputs, and expected checks from repository workflows; verify fixtures identify component-specific checks and uncovered path-filter cases such as `mock-idp/` and workflow changes.
- [ ] 1.5 Add tests for recognized, unsupported, unparseable, and inaccessible dependency sources, and document supported source types and known coverage limits; verify the tests pass and the documented inventory matches fixture results.

## 2. Candidate, impact, and validation evidence

- [ ] 2.1 Assess a supplied update candidate or PR and discover candidates for initially supported public update sources without changing the subject repository; verify candidates include old/new versions and the source used, while unsupported sources remain explicitly uncovered or unknown.
- [ ] 2.2 Collect accessible release-note and advisory evidence and produce an evidence-linked impact and preliminary risk explanation; verify a fixture distinguishes observed facts from inference and reports inaccessible or conflicting evidence as uncertain.
- [ ] 2.3 Compare expected checks with observed check-run results and normalize them to `passed`, `failed`, `skipped`, `not applicable`, or `unknown`; verify fixtures cover successful, failing, path-filter-skipped, irrelevant, and inaccessible results and never count a skip as a pass.
- [ ] 2.4 Add tests and document how candidate discovery, risk explanations, and check evidence are represented; verify the examples include a grouped update with different affected outputs and validation gaps.

## 3. Report-only pilot and evaluation

- [ ] 3.1 Generate Markdown and machine-readable reports bound to the exact subject commit, candidate, time, and evidence references; verify both outputs describe the same assessment and are stored outside the subject repository.
- [ ] 3.2 Enforce the read-only boundary for the pilot, using no write-capable subject-repository credentials and triggering no CI, release, deployment, merge, or publishing actions; verify an assessment leaves the subject revision and remote state unchanged.
- [ ] 3.3 Replay the baseline dependency-pass snapshot and recorded cases for PRs #75, #76, #77, and #89; verify expected coverage gaps and skipped/failed/unknown distinctions appear, and record any mismatches against the manual assessment.
- [ ] 3.4 Document the manual invocation, required inputs, report interpretation, evidence limitations, and pilot evaluation measures; verify a maintainer can reproduce a report for a pinned revision using the runbook.
