# Design

## Context

See `proposal.md` for motivation and `specs/dependency-update-assessment/spec.md` for the behavior contract. The baseline assessment found multiple dependency declaration and update sources, with affected outputs and CI checks that are not always exercised together. The pilot must remain separate from the subject repository and must not turn missing or skipped evidence into a safety claim.

## Goals / Non-Goals

**Goals:**

- Produce a reproducible assessment for an explicitly selected repository revision and optional update candidate or pull request.
- Keep observed facts, tool-derived results, and LLM inference distinguishable and linked to their evidence.
- Make an incomplete dependency inventory and incomplete validation visible.
- Exercise the deterministic-tool/LLM division of responsibilities while keeping the run read-only.

**Non-Goals:**

- Updating dependency declarations, creating or editing pull requests, merging, releasing, deploying, or publishing an image.
- Treating this pilot's preliminary risk label as an automatic-merge policy.
- Claiming universal ecosystem coverage or building a persistent vulnerability database.

## Decisions

### Assess a pinned repository revision, with optional candidate context

Require an exact subject repository and revision for every run; accept a candidate update or PR as additional input, not as the only possible run mode. This supports a baseline inventory as well as a focused update review and makes reports comparable. A moving branch name alone is insufficient evidence; resolve it to a commit before assessment.

**Alternatives considered:** PR-only reports would not reveal uncovered dependency sources when no update PR exists. Continuous scanning would introduce scheduling and notification policy before the report-only behavior has been evaluated.

### Separate deterministic evidence collection from LLM interpretation

Use deterministic checks as the authority for parsed versions, discovered source paths, available CI states, and artifact/check mappings. Use an LLM to interpret release notes and advisories, explain likely blast radius, and summarize uncertainty. Each material conclusion must link to the collected evidence; if the evidence is absent or contradictory, preserve `unknown` rather than filling the gap with inference.

**Alternatives considered:** LLM-only inspection is flexible but makes source coverage and check-state claims difficult to reproduce. Deterministic-only reporting is auditable but provides little help interpreting upstream change notes or project-specific impact.

### Normalize expected and observed validation separately

Maintain the set of checks expected for an affected component/output separately from the check runs actually observed. Derive `passed`, `failed`, `skipped`, `not applicable`, or `unknown` from those two facts. In particular, a missing check run or path-filter skip is never upgraded to `passed`.

**Alternatives considered:** Reporting only a single aggregate green/red result would conceal output-specific gaps, including checks skipped for mock-idp, image, or workflow changes.

### Produce paired human- and machine-readable reports from one assessment

Render a concise Markdown report for maintainers and a structured machine-readable record from the same normalized result. Bind both to the subject commit, candidate, assessment time, and evidence references. Keep generated reports in the SDLC project or run output, not in the monitored repository; do not persist secrets or private API responses.

**Alternatives considered:** Markdown-only is easy to review but difficult to evaluate consistently across runs. A database is unnecessary for the initial pilot and would introduce retention and access-control decisions.

### Keep the pilot read-only and manually invoked

Run only when a maintainer requests an assessment. Read available repository metadata and existing check results; do not trigger CI, write to the subject checkout, or call release/deployment/publishing actions. Use read-only access when private GitHub metadata is needed. Missing permissions or unavailable logs become explicit coverage gaps.

**Alternatives considered:** Automatically triggered scans may reduce latency but add workflow permissions and operational noise before output quality is known. The pilot deliberately measures usefulness before adding autonomy.

## Risks / Trade-offs

- **Static discovery misses an unconventional dependency source** → report unsupported or unknown sources, retain source paths and inventory coverage, and compare findings against the initial manual inventory.
- **Upstream release notes or vulnerability data are stale or unavailable** → record the source and retrieval time; surface missing evidence as unknown.
- **LLM overstates compatibility or security impact** → require evidence-linked explanations, preserve uncertainty, and prohibit the risk label from authorizing changes or merges.
- **CI status does not cover an affected artifact** → map checks per component and output, and keep skipped or absent results distinct from successful checks.
- **Private GitHub data is unavailable or sensitive** → operate with read-only permissions, omit secret material, and state when private alerts or logs could not be assessed.

## Migration Plan

No migration or subject-repository change is required. Validate the report against the recorded dependency-pass snapshot and selected existing update PRs. Keep outputs in the SDLC project/run artifacts; discontinue the pilot by removing those outputs and its invocation without reverting or changing the subject repository.

## Open Questions

- Which private GitHub alert and Actions-log sources can be made available with read-only credentials for the pilot? If unavailable, report them as unknown and do not block the initial baseline inventory.
- Which registry queries can reliably resolve current candidate versions for each discovered source? Start with sources already covered by existing package-manager data and explicitly list gaps; expand only after validating source quality.
