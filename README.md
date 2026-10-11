# Agentic SDLC automation for azure-egress-proxy

**Status:** Slice 1, the revision dependency scan, is built. Its spec is [`openspec/specs/dependency-scan`](openspec/specs/dependency-scan/spec.md), and the change that built it is archived under [`openspec/changes/archive/2026-10-10-revision-dependency-scan`](openspec/changes/archive/2026-10-10-revision-dependency-scan/). To run a scan, see [`docs/running-a-scan.md`](docs/running-a-scan.md).

Slice 2 is being designed. How it applies updates is settled in [ADR-0001](docs/adr/ADR-0001-how-updates-are-applied.md); its first change selects which updates to prepare.

## Purpose

Keep [`azure-egress-proxy`](https://github.com/alanta/azure-egress-proxy) up to date with as little maintainer effort as possible. The end goal is hands-off operation:
- the system finds updates, applies them, and builds and tests every affected output;
- a coding agent resolves upgrade problems in the software and the pipelines;
- low-risk changes are merged;
- the maintainer is told when a release is worth cutting.

Trust is built step by step on the way there. The project also serves to learn where agentic AI helps in SDLC automation.

`azure-egress-proxy` is a good pilot. It produces binaries and container images, secures network egress, and is adding a Marketplace VM image.

## Repository boundary

This system lives in this repository, separate from the code it maintains.

- **This repository:** the scanner, the orchestration, agent prompts and configuration, record schemas, evidence fixtures and run outputs.
- **The subject repository:** its code and the policies about that code. Today that means the update policy. Later it may include the map of components, outputs and required checks, so that it changes in the same PR as the code it describes.
- **How changes reach the subject:** the system works on a copy. It branches or forks, makes and tests the change, and merges back through a PR. It never writes to the subject's default branch directly.

## Delivery slices

1. **Scan a revision** (read only, no LLM). Produce an inventory, update candidates, a policy classification, vulnerability matches and cross-file version consistency for a pinned commit, with every gap made visible. Slice 1 showed that it finds at least what the open Dependabot PRs proposed.
2. **Apply and validate.** The system selects updates, then applies routine ones with deterministic tools and breaking ones with a coding agent. It checks every result deterministically, then opens a draft PR from a fork, and the subject's CI builds and tests every affected output. The agent also makes bounded repair attempts (any file, including minor code and pipeline changes) and drafts release-note summaries.
3. **Decide.** A merge policy (deterministic gates plus scores per risk dimension), automatic merge for the low-risk category, checks after merge, and release-readiness advice.

What each step should do, from discovery to release advice, is described in [docs/functional-workflow.md](docs/functional-workflow.md).

In parallel: a research change on **where the system runs**. GitHub Actions, a cloud job and a dedicated machine are all open. Credential scope and isolation are hard criteria, because the runner will be able to change a security product that ships to the Azure Marketplace.

## Decisions so far

- **Deterministic code decides and checks; an agent may do the work** ([ADR-0002](docs/adr/ADR-0002-deterministic-decisions-agent-work.md)). Routine updates are applied deterministically. Breaking updates and repairs go to a coding agent, not to a single structured LLM call. Every result passes the same deterministic check, whoever made it.
- **The first slice scans a whole revision,** not individual Dependabot PRs.
- **The update policy stays with the code.** No cross-tool standard exists, so it uses Renovate's config format in the subject repository (`.github/renovate.json5`). Until the maintainer merges one, a trial policy kept here stands in for it.
- **Dependabot's version-update PRs are retired once slice 2 runs.** Slice 1 showed that the scan finds what they propose, so the scan no longer compares with them. Dependabot alerts stay as a second source for vulnerabilities.
- **Updates reach the subject as draft PRs from a fork** ([ADR-0001](docs/adr/ADR-0001-how-updates-are-applied.md)). The subject's CI validates them. A deterministic step pushes, and the only write credential is scoped to the fork and to opening PRs. An agent may get write access to the fork later, given guardrails against prompt injection.
- **Renovate is used for discovery and lookups.** Selection, applying and delivery are the system's own code, so the policy doesn't depend on Renovate's semantics.
- **Updates are prepared for a reason, not on a weekly schedule.** Each run depends only on the state of `main`, the date and the policy:
  - security fixes are prepared right away, reachable or not, at the smallest fixing version. This includes the Go standard library;
  - a version line nearing end of life gets a PR when the policy allows the move, and an early warning otherwise;
  - everything else is batched in a monthly window and left unchanged between windows, which keeps churn down.
- **A security fix doesn't override a policy hold.** It is reported to the maintainer instead.
- **Platform migrations are out of scope for now.** Moving .NET from 10 to 11 brings many NuGet majors with it. The policy holds those until the platform moves, and that move stays a human decision.
- **Slice 2 relies on the subject's CI.** It builds every output, including the app images and `mock-idp`, and runs govulncheck with the Go version the PR builds with.
- **VM image coverage waits for the image build.** It will be added once the `marketplace-vm-image` change is implemented in the subject repository.

## Division of responsibilities

- **Deterministic tools and policy** establish versions, resolve dependencies, select updates, apply routine updates, check every result, run scanners, builds and tests, enforce merge eligibility, and report pass or fail. They are the authority for hard gates.
- **The coding agent** applies breaking updates, interprets release notes and advisories, maps changes to project context, diagnoses failures, makes bounded fixes and drafts summaries. Its assessments cite evidence and state uncertainty. It cannot override a failed check or grant itself permission to merge.
- **The maintainer** sets policy, resolves exceptions and novel risks, reviews what falls outside the automatic path, and approves Marketplace publication.

**Untrusted input.** Release notes, changelogs and PR bodies are written by upstream authors and are treated as data. Nothing read from them can lower a risk score or relax a gate. The agent's sandbox doesn't hold the credential that writes to the subject repository.

## Risk and autonomy

Risk accounts for at least security relevance, scope of impact, compatibility uncertainty, validation coverage and reversibility. Uncertainty moves a change toward review; it never makes a change eligible for automatic merge.

Autonomy grows in steps:

1. Compare the system's findings with current practice (Dependabot, manual review) and record disagreements.
2. Let the system prepare changes and validation evidence for review.
3. Allow bounded repair attempts with clear diffs and rerun results.
4. Enable automatic merge for explicitly defined low-risk changes.

The system records what it observed, its assessment and evidence, what it did, which checks ran, human corrections, and outcomes after merge, so that autonomy can be widened deliberately.

## Marketplace VM image

The `research/marketplace` branch of the subject repository holds the `marketplace-vm-image` OpenSpec change. It plans:
- a Packer-built Azure Linux 3 ARM64 image containing a verified release binary;
- SBOMs and vulnerability gates (Grype, govulncheck);
- a smoke-tested VM;
- promotion of an immutable Compute Gallery image version behind a protected environment.

None of it is implemented yet. When it is, this system adds:
- the image's build inputs as dependencies: Packer and its plugins, the tools that build and scan the image, and the platform image version. The image design resolves `latest` at build time; whether that version should be pinned in the repository, so that updates arrive as reviewable PRs, is a decision for then;
- the actual candidate image, validated with a VM smoke test, as release evidence;
- re-scans of published image SBOMs against a fresh vulnerability database, triggering a patch-release recommendation;
- separate decisions, evidence and permissions for update merging, GitHub releases, gallery promotion and any Partner Center publication. Low-risk auto-merge never implies image publication.

## How to evaluate the pilot

- Coverage of the dependency inventory and available updates. Slice 1 measured this against Dependabot.
- Time from an update or security fix becoming available to a validated change.
- Coverage and success rate of validation across affected outputs.
- Accuracy of risk assessments compared with human review and observed outcomes.
- Bounded-repair success rate, and how often a human has to step in.
- Automatic-merge volume, regressions or reverts after merge, and unnecessary churn.
- Usefulness of release recommendations, and whether releases carry clear validation evidence.

## Open questions

- Where the system runs, and with which credentials (separate research change).
- Which update categories qualify as low risk, and the exact conditions for automatic merge.
- What evidence makes a release recommendation useful, and which release and versioning conventions apply.
- Which measures and review period decide whether autonomy can be widened.

## Development

Python 3.12+ with [uv](https://docs.astral.sh/uv/):

```bash
uv sync                      # install from the lock file
uv run sdlc scan --help      # the CLI
uv run pytest                # tests
uv run ruff check && uv run ruff format --check
```

## Further reading

- [Dependency and validation discovery](docs/azure-egress-proxy-dependency-pass.md): manual inventory of the subject at `064aa09`.
- [What the scan covers](docs/scan-coverage.md): sources, lookup states, locked entries and known gaps.
- [Tooling spike](docs/tooling-spike.md): Renovate, OSV-Scanner and the PydanticAI/Copilot trial.
- [ADR-0001: How updates are applied](docs/adr/ADR-0001-how-updates-are-applied.md): the options considered for slice 2 and why fork mode was chosen.
