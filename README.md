# Agentic SDLC automation for azure-egress-proxy

**Status:** Functional concept; requirements to refine against the repository and its release process.

## Purpose

Explore a semi-autonomous system that keeps `azure-egress-proxy` up to date, handles routine dependency changes, and recommends when a release is worthwhile. The project is a useful pilot because it produces binaries and container images and is adding a Marketplace VM image release path. The initial dependency pass was against `main`, before that image work; the newer image proposal is described below. The project is intended to secure network egress.

This document describes desired behavior, not a technical architecture.

## Desired outcomes

The system should:

- Discover dependency updates and security fixes across the project, rather than being limited to updates raised by Dependabot.
- Explain what an update changes, why it matters, and which project components and outputs it may affect.
- Prepare updates, validate every affected output, and attempt bounded, evidence-based fixes when checks fail.
- Merge changes that meet an explicit low-risk policy and all required validation gates.
- Keep higher-risk, ambiguous, or insufficiently validated changes out of the automatic merge path.
- Recommend releases based on validated changes and prepare supporting evidence, without publishing to the Azure Marketplace automatically.
- Make decisions and results understandable enough to build trust and learn where agentic AI helps in SDLC automation.

## Functional workflow

1. **Maintain a dependency inventory.** Identify the dependencies and update mechanisms in use. The inventory may include direct and transitive language packages, container base images, operating-system packages in build and development environments, VM scale set Marketplace base-image references, build toolchains, Bicep modules, and CI actions. The initial repository discovery is captured in [azure-egress-proxy-dependency-pass.md](docs/azure-egress-proxy-dependency-pass.md); coverage and update mechanisms still need to be evaluated.
2. **Discover and prioritize updates.** Find available versions and relevant security advisories. Prioritize urgent security fixes and avoid creating noisy or redundant work. Decide when related updates should be grouped and when they should stay separate so failures remain attributable.
3. **Assess impact and propose a plan.** Summarize relevant release notes and advisories; identify how the dependency is used; estimate affected components and outputs; and state risks, evidence, and uncertainties. Major, security-sensitive, or behavior-changing updates should receive particular scrutiny.
4. **Prepare the change.** Make the update in an isolated, reviewable change, preserving enough context to explain what was changed and why.
5. **Validate affected outputs.** Run the required checks for every affected output: container images and binaries, plus relevant infrastructure and deployment checks for the VM scale set and its selected Marketplace base-image version. Once the custom image path is implemented, validate the image build, its SBOMs, and a VM booted from the candidate image before promotion. Report each check and artifact result; a single green CI check is not sufficient if other affected outputs were not validated.
6. **Diagnose and attempt bounded repairs.** Distinguish likely update regressions from flaky checks and unrelated failures. The agent may make safe, limited fixes and rerun validation. It must stop and explain when evidence is inconclusive, repair attempts fail, or a decision requires security or design judgment.
7. **Decide whether to merge.** Automatically merge only when an update fits an explicitly approved low-risk category and all deterministic policy and validation requirements pass. Hold other changes for review, with the unresolved question or evidence needed made clear.
8. **Check the result after merge.** Confirm the merged change remains healthy under the relevant checks and report regressions for investigation or revert consideration.
9. **Recommend release readiness.** Summarize validated, unreleased changes; explain their security and user impact; identify remaining validation gaps; and recommend whether to cut a release.
10. **Keep image release gates explicit.** The proposal puts Compute Gallery publication behind a protected GitHub environment with required reviewers and promotes an image version to `latest` only after smoke tests and SBOM publication pass. Partner Center offer publication is out of scope for that change; treat it as a separate, human-approved action unless its policy is explicitly changed.

## Marketplace VM image work underway

A read-only look at the separate `research/marketplace` checkout found an OpenSpec change at `openspec/changes/marketplace-vm-image/` with a proposal, design, specs, and tasks. It describes a custom Azure Linux 3 ARM64 image built with Packer, containing a verified proxy release binary, and a release workflow that creates SBOMs, applies vulnerability gates, smoke-tests a VM, and promotes an immutable Compute Gallery image version only after the gates pass. In the inspected checkout, the OpenSpec tasks were still unchecked; treat this as planned work, not as a verified implementation. The earlier [dependency pass](docs/azure-egress-proxy-dependency-pass.md) remains a snapshot of `main` before this work.

This adds functional requirements to the SDLC pilot:

- Track image-specific inputs as dependencies: the platform image version, Packer and its plugins, provisioned OS packages, and tools used to build and scan the image.
- Trace each image version back to its source release, verified binary, build inputs, vulnerability results, and OS and application SBOMs.
- Validate the actual candidate image with a VM smoke test; do not treat a successful Packer build or an unrelated CI job as release evidence.
- Keep update merging, GitHub release creation, Compute Gallery publication/promotion, and any later Marketplace offer publication as separate decisions with separate evidence and permissions. Low-risk auto-merge must not imply automatic image publication or promotion.

## Division of responsibilities

Use deterministic tools and LLMs for different strengths:

- **Deterministic checks and policy** establish versions, resolve dependencies, run scanners and tests, validate artifacts, enforce merge eligibility, and report pass/fail results. These checks are the authority for hard gates.
- **LLM-assisted reasoning** interprets release notes and advisories, connects changes to project context, proposes an impact and risk explanation, diagnoses failure logs, suggests bounded fixes, and drafts update and release summaries.
- **Human judgment** sets policy, resolves exceptions and novel risks, reviews changes outside the automatic path, and approves Marketplace publication.

An LLM assessment should include supporting evidence and uncertainty. It must not override failed checks or grant itself permission to merge. Low-risk automatic merge is a desired capability, subject to explicit policy and required gates.

## Risk and autonomy

Risk assessment should account for at least security relevance, scope of impact, compatibility uncertainty, validation coverage, and reversibility. Uncertainty should move a change toward review, not make it eligible for automatic merge. The exact low-risk definition and merge policy remain open decisions.

Build trust progressively:

1. Compare system discovery and recommendations with current practice and record disagreements.
2. Let the system prepare changes and validation evidence for review.
3. Allow bounded repair attempts with clear diffs and rerun results.
4. Enable automatic merge only for explicitly defined low-risk changes after the policy and validation process has been refined.

Record what the system observed, its assessment and evidence, actions it took, checks that ran, human corrections, and post-merge outcomes. This makes it possible to evaluate its behavior and expand autonomy deliberately.

## How to evaluate the pilot

Useful measures include:

- Coverage of the project's dependency inventory and available updates.
- Time from an update or security fix becoming available to a validated change.
- Coverage and success rate of validation across affected outputs.
- Accuracy of risk assessments compared with human review and observed outcomes.
- Bounded-repair success rate and how often human intervention is needed.
- Automatic-merge volume, regressions or reverts after merge, and unnecessary update churn.
- Whether release recommendations are useful and whether releases have clear validation evidence.

## Initial scope and open questions

The initial pilot is `azure-egress-proxy`. Dependabot may remain as a comparison or signal while the system's own discovery is evaluated; it should not define the system's eventual scope. The read-only repository discovery in [azure-egress-proxy-dependency-pass.md](docs/azure-egress-proxy-dependency-pass.md) is a snapshot of `main` before the Marketplace image work was added on the separate `research/marketplace` checkout. A preliminary scanner/provider spike and its handoff notes are in [tooling-spike.md](docs/tooling-spike.md).

Before implementation, refine this brief by inspecting the repository and answering:

- What dependencies and update sources are present, including the VM scale set's base image, custom image build inputs, Packer tooling, provisioned OS packages, and packages used in development environments?
- Which existing checks validate each output, and what additional checks are required before merge or release?
- Which update categories qualify as low risk, and what exact conditions permit automatic merge?
- How should updates be grouped, prioritized, and scheduled, especially for security fixes?
- What evidence makes a release recommendation useful, and what release/versioning conventions apply?
- What validation and human approval are required before Marketplace publication?
- Which measures and review period will determine whether autonomy can safely expand?

## Explicit initial boundary

The goal is to automate dependency discovery, assessment, update work, validation, and release recommendations. It is not to publish to the Azure Marketplace without human approval, bypass required checks, or silently make uncertain security and design decisions.
