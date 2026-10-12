# Deterministic decisions, agent work

## Status
Accepted

## Created / Updated
11-Oct-2026

## Deciders
Marnix van Valen

## Context
The system started from the principle that an agent is brought in only where a deterministic tool can't do the job. Designing how slice 2 applies and selects updates put that principle under strain.

Renovate can apply updates deterministically, but only if we bend it:
- Its own security path either misses the Go standard library (GitHub alerts) or replaces our holds (OSV alerts set their own `allowedVersions`).
- Its schedule semantics would have to be imitated to preview what it will do.
- Its lookup report has no release history.

Putting the selection into Renovate's configuration would also make our policy depend on its semantics. Replacing Renovate later would then mean rewriting the policy.

Applying an update is often not hard in itself. For an ecosystem with a package manager, it's a CLI command (`dotnet add package` with `dotnet restore --force-evaluate`, `go get` with `go mod tidy`). The other sources, such as Dockerfile digests, pinned actions, Bicep modules and inline `pip install`, are regex edits.

What determinism can't do is the work around a breaking change. A major version for end of life, or a security fix that changes behaviour, needs the release notes and migration guide, and changes to code and pipelines. That is agent work. It also means the agent reads upstream text, which is untrusted.

## Decision drivers
* **Authority.** Gates, risk scores and the choice of what to update must stay deterministic. An agent can never relax them.
* **Reproducibility.** A routine update should give the same result every time, and the record must say exactly what happened.
* **Cost of the work.** We compare what it costs to do the work deterministically with what it costs to check an agent's result deterministically.
* **Replaceability.** The policy and the selection must not depend on the semantics of one tool.
* **Containing untrusted input.** Release notes and migration guides can contain instructions aimed at the agent.

## Considered options

### Option 1: An agent only where determinism can't do the job

The original principle. Every update is applied deterministically, by Renovate or by per-source appliers, and an agent only repairs failures.

**Pro:**
* Agent work is as small as it can be.

**Con:**
* It forces either bending Renovate or writing appliers for every source, even where checking an agent's work would be cheaper.
* Breaking updates still reach the agent, but only after a deterministic attempt that was bound to fail.

### Option 2: Deterministic decisions and checks; routine work deterministic, breaking work by the agent

Deterministic code decides which units to prepare, why, and to which target version, and checks every result. Routine updates are applied by deterministic appliers. Units that the policy marks as breaking go straight to the agent: majors, end-of-life moves, and fixes that are known to break. The agent also repairs any unit whose checks fail.

**Pro:**
* Routine updates stay reproducible and cost no agent time.
* The agent does the work that needs judgement, and starts from the right place for breaking units.
* The same check applies to every result, whoever made it.

**Con:**
* Deterministic appliers are needed for the routine path. They can be built by an agent at development time and reviewed like any code.
* There are two ways of doing the work, routed by a deterministic "breaking" mark.

### Option 3: Deterministic decisions and checks; the agent does all the work

As option 2, but the agent applies every unit, calling the CLIs itself.

**Pro:**
* The least code: one way of doing the work.

**Con:**
* Routine updates become nondeterministic and cost agent time, for work a CLI does exactly.
* The agent runs on every unit, so the exposure to untrusted input is the largest.

### Option 4: The agent also decides

The agent chooses what to update and when, as well as doing the work.

**Con:**
* It breaks the rule that gates and risk stay deterministic. Rejected without further weighing.

## Decision
The decision has been made to adopt option 2: deterministic tools own the decisions and the checks, and an agent may do the work wherever doing it deterministically costs more than checking the agent's result deterministically. Routine updates are applied deterministically. Breaking units and repairs go to the agent. Option 2 keeps routine updates reproducible, and spends agent time only where judgement is needed. It also keeps the policy and the selection in our own code, independent of any one tool.

### Consequences
* **Selection is our code.** It works from the scan record and the policy: security from the scan's own advisories, lifecycle from its end-of-life data, and a monthly batch for the rest. Renovate's `vulnerabilityAlerts`, `osvVulnerabilityAlerts` and `schedule` are not used.
* **Renovate's role shrinks to discovery and lookups,** where its breadth is hard to match. The record is the seam: whatever produces the record can be replaced, one source at a time.
* **Applying and delivery are ours.** Deterministic appliers (a package manager's CLI, or a regex edit) apply a unit to a fresh branch. A deterministic step pushes the branch to the fork and opens or updates the draft PR. Each run rebuilds a unit's branch from the current `main` and pushes only when its content changes. [ADR-0001](ADR-0001-how-updates-are-applied.md) still applies to the fork, the draft PRs and the credentials. Its choice of Renovate as the tool that makes the PRs is superseded by this ADR.
* **Every result goes through the same deterministic check before it's pushed.**
  * The branch is scanned again. Every declaration of the unit's dependencies is at the target version, no other dependency changed, and the lock files are consistent.
  * A diff policy decides which paths and sizes need human review whatever the checks say, such as workflows, `infra/` and authentication code.
  * The subject's CI then validates every affected output.
* **Upstream text is contained.**
  * Release notes and migration guides come only from the source repository that the registry metadata points to, fetched from allowed domains. The record keeps each text's source and hash.
  * A reading step without tools turns them into structured facts, each with its source link. The acting agent gets those facts, not the raw text.
  * The agent works in a sandbox without credentials. Whether it may ever hold the fork token is decided together with its guardrails.
  * Agent work never qualifies for automatic merge until the record shows that the category holds up.
* **An agent may build the deterministic tooling** (appliers, custom managers) at development time, through normal review.

### Potential next steps
* Define the selection, including the deterministic "breaking" mark (`update-selection`).
* Define the appliers, the re-scan check, the diff policy and the delivery to the fork (`fork-mode-delivery`).
* Design the reading step's structured facts and the agent's sandbox, in the change that brings in the agent.

## Links
* [ADR-0001: How updates are applied](ADR-0001-how-updates-are-applied.md)
* [README](../../README.md): division of responsibilities, untrusted input
* [Functional workflow](../functional-workflow.md): steps 3 to 6
