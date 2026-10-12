# Proposal

## Why

Until updates go all the way from a scan to a validated draft PR, we can only guess how a choice early in the pipeline plays out at its end. This change builds the thinnest end-to-end process that is still real: selected units are applied (routine ones by a deterministic applier, breaking ones and repairs by a coding agent), checked deterministically, pushed to a fork, and opened as draft PRs whose CI results come back into the record. From then on, each part is improved on a process that runs ([ADR-0002](../../../docs/adr/ADR-0002-deterministic-decisions-agent-work.md)).

It builds on `update-selection`, which decides the units.

## What Changes

- **A `prepare` run.** It scans the subject's `main` and selects units, as the scan already does with `update-selection`. Then it takes each unit through the steps below and writes a prepare record and report. Runs are started by hand. Each run depends only on the state of `main`, the date, the policy and the open PRs.
- **Apply.**
  - **Routine units:** one generic applier. It replaces each target's current version at the file and line the scan recorded, then refreshes the ecosystem's lock files (`dotnet restore --force-evaluate`, `go mod tidy`).
  - **Units it can't apply,** such as actions pinned by SHA, which need the new digest: reported as "no applier yet" and skipped.
  - **Breaking units:** go to the agent.
- **Agent.** A coding agent runs once per breaking unit, and once more for a unit whose CI is red.
  - **Where:** in a container that holds no credential for GitHub or the subject. Its network access is limited to the model's API and the package registries the build needs.
  - **What it gets:** the unit, the diff so far, and build, test or CI output. No upstream release notes yet.
  - **What it can't do:** push. Its result goes through the same check as any other.
- **Check.** The branch is scanned again, and must satisfy two things: every target of the unit is reached, and no other dependency changed. One diff-policy rule applies: a change under `.github/workflows/` or `infra/` gets a "needs review" label. A unit that fails the check isn't pushed, and the report says why.
- **Deliver.**
  - **Branch:** each unit's branch is rebuilt from `main` and pushed to the fork with the machine account's token, but only when its content changed.
  - **Draft PR:** each unit has one draft PR on the subject. Its body comes from the record: the reason, the evidence, the check result, and whether an agent made changes.
  - **Closing:** a PR is closed when its unit is no longer selected. The exception is a batch PR outside the batch window, which stays open unchanged.
- **CI results.** The next run reads each open PR's check results into the record, and starts the repair for a red one.
- **Prepare record and report.** For each unit, the outcome is one of: checks passed, checks failed, checks pending, apply failed, check failed, or no applier yet. The record links each PR, and says which steps were deterministic and which were the agent's.
- **Out of scope**, for the improvement rounds that follow:
  - reading release notes, and the structured facts the agent would get from them;
  - more than one repair attempt;
  - a richer diff policy;
  - appliers for digest pins;
  - running on a schedule, and the question of where the system runs;
  - merge decisions (slice 3).

## Capabilities

### New Capabilities
- `update-application`: turns a selected unit into a checked change on a branch, whether a deterministic applier or the agent makes it, with the deterministic check and the diff policy.
- `update-delivery`: brings checked changes to the subject as draft PRs from a fork, keeps those PRs in step with the selection, and reads their CI results back into the record.

### Modified Capabilities
None. The scan and the selection are used as they are.

## Impact

- **Code:** a `prepare` command, the generic applier, the agent step, the check, and delivery through the GitHub API. Also a prepare record schema and its report.
- **Credentials:**
  - **The machine account's classic token** (`public_repo`), kept in the keyring like the scan's token. It only pushes to the machine account's fork and opens PRs.
  - **A key for the model's API,** for the agent's container.
  - The scan's read-only token is unchanged, but it needs `Pull requests: read` again to read the PRs and their checks.
- **Subject:** for the first time, the system opens PRs on the subject, always as drafts and from the fork. A maintainer approves the first CI run of the machine account.
- **Prerequisites the maintainer sets up:** the machine account, its fork and token, and the model API key.
- **Docs:** a how-to for running a prepare and reading its report, next to [running-a-scan.md](../../../docs/running-a-scan.md).
