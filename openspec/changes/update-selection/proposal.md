# Proposal

## Why

Slice 1 lists every update candidate for a revision, but it doesn't say which of them are worth preparing. Updating everything every week, as Dependabot does, causes churn without reducing risk. Slice 2 prepares updates as draft PRs from a fork. Deterministic code decides what to prepare, and an agent does the work only where judgement is needed ([ADR-0002](../../../docs/adr/ADR-0002-deterministic-decisions-agent-work.md)). So slice 2 first needs a deterministic answer to four questions: which units, why, to which version, and whether each one is breaking.

This change defines that answer and shows it in the scan report, without writing anything. The selection can be checked against real scans before the follow-up change, `fork-mode-delivery`, acts on it.

## What Changes

The selection starts simple and grows when a real case needs it. Values that may need tuning are defaults in the code, and the report shows them.

- **A selection step runs inside the scan.** Its inputs are the scan record, the update policy and the scan's date, and it decides which **units** to prepare. A unit is a set of updates that the policy's group rules put together, or a single update. Nothing is carried over between runs: an update that hasn't been merged is selected again for as long as its reason holds.
- **Only in-scope candidates are targets, so holds always win.** That includes security fixes.
- **There are three reasons to select a unit:**
  - **Security:** an inventoried version has a known vulnerability, whether it is reachable or not. The evidence is the scan's own advisory sources: OSV, govulncheck (including the Go standard library) and Dependabot alerts. The unit covers that package in every file that declares it at a vulnerable version, and each declaration's target is the smallest in-scope candidate that reaches the fix. Security units are selected on every run, with no minimum release age.
  - **Lifecycle:** a version line in use is nearing its end of life, or past it, according to the scan's lifecycle data (90 days ahead). The unit covers the dependencies on that line. For each of them, the target is the smallest in-scope candidate on a supported line. Lifecycle units are selected on every run.
  - **Batch:** in a monthly window, the first seven days of the month, every other dependency with an in-scope candidate. The target is its newest in-scope candidate, if that is at least 7 days old. A younger one waits for the next window. A candidate with no known release date counts as old enough, and is marked "age unknown". The batch skips dependencies that already have a security or lifecycle unit, so two units never touch the same dependency. Updates are put into units by the policy's groups, and the updates of a package in no group form one unit across all the files that declare it.
- **Problems are reported, never left out:**
  - a security fix that only held candidates reach is reported as "vulnerable, fix held by policy", with the rule that holds it;
  - a lifecycle move that has no in-scope candidate is reported as an early warning;
  - an advisory with no fixed version is reported as having no route;
  - a reason that can't be evaluated because data is missing is reported as not evaluated, with the reason.
- **Breaking mark.** A unit is breaking when it contains a major update or is a lifecycle move, and routine otherwise. In `fork-mode-delivery`, the mark decides whether a deterministic applier or the agent does the work.
- **Preview.** The record gains a selection section, and the Markdown report a "Would prepare" section. For each unit they show its reason, targets, breaking mark and evidence. The defaults in use are shown too.
- **Out of scope,** for `fork-mode-delivery` or later:
  - applying updates;
  - the deterministic check after applying;
  - fork, PRs and any write credential;
  - reading CI results;
  - the agent;
  - merge decisions;
  - a policy file for the defaults, which comes once the maintainer wants to change one.

## Capabilities

### New Capabilities
- `update-selection`: decides and reports which units the system prepares, with the reason, targets and breaking mark for each. It also reports held security fixes, early warnings and anything it couldn't evaluate.

### Modified Capabilities
- `dependency-scan`: each candidate also carries its release date, when the source publishes one, so that the batch can apply the minimum release age. It also carries the policy group it falls in, recorded when the scan classifies it, so that the selection can group from the record.

## Impact

- **Code:** a selection module beside `src/sdlc/record.py`, built on the scan's candidates, advisory and lifecycle data. The policy evaluator in `src/sdlc/policy.py` also learns the policy's group rules, and the scan records each candidate's group. There are also additions to the Renovate normalisation (release dates), the record schema (a new version, after the one `retire-dependabot-pr-comparison` introduces) and the report renderer. Selection is a pure function of the record, the policy and the date, so it can be tested completely against fixtures.
- **Renovate:** only used for discovery and lookups, as in slice 1.
- **Policy:** the trial policy's weekly `schedule` has no effect on the system any more and is removed. Groups and holds are unchanged.
- **Credentials and subject:** no new credentials and no writes. This change stays within slice 1's read-only boundary.
