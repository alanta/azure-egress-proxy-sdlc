# Proposal

## Why

Slice 1 lists every update candidate for a revision, but it doesn't say which of them are worth preparing. Updating everything every week, as Dependabot does, causes churn without reducing risk. Slice 2 prepares updates as draft PRs from a fork. Deterministic code decides what to prepare, and an agent does the work only where judgement is needed ([ADR-0002](../../../docs/adr/ADR-0002-deterministic-decisions-agent-work.md)). So slice 2 first needs a deterministic answer to three questions: which units, why, to which version, and whether each one is breaking.

This change defines that answer and shows it in the scan report, without writing anything. The selection can be checked against real scans before the follow-up change, `fork-mode-delivery`, acts on it.

## What Changes

- **A selection step reads a scan record and the subject's policy,** and decides which **units** to prepare. A unit is a group of updates that the policy groups together, or a single update. Each run depends only on three inputs: the scanned commit of `main`, the date and the policy. Nothing is carried over between runs: an update that hasn't been merged is selected again for as long as its reason holds.
- **There are three reasons to select a unit:**
  - **Security:** an inventoried version has a known vulnerability with a fixed version, whether it is reachable or not. The evidence is the scan's own advisory sources: OSV, govulncheck (including the Go standard library) and Dependabot alerts. The target is the smallest version that fixes it. Security units are selected on every run.
  - **Lifecycle:** a version line in use reaches end of life within the policy's horizon, 90 days by default. The target is the oldest supported line whose end of life lies beyond the horizon. Lifecycle units are selected on every run.
  - **Batch:** every other in-scope candidate, in a monthly window that by default covers the first seven days of the month. The target is the newest version that has passed the minimum release age (7 days by default). Outside the window, no batch units are selected.
- **Holds win.** A hold in the policy blocks any unit, including a security fix. A held security fix is reported prominently as "vulnerable, fix held by policy", with the rule that holds it. A held end-of-life move is reported as an early warning. An advisory with no fixed version is reported as having no route.
- **Breaking mark.** Each unit is marked breaking or routine, deterministically. A major update, an end-of-life move, or an update that the source flags as breaking counts as breaking. In `fork-mode-delivery`, the mark decides whether a deterministic applier or the agent does the work.
- **Missing data is reported.** A reason that can't be evaluated because data is missing, such as an unknown release date or missing lifecycle data, is reported as not evaluated, with the reason. It is never left out silently, and missing data never selects or excludes a unit on its own.
- **`--unit <name>`** adds a named unit by hand, with the reason "requested", for trials.
- **`--as-of <date>`** evaluates the window and the horizon for a given date. That makes runs reproducible and the rules testable against fixtures.
- **Preview.** The scan record gains a versioned selection section, and the Markdown report a "Would prepare" section. For each unit they show its reason, its targets, its breaking mark and the evidence behind them. Warnings, held fixes and anything that couldn't be evaluated are listed separately.
- **Policy values.** Groups and holds stay in the update policy (`.github/renovate.json5` in the subject, with the trial copy in `policies/`), evaluated by our own code. The window, horizon and minimum release age go in a small selection policy file next to it, with a trial copy here too.
- **Out of scope,** for `fork-mode-delivery` or later:
  - applying updates;
  - the deterministic check after applying;
  - fork, PRs and any write credential;
  - reading CI results;
  - the agent;
  - merge decisions.

## Capabilities

### New Capabilities
- `update-selection`: decides and reports which units the system prepares, with the reason, targets and breaking mark for each. It also reports held security fixes, early warnings and anything it couldn't evaluate.

### Modified Capabilities
- `dependency-scan`: the record must also carry what selection needs:
  - for each update type, the newest version that has passed the minimum release age, alongside the newer versions still pending;
  - whether the source flags an update as breaking;
  - a policy classification for an advisory's fixed version, which needn't be a newest candidate.

  The report gains the preview section.

## Impact

- **Code:** a selection module beside `src/sdlc/record.py`, built on the scan's advisory and lifecycle data and on the policy evaluator in `src/sdlc/policy.py`. The evaluator also learns the policy's group rules. There are also additions to the Renovate normalisation, the record schema (a new version, after the one `retire-dependabot-pr-comparison` introduces) and the report renderer. Selection is a pure function of the record, the policy and the date, so it can be tested completely against fixtures.
- **Renovate:** only used for discovery and lookups, as in slice 1. The scan's lookup configuration gains the minimum release age, so that Renovate reports the newest version that has passed it. Renovate's `vulnerabilityAlerts`, `osvVulnerabilityAlerts` and `schedule` are not used.
- **Policy:** the trial policy's weekly `schedule` loses its meaning and is removed, and a trial selection policy file is added. The subject only changes when the maintainer adopts the policy.
- **Credentials and subject:** no new credentials and no writes. This change stays within slice 1's read-only boundary.
