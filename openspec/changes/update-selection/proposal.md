# Proposal

## Why

Slice 1 lists every update candidate for a revision, but it doesn't say which of them are worth preparing. Updating everything every week, as Dependabot does, causes churn without reducing risk. Slice 2 applies updates as draft PRs from a fork ([ADR-0001](../../../docs/adr/ADR-0001-how-updates-are-applied.md)), and it first needs a deterministic answer to "which updates, and why".

Renovate can make most of these decisions itself, from the subject's policy: security fixes, a batching schedule and a minimum release age. What it can't do is know about end-of-life dates, report a security fix that the policy holds back, or show its plan before it acts. This change sets the policy up for that and adds the missing pieces to the scan, without writing anything. The follow-up change, `fork-mode-delivery`, then acts on a policy whose effect can already be seen in real scans.

## What Changes

- **Update policy.** The policy's selection rules move to Renovate's own options. This applies to the trial policy in `policies/`, and to the subject's `.github/renovate.json5` once the maintainer adopts it:
  - **Security:** `vulnerabilityAlerts`, which reads GitHub's Dependabot alerts, and `osvVulnerabilityAlerts`, with the default `vulnerabilityFixStrategy: lowest`. Security fixes skip the schedule and the PR limits, whether the vulnerability is reachable or not.
  - **Everything else:** batched in a monthly `schedule` window instead of weekly. `updateNotScheduled: false` keeps open PRs unchanged between windows, so a fast-releasing package doesn't cause churn.
  - **Minimum release age:** `minimumReleaseAge` (7 days) with `internalChecksFilter: strict`, for the datasources that provide release timestamps. Since Renovate 42, a release without a timestamp never passes the minimum age, so the rule must not apply to the others.
  - **Holds:** they stay as they are. A security fix that a hold blocks is not raised. A hold doesn't give way to a security fix.
- **Lifecycle.** The scan's lifecycle data (endoflife.date) decides when a version line reaches end of life within the policy's horizon, 90 days by default. When the policy allows the move, the scan selects it and names the extra rule that takes it out of the schedule; `fork-mode-delivery` passes that rule to Renovate. When the policy holds the move, the scan reports an early warning. The horizon lives in a small policy file next to `.github/renovate.json5`, because Renovate rejects options it doesn't know.
- **Held security fixes.** A vulnerability whose fixed version the policy holds is reported prominently as "vulnerable, fix held by policy", with the rule that holds it. The evidence comes from the scan's own advisory sources: OSV, govulncheck and Dependabot alerts. An advisory with no fixed version is reported as having no route.
- **"Would prepare" preview.** The scan record gains a section, and the report gains a section, listing which PRs the policy will open or keep and why. The reasons are security, lifecycle or the scheduled batch. The security part comes from the scan's own advisories, because Renovate can't read GitHub's alerts in lookup mode. A reason that can't be evaluated because data is missing is reported as not evaluated, with the reason, never left out.
- **`--as-of <date>`** evaluates the schedule and the lifecycle horizon for a given date. That makes runs reproducible and the rules testable against fixtures.
- **Checks first.** Three things are verified with the pinned image before anything relies on them:
  - whether holds that use `allowedVersions`, not only `enabled: false`, also block security fixes;
  - that Renovate leaves existing branches alone outside the schedule window;
  - how images without release timestamps behave under `minimumReleaseAge`.
- **Out of scope**, planned for `fork-mode-delivery` or later:
  - running Renovate to make changes;
  - fork mode, PRs and any write credential;
  - reading CI results;
  - comparing the preview with the PRs Renovate actually opens;
  - the agent;
  - merge decisions.

## Capabilities

### New Capabilities
- `update-selection`: decides and reports which updates the system prepares. This covers the policy's selection rules and the lifecycle reason. It also reports held security fixes, early warnings, anything it couldn't evaluate, and the "would prepare" preview.

### Modified Capabilities
- `dependency-scan`: the record must also carry two things:
  - the branch, and therefore the unit, that each candidate belongs to;
  - a policy classification for an advisory's fixed version, which needn't be the newest candidate.

  The report also gains the preview section.

## Impact

- **Code:** a selection module beside `src/sdlc/record.py`, built on the existing advisory and lifecycle data and on the policy evaluator in `src/sdlc/policy.py`. It also needs additions to the Renovate normalisation, the record schema (a new version, after the one `retire-dependabot-pr-comparison` introduces) and the report renderer.
- **Policy:**
  - In `policies/azure-egress-proxy.renovate.json5`, the weekly `schedule: ["on monday"]` becomes the monthly window, and the options above are added.
  - The lifecycle horizon gets its own small file.
  - The subject only changes when the maintainer adopts the policy.
- **Renovate:** stays at the pinned version. The checks above cover the behaviour this change relies on.
- **Credentials and subject:** no new credentials and no writes. This change stays within slice 1's read-only boundary.
