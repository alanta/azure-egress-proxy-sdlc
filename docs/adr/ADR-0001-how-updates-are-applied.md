# How updates are applied

## Status
Accepted. Partly superseded by [ADR-0002](ADR-0002-deterministic-decisions-agent-work.md): our own code, not Renovate, selects, applies and delivers updates. The fork, the draft PRs, the credentials and the validation by the subject's CI still stand.

## Created / Updated
10-Oct-2026

## Deciders
Marnix van Valen

## Context
Slice 2 starts by turning an update candidate from the scan record into a change, then checking that change against the affected outputs. Slice 1 runs Renovate on its `local` platform, and that platform only supports the `extract` and `lookup` dry runs. Its docs say "branch creation is not supported", and asking for `dryRun=full` falls back to `lookup`. So the slice 1 setup can find updates but can't make them, and something else has to apply them.

The choice also settles where the change lives and where it's validated. That ties it to an open question in the README: branch in the subject repository or fork?

Facts about the subject that the options depend on:
- Its CI (`ci.yml`) runs on `pull_request` with `contents: read` and uses no secrets. A PR from a fork therefore gets the same checks as a PR from a branch.
- `deploy.yml` and `allowlist.yml` request `id-token: write` to sign in to Azure.
- Workflows from fork PRs need approval for first-time contributors (`approval_policy: first_time_contributors`).

Renovate can be steered a long way through configuration, but it has no plugin API. A new kind of manager, datasource or versioning scheme means changing Renovate itself. The options that use Renovate (1 to 5) can all rely on these extension points:
- **`customManagers` (`regex`, `jsonata`) and `customDatasources`:** find dependencies it doesn't know and look up versions from any URL. Slice 1 already uses custom managers.
- **`packageRules`:** decide what is updated, grouped or held.
- **`postUpgradeTasks`:** self-hosted only, limited to an `allowedCommands` list. These run commands on the update branch, per update or per branch (`executionMode`), and commit the files that `fileFilters` selects.
- **PR body and commit templates** (`prBodyTemplate`, `prBodyDefinitions`, `prHeader`, `prFooter`): control what a PR says, including structured content the system can read back.
- **`draftPR`, `prConcurrentLimit`, `schedule`, `minimumReleaseAge` and `dependencyDashboardApproval`:** control when PRs open and how many are open at once.
- **Presets:** share configuration between this repository and the subject's policy file.

The statements below about Renovate's behaviour were checked against the source of the pinned image, `renovate/renovate:44.145.1`, unless they're marked as unverified.

## Decision drivers
* **Determinism.** A deterministic tool makes the change. An agent is only brought in where determinism can't do the job.
* **Same engine as the scan.** The engine that found a candidate should apply it, under the same policy file and a pinned, recorded version.
* **Credential scope and isolation.** This is a hard criterion: the system can change a security product that ships to the Azure Marketplace.
* **Validation fidelity.** Evidence should come from the checks that will gate the merge, not from a copy of them.
* **Complexity.** Count the moving parts this repository has to build, run and keep in step with the subject.
* **A clear point for an agent to pick up from.** An agent added later for repairs, or for sources no tool can update, must start from the same state the deterministic step left.
* **Noise on the subject.** That means what maintainers see in the subject's PRs, issues and branches.

## Considered options

### Option 1: Renovate dry run against GitHub, changes read from the logs

Run the pinned Renovate image with `platform=github`, `dryRun=full` and the scan's read-only token. In full dry-run mode, Renovate goes through branch creation without pushing. At debug level it logs every file it would commit, with full contents (`commitFilesToBranch` in `workers/repository/update/branch/commit.js`). The system rebuilds each unit's change from those log entries, applies it to a throwaway checkout and runs the affected checks locally.

**Pro:**
* No write credential and no extra infrastructure.
* The same engine, version and policy as the scan. Grouping and the change itself come from one place.
* Nothing is visible on the subject until we decide to deliver.

**Con:**
* The debug log isn't a supported interface. The code path is excluded from Renovate's test coverage and could change in any version. Pinning the version and testing against fixtures limits this, but every Renovate upgrade has to be checked.
* The PR body isn't logged, only its title, so release notes have to be fetched separately.
* Unverified: whether lock files (`updatedArtifacts`) are regenerated during a dry run, and whether a read-only token passes every GitHub call Renovate makes in full mode.
* Validation is local, so this repository needs a check runner and a map from changed paths to checks. That map can drift from `ci.yml`. The evidence also isn't the CI result that later gates the merge.
* Lock-file updates and local checks run code from the updated packages on our machine. They need a sandbox without credentials.
* Delivering the change as a PR is still a separate step, and it needs a write credential anyway.

### Option 2: Renovate on a throwaway local Forgejo

Start a Forgejo container, push the checkout at the scanned commit into it, and run Renovate in full mode with `platform=forgejo` (version 44.145.1 ships one). Fetch the branches it creates, then validate them locally as in option 1.

**Pro:**
* No write credential on GitHub.
* Renovate's normal, supported output: real branches and PR bodies with release notes.
* The same engine, version and policy as the scan.

**Con:**
* Adds a service to run, seed and tear down for every run.
* Release notes are fetched from github.com in any case, so a GitHub token is still needed.
* The same local check runner, path-to-check map, drift and sandbox needs as option 1.
* Delivering to GitHub is still a separate step that needs a write credential.
* It's the option with the most moving parts.

### Option 3: Self-hosted Renovate in fork mode, draft PRs to the subject

Run the pinned Renovate image with `platform=github`, the read-only token as `token`, and a `forkToken`. In fork mode, Renovate forks the subject into the token owner's account and keeps the fork's default branch in step with the subject. It then pushes update branches to the fork and opens PRs against the subject (`initRepo` and `createPr` in `modules/platform/github/index.js`). With `draftPR: true` and the dependency dashboard turned off, the only thing it writes to the subject is draft PRs. The subject's own CI validates each PR. The system reads the PRs and their check results into its record with read-only access.

**Pro:**
* The checks that gate the merge also produce the evidence. There's no local check runner, no path-to-check map to keep in step with CI, and no upstream code running on our machine.
* The same engine, version and policy as the scan. Renovate's PR bodies carry the release notes.
* The write credential can't push to the subject. Its write access is limited to the fork and to opening PRs.
* Fork PRs get no secrets and no Azure OIDC token, so a changed workflow in an update branch can't reach `deploy.yml`'s Azure sign-in. CI uses no secrets, so nothing is lost.
* It answers the branch-or-fork question, and it's the delivery that slice 2 needs in any case.
* `postUpgradeTasks` can make deterministic follow-up fixes on the update branch, such as regenerating a file or running a formatter, so an agent is only needed when those aren't enough.
* Clear pickup point: an agent starts from the fork branch, the unit and the failed check results.

**Con:**
* `forkToken` has to be a classic personal access token. Fine-grained tokens can't contribute to public repositories where the user isn't a member. A classic token with `public_repo` scope is broad, so it needs a dedicated machine account that owns nothing else and isn't a collaborator on the subject.
* Every run makes PRs on the subject. Until Dependabot is retired, the subject gets duplicate PRs alongside Dependabot's.
* Evidence depends on GitHub Actions running. The first PR's workflows need a maintainer's approval, because the machine account is a first-time contributor.
* The machine that holds the token becomes part of the open question of where the system runs. Until then it has to sit somewhere trusted, such as a keyring, like the scan token.
* Release notes in PR bodies are upstream text. They must be treated as untrusted data when the system reads them back.

### Option 4: Self-hosted Renovate, branches in the subject

Run the pinned Renovate image with a GitHub App installation token that can write to the subject. Renovate pushes branches to the subject and opens PRs there, which is its standard setup.

**Pro:**
* Renovate's simplest and best-documented setup. Installation tokens are short-lived and can be scoped per permission.
* Maintainers can push fixes to update branches directly.
* Validation by the subject's CI, with the same benefits as option 3.

**Con:**
* The system needs `contents: write` on the subject, and `workflows: write` to update pinned actions. That's the widest credential of all the options.
* An update branch in the subject can carry a workflow that runs on push, with access to the repository's OIDC token. Whether that reaches Azure depends on how tightly the federated credentials are scoped. Branch protection and environment rules would have to be reviewed and kept tight first, as the README's open questions already note.
* Branches pile up in the subject.

### Option 5: Mend Renovate hosted app

Install the Mend Renovate GitHub App on the subject. It reads `.github/renovate.json5`, opens PRs on its own schedule, and the subject's CI validates them.

**Pro:**
* Nothing to run. The question of where the system runs no longer applies to this step.
* Validation by the subject's CI.

**Con:**
* A third party holds write access to code, workflows, PRs, issues and checks on a security product.
* We don't choose or record the Renovate version, so the scan and the apply step can run different versions. That breaks the rule that every tool version is recorded.
* The scan's custom managers have to move into a preset the app can read. The schedule and the run trigger are Mend's.
* The system only watches. It can't decide when a unit is prepared, or which one.

### Option 6: Dependabot CLI, locally

Run `dependabot update` per ecosystem. It runs the updater in containers and writes `create_pull_request` events with the updated file contents to its output, without creating PRs. Unverified: whether the output always includes full file contents for every ecosystem we use.

**Pro:**
* No write credential. It's built to run locally.
* The same engine as the current baseline.

**Con:**
* A different engine from the scan, so candidates and groups won't match the record.
* It doesn't read the Renovate policy, and lacks the coverage the scan adds: Bicep modules, inline pip and the `go` directive.
* Dependabot is due to be retired.
* The same local validation costs as option 1.

### Option 7: Our own apply code per ecosystem

Edit files and run `dotnet`, `go get` and similar commands per ecosystem, driven by the scan record.

**Pro:**
* Full control over every change.

**Con:**
* The most code of any option. Lock files, central package versions and digests all have to be handled.
* It duplicates what Renovate already does well. Slice 1 rejected the same approach for discovery.

### Summary

| | 1 Dry-run logs | 2 Local Forgejo | 3 Fork mode | 4 Subject branches | 5 Hosted app | 6 Dependabot CLI | 7 Own code |
|---|---|---|---|---|---|---|---|
| Same engine and version as the scan | yes | yes | yes | yes | no | no | no |
| Write credential | none | none | fork + PRs (classic PAT) | subject write | third party, subject write | none | none |
| Validation | local copy | local copy | subject CI | subject CI | subject CI | local copy | local copy |
| Pieces we build and run | log parser, check runner | Forgejo, check runner | Renovate run, PR and CI reader | Renovate run, PR and CI reader | PR and CI reader | Dependabot runs, check runner | appliers, check runner |
| Supported interface | no | yes | yes | yes | yes | yes | n/a |
| Visible on the subject | no | no | draft PRs | branches, PRs | branches, PRs | no | no |

## Decision
The decision has been made to apply updates with **self-hosted Renovate in fork mode, opening draft PRs** (option 3). It uses a supported Renovate interface. It keeps the same pinned engine and policy as the scan. It takes evidence from the CI that will gate the merge, so this repository doesn't have to build and maintain a copy of the subject's checks. Its only write credential can't push to the subject. And fork PRs can't reach the subject's Azure OIDC sign-in, which branches in the subject (option 4) could.

Option 1 was the best of the options that make no writes at all. It was not chosen because it would need a local check runner and would depend on Renovate's debug log.

### Consequences
* Slice 2 no longer needs a local check runner or a path-to-check map. "Which outputs were validated" comes from the PR's check results, and the CI gaps fixed in the subject's #100 become essential.
* A dedicated machine account with a classic `public_repo` token, its fork, and a trusted place to keep the token are needed. The runtime research change has to take this credential into account.
* The subject gets draft PRs from the system alongside Dependabot's. This should be measured, and should feed into when Dependabot's version updates are switched off.
* A maintainer approves the machine account's first workflow run.
* The system drives Renovate with a config generated for each run, as the scan already does. Our code decides which units to prepare and switches everything else off. Renovate only makes the change and opens the PR, so the decisions stay in code we test and record.
* An agent added later picks up from a fork branch and its failed check results. The maintainer is open to giving that agent write access to the fork, but only with guardrails against prompt injection, because the agent reads untrusted upstream text such as release notes, changelogs and PR bodies. The change that brings in the agent decides those guardrails and the agent's credential. Until then, a deterministic step pushes the agent's commits.
* An agent is never started from `postUpgradeTasks`, whatever is decided about its credential. Those tasks run inside Renovate's process, outside any sandbox an agent would get, alongside both of Renovate's tokens.
* Lock-file updates and `postUpgradeTasks` run code from the updated packages wherever Renovate runs. That machine has to be isolated, which ties into the question of where the system runs.

### Potential next steps
* Verify fork mode with the pinned image against the subject: one draft PR, `dependencyDashboard: false`, the read-only `token` for reads, and the fork token used only for the fork and the PR.
* Decide how the system decides which units get a PR, and how many may be open at once (Renovate's `prConcurrentLimit` and the policy groups).
* Define the record that captures each unit's PR, diff, release notes and check results, versioned like the scan record.

## Links
* [README](../../README.md): slices, open questions (branch or fork, runtime and credentials)
* [Functional workflow](../functional-workflow.md): steps 4 and 5
* [Dependency scan spec](../../openspec/specs/dependency-scan/spec.md)
* [Renovate configuration options: `postUpgradeTasks`, `customDatasources`, `prBodyTemplate`, `draftPR`](https://docs.renovatebot.com/configuration-options/)
* [Renovate local platform](https://docs.renovatebot.com/modules/platform/local/)
* [Renovate self-hosted configuration: `dryRun`, `forkToken`, `forkOrg`, `forkCreation`](https://docs.renovatebot.com/self-hosted-configuration/)
* [Renovate security and permissions (Mend hosted app)](https://docs.renovatebot.com/security-and-permissions/)
* [GitHub fine-grained personal access token limitations](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
* [Dependabot CLI](https://github.com/dependabot/cli)
