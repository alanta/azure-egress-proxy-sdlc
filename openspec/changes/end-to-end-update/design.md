# Design

## Context

The scan already gives, for each dependency, the file and location of every declaration, its candidates, and its lock-file state. `update-selection` adds units with their reasons, targets and breaking marks. The scan runs its tools in pinned containers, through docker or podman. Its throwaway checkout is in `src/sdlc/subject.py`, and the .NET and Go images in `src/sdlc/native.py`. The subject's CI runs on `pull_request`, uses no secrets, and needs a maintainer's approval for a first-time contributor's first run.

The guiding rule is the planning principle in AGENTS.md: every part is the simplest version that is still real, and grows when a run shows it needs to.

## Goals / Non-Goals

**Goals:**
- A `prepare` run that takes the real subject from scan to draft PRs, and reads their CI back on the next run.
- Every step recorded, so that a run can be understood afterwards without logs.
- The agent contained by the sandbox and the check, not by trusting what it does.

**Non-Goals:**
- Speed. Re-scanning per unit and rebuilding branches are fine at this size.
- Running unattended. Runs are started by hand from the maintainer's machine.
- Release notes, retries beyond one repair, and a richer diff policy. These come in improvement rounds once runs show what's needed.

## Decisions

### 1. One `sdlc prepare` command, writing to its own run directory

`sdlc prepare --repo <subject> --trial-policy <file>` runs the scan with selection, then takes each unit through apply, check and deliver, then reads CI for the open PRs. It writes `prepare.json` and `prepare.md` next to the scan's own record, in the scan's run directory. The prepare record references the scan record by path and commit, so it doesn't copy it.

**Alternative:** separate commands per step. That would need state passed between them, and the skeleton has no use for running a step alone.

### 2. A unit's change is identified by its base commit and targets

Each unit's branch is `sdlc/<unit name>`. A trailer in the branch's last commit records the scanned commit it was built on, the targets, and whether a repair has been made (`Sdlc-Base`, `Sdlc-Targets`, `Sdlc-Repair`). On each run:
- **Same base and targets:** the change is not rebuilt. The run only reads CI, and repairs once if CI failed and no repair has been made yet.
- **Anything else:** the change is rebuilt from the new scanned commit, and the repair count starts again.

This keeps the system stateless: the state is the branch on the fork, which anyone can inspect. It also gives "push only when the content changed" without comparing trees.

### 3. The generic applier edits recorded locations, then lets each ecosystem refresh its lock files

For each target, the applier replaces the exact current value at the recorded file and line, and nowhere else. If the current value isn't on that line, the unit fails to apply rather than guessing. Then it refreshes the lock files in the same pinned images that `native.py` uses:
- **NuGet:** `dotnet restore --force-evaluate`, for the solution that contains the changed file;
- **Go:** `go mod tidy`, in each changed module.

These targets are reported as "no applier yet":
- digest pins (`update_type: digest`, or a value with `@sha256:` or a 40-character SHA);
- a dependency that only appears in a lock file and has no declaration line.

**Alternative:** each ecosystem's own update command, such as `dotnet add package` or `go get`. These are more exact for their own ecosystem, but each needs its own code, and the recorded location already says where the version lives. They can replace the line edit one ecosystem at a time, once a run shows the line edit isn't enough.

### 4. The check reuses the scan's inventory, without lookups

The check runs the scan's inventory stage on the branch: Renovate in `extract` mode, plus the native lock-file reads. It compares the result with the base scan's inventory. It passes only when every dependency in the unit is at its target in every declaration, and every other dependency is unchanged. It also checks that the lock files show no drift the base didn't have. Lookups are skipped, so the check makes no registry queries and is fast enough to run per unit.

The diff policy is one rule: any changed path under `.github/workflows/` or `infra/` marks the change "needs review". The machine account isn't a collaborator on the subject, so it can't set labels there. The mark therefore goes into the PR title, as a `[needs review]` prefix, and into its body.

### 5. The agent is Claude Code headless, in a container behind an allowlisting proxy

- **The image** is built from a Dockerfile in this repository, on pinned bases: Claude Code at a pinned version, plus the .NET SDK and Go toolchains the subject builds with.
- **How it runs:** `claude -p` with a prompt from a template in this repository (`apply` or `repair`), `--output-format json`, and a pinned `--model`. The prompt contains:
  - the unit, its targets and the scan's evidence;
  - for a repair, the current diff and the failed checks' output.
- **Permissions:** `--dangerously-skip-permissions`, because the container, not Claude Code's permission prompts, is the boundary.
- **Files:** the checkout is mounted read-write, with its git remotes removed.
- **Credential:** the only one is `CLAUDE_CODE_OAUTH_TOKEN`, read from the keyring at run time. `ANTHROPIC_API_KEY` is explicitly unset, because it would take precedence.
- **Network:** the container sits on an internal network whose only way out is a small forward proxy container (tinyproxy) with an allowlist. The list holds the model API, NuGet, the Go module proxy and checksum database, and the image registries the build needs. `HTTP(S)_PROXY` points at the proxy. Traffic that ignores the proxy has no route out.
- **What's kept:** only the checkout's files are taken from the run, and they go to the check.
- **What's recorded:** the JSON result, with the model, turns, cost and session id.

**Alternative:** no network limit in the skeleton. Simpler, but a sandbox that can reach anything isn't the containment ADR-0002 depends on, and the proxy is a few lines of configuration.

### 6. Delivery through git and the GitHub REST API, with the machine account's token

The branch is pushed to the machine account's fork over HTTPS, with the token passed through a one-shot credential helper and never written to disk. The PRs are opened, updated and closed through the REST API with the same token:
- a PR is found by its head, `<machine account>:sdlc/<unit name>`;
- its body is rendered from the prepare record;
- closing it adds a comment with the reason.

CI results are read with the scan's read-only token, through the check runs of the PR's head commit. Both tokens come from the keyring, like the scan's token today.

### 7. A prepare record schema of its own

`prepare-record.v1.json` holds, for each selected unit:
- its outcome and PR link;
- each step taken (applier or agent, with the model and the hash of the prompt);
- the check result with the dependencies it compared;
- the "needs review" mark;
- the CI state.

The Markdown report is rendered from it, like the scan's.

## Risks / Trade-offs

- [The agent writes outside the unit's scope, or quietly weakens a test] → The check catches version changes. The `[needs review]` mark catches workflow and infra changes. Everything stays a draft PR for a human, and agent work never merges on its own. Weakened tests are the gap. The record shows which files the agent changed, and a richer diff policy is the first improvement if runs show it.
- [CI output given to a repair contains text an upstream package wrote] → The repair only gets output from the subject's own builds and tests, never release notes. The sandbox holds no GitHub credential and has no route except the allowlist, and the check gates the result.
- [The classic token can write to every public repository the machine account can reach] → The account owns nothing but the fork, and is no collaborator anywhere. The token lives in the keyring and only reaches git through the credential helper.
- [The subscription's usage limits are shared with the maintainer's own use] → One attempt per breaking unit and one repair per change keep the use small. The record holds each run's cost, so the next improvement can be based on it.
- [The first PRs stay pending until a maintainer approves the account's first CI run] → Pending is reported as pending, and the how-to says so.
- [The line edit misses a version that's written differently from how the scan recorded it] → The unit fails to apply, saying where. That is the signal to move the ecosystem to its own update command.
