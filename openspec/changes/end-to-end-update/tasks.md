# Tasks

This change builds on `update-selection`. Start once that change is done, and stack on its branch if it hasn't merged yet.

## 1. Prerequisites (the maintainer)

- [ ] 1.1 Create the machine account, and fork the subject into it. Create its classic token with only the `public_repo` scope, and store it in the GNOME keyring. Verify that the token can push to the fork, and that `GET /repos/alanta/azure-egress-proxy/collaborators/<account>` doesn't list the account.
- [ ] 1.2 Run `claude setup-token` and store the token in the keyring. Add `Pull requests: read` back to the scan's read-only token. Verify with `claude -p "say ok"`, using only `CLAUDE_CODE_OAUTH_TOKEN`, and with a read of the subject's open PRs using the scan's token.

## 2. Prepare run and record

- [ ] 2.1 Define `prepare-record.v1.json` (decision 7). Verify that schema tests accept a record with each outcome and reject an unknown outcome or a delivered unit without a PR link.
- [ ] 2.2 Add `sdlc prepare`. It runs the scan with selection, writes an empty prepare record and report next to the scan's, and reads its tokens from the keyring the way the scan does. Verify with `tests/test_cli.py` that a run on fixtures writes both files, and that a missing token fails before anything is written.

## 3. Applying routine units

- [ ] 3.1 Build a unit's change on a fresh branch from the scanned commit in a disposable checkout. Write the `Sdlc-Base`, `Sdlc-Targets` and `Sdlc-Repair` trailers, and skip rebuilding when an existing branch has the same base and targets (decision 2). Verify with tests on a local git repository: rebuild when `main` moves, skip when it hasn't.
- [ ] 3.2 Implement the generic applier (decision 3): exact replacement at the recorded line, failing when the value isn't there, then the lock-file refresh for NuGet and Go in the pinned images, and "no applier yet" for digest pins and dependencies without a declaration line. Verify with tests on a fixture copy of the subject: a central NuGet version with lock files, a Go module, a Dockerfile tag, an action pinned by SHA, and a value that isn't on its recorded line.

## 4. Check

- [ ] 4.1 Implement the check (decision 4): the inventory stage on the branch, compared with the base inventory, plus the lock-drift comparison, plus the `.github/workflows/` and `infra/` rule. Verify with tests: a change that reaches its targets passes, one that raises another dependency fails naming it, one that leaves new lock drift fails, and one that touches a workflow is marked "needs review".

## 5. Delivery and CI

- [ ] 5.1 Push a checked branch to the fork through the one-shot credential helper, and open or update the unit's draft PR with a body rendered from the record and a `[needs review]` title prefix where it applies. Verify against a scratch repository and fork owned by the machine account: the token is never written to disk, the PR is a draft, and an unchanged unit pushes nothing.
- [ ] 5.2 Close the PR of a unit that's no longer selected, with a comment giving the reason, and leave batch PRs alone outside the window. Verify on the scratch repository, for a closed unit and for a batch PR outside the window.
- [ ] 5.3 Read the check runs of each open PR's head commit with the scan's token into the record, as passed, failed, pending or unknown. Verify with tests on recorded API responses for each state, including a failed read.

## 6. Agent

- [ ] 6.1 Build the sandbox (decision 5): the agent image on pinned bases, the internal network, and the allowlisting proxy. Verify that Claude Code answers from inside the container, that `curl https://example.com` fails, that `dotnet restore` and `go mod download` succeed through the proxy, and that the container's environment holds no GitHub token or `ANTHROPIC_API_KEY`.
- [ ] 6.2 Give breaking units to the agent with the `apply` prompt, and record the step, the model, the prompt's hash and the JSON result. Its files then go to the check. Verify on the scratch repository with a breaking unit: the agent's change is checked, and its record entry is complete.
- [ ] 6.3 Repair a unit with failed CI once, with the `repair` prompt, the diff and the failed checks' output. A unit that fails again is reported as failed. Verify with tests on the trailers and recorded check runs: a first failure leads to one repair, and a failure after a repair leads to none.

## 7. Report and how-to

- [ ] 7.1 Render the prepare report: each unit with its outcome, PR link, steps and check result, and the "needs review" marks. Verify with `tests/test_report.py`-style tests that every part of a fixture prepare record appears.
- [ ] 7.2 Write `docs/running-a-prepare.md`: the prerequisites, how to run a prepare, how to read its report, the first-run approval, and what to do with each outcome. Verify that a fresh agent can follow it to run a prepare on the scratch repository.

## 8. End-to-end

- [ ] 8.1 Run `sdlc prepare` against the subject's `main` with the trial policy. Approve the machine account's first CI run, then run again. Verify that each selected unit ends with a recorded outcome, that the delivered units have draft PRs with CI results in the record, and that a breaking unit went to the agent. Record what you learn as issues for the improvement rounds, not as silent fixes.
