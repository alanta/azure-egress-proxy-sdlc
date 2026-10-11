# Instructions for agents

This repository holds an SDLC system that keeps [`alanta/azure-egress-proxy`](https://github.com/alanta/azure-egress-proxy), the subject, up to date. The [README](README.md) covers its purpose, slices and decisions. This file covers how to work on it.

## Boundaries

- **The system lives here, and only here.** The scanner, the orchestration, agent prompts and configuration, record schemas, fixtures and run outputs all stay in this repository. Never put system code or configuration in the subject.
- **The subject holds its own code and the policies about that code**, such as its update policy in `.github/renovate.json5`. A trial copy of that policy lives in `policies/` until the maintainer adopts it in the subject.
- **Changes reach the subject only through PRs.** Never push to the subject's default branch.
- **The scan is read-only.** It uses a fine-grained token that can only read the subject ([running-a-scan.md](docs/running-a-scan.md) lists its permissions). Never use the `gh` CLI's token for a scan.
- **This repository is public.** Its Actions logs and artifacts are public too, so nothing non-public may be logged.

## Design principles

- **Deterministic code decides and checks; an agent may do the work** ([ADR-0002](docs/adr/ADR-0002-deterministic-decisions-agent-work.md)).
  - What to update, why, and to which version is always decided deterministically, and every gate is deterministic.
  - An agent does the work where doing it deterministically costs more than checking the agent's result deterministically.
  - An agent's output cites evidence and can never lower a risk score or relax a gate.
- **Upstream text is untrusted data.** That includes release notes, changelogs, PR bodies and advisories.
- **Unknown is reported as unknown.** A source that was missing, skipped or unavailable is reported as such, never as success or as "nothing found".
- **Reuse tools before writing code.**
  - Renovate is the engine for discovery and lookups. Extend it through configuration (custom managers, presets) before adding code of our own.
  - To apply an update, use the ecosystem's own CLI where there is one.
  - Keep decisions out of tool-specific semantics, so that a tool can be replaced.
- **Pin and record every tool.** External tools run in containers pinned by digest, and the record names each version.

## Tech and commands

Python 3.12+ with [uv](https://docs.astral.sh/uv/). Use Python for new tooling, not TypeScript.

```bash
uv sync
uv run pytest
uv run ruff check && uv run ruff format --check
uv run sdlc scan --help
```

How to run a scan and read its output: [docs/running-a-scan.md](docs/running-a-scan.md). Containers run under docker by default; set `SDLC_CONTAINER_RUNTIME=podman` for podman.

Pitfalls already solved in the Renovate integration (see the comments in `src/sdlc/renovate.py` and `src/sdlc/config/scan.renovate.json5`):
- Renovate's local mode reads only git-tracked files, so the trial policy is committed into the throwaway checkout.
- A `/regex/` file pattern that contains a `/` silently matches nothing. Use globs.
- NuGet versioning reads a bare `1.2.3` as a range, so a custom NuGet manager needs `versioningTemplate: "semver"`.
- Containers that write files need `--userns=keep-id` under podman, or `--user uid:gid` under docker.

## Planning with OpenSpec

- **Every change goes through an OpenSpec change** in `openspec/changes/`: proposal, specs, design, then tasks. Use the CLI (`openspec new change`) to create one, never by hand.
- **The specs in `openspec/specs/` describe the system as it is.** A change updates them when it's archived.
- **Architecture decisions are ADRs** in `docs/adr/`, written from [the template](docs/adr/ADR-template.md).

## Documentation

- **Documents describe the current state.** Don't add "Update …" sections, dated notes or change logs. Git holds the history.
- **When a decision changes, rewrite the text that states it.** Don't append the new decision next to the old one.
- **Evidence from a specific commit says which commit it describes**, such as a scan of `064aa09`. That's what it records, not a change log.

## Git and GitHub

- **Work on a branch and commit as you go.** Small commits that can be squashed later are better than losing a state to go back to. `main` only changes through PRs.
- **PRs are squash-merged,** and the PR title and body become the commit message.
- **Start every commit subject and PR title with a Gitmoji** (https://gitmoji.dev), as the Unicode emoji followed by a space. For example `✨` for a feature, `🐛` for a fix, `📝` for docs, `♻️` for a refactor, `✅` for tests, `🔧` for config, `⬆️` for an upgrade, `🔒️` for security.
- **Messages explain why, and briefly what the change achieves.** Never list what changed: the diff shows that. Keep them short.
- **No AI attribution.** No `Co-Authored-By` trailers for AI tools, and no "Generated with …" lines, in commits or PRs. This repository and the subject are public.
- **Stacking PRs is fine.** If a PR still conflicts after the one below it has been squash-merged, move the rest of the stack with `git rebase --onto origin/main <old-base-branch> <top-branch> --update-refs`, then `git push --force-with-lease` each moved branch.

## Working with the maintainer

- **A stated preference is not a constraint.** When new facts change the trade-offs, lay out the options again, including ones set aside earlier, and let the maintainer decide.
- **Quality over speed.** Every task that changes logic gets a review round. If the work can't be finished well in one session, stop at a clean point.
- **Choose a subagent's model by what the task needs.** Use the strongest model for subtle logic (classification, parsing untrusted input, security checks) and for reviewing it. Use a lighter one for runs, docs and mechanical changes.
- **Test a how-to by having a fresh agent follow only that document.**
