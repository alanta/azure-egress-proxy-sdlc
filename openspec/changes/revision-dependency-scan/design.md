# Design

## Context

See `proposal.md` for why, and `specs/dependency-scan/spec.md` for the required behaviour.

Constraints that shape the approach:

- **Separate repositories.** The SDLC system lives here. The subject repository holds the code being maintained and its update policy, nothing else of this system. The scan works on a copy of the subject at a commit; later slices branch, change, test and merge back through a PR.
- **Where it eventually runs is open.** A GitHub Actions job, a cloud job and a home machine are all candidates, decided in a later change. The scan must not depend on one of them.
- **What already exists.** `docs/azure-egress-proxy-dependency-pass.md` is the manual inventory of the subject at `064aa09`. `docs/tooling-spike.md` ran Renovate, OSV-Scanner and native NuGet queries against it. Renovate found 191 entries across 30 files. It doesn't read AVM module tags, the inline PyJWT install or Packer plugins, and its output was only checked as log text.
- **Dependabot is the baseline, and is expected to go away.** Until then, the scan has to be measurably at least as good.

## Goals / Non-Goals

**Goals:**

- Reuse existing tools for discovery and lookups. Our own code merges, classifies and compares their results.
- Make every gap visible: an unsupported source, a failed lookup, an unreadable advisory source, an unparseable PR.
- Make parity with Dependabot something a run measures, not something we assume.

**Non-Goals:**

- No LLM in this slice. Nothing here needs judgement, and leaving it out keeps the scan deterministic.
- No risk assessment, release-note summaries, builds or check-state analysis (slice 2).
- VM image inputs (platform image version, Packer plugins, OS packages) until the image build exists in the subject repository. Until then, a Packer template is reported as an unsupported source.
- Platform migrations, such as moving .NET from 10 to 11. The scan reports the candidates; the policy holds them.

## Decisions

### 1. Containerised tools behind one CLI

A Python CLI orchestrates the scan. Each external tool runs in a container pinned by digest: Renovate, OSV-Scanner, and the .NET SDK and Go images for the native queries and govulncheck. The subject is cloned at the commit into a temporary directory and mounted read-only wherever a tool allows it.

Python, because the scan is mostly JSON plumbing, the Claude Agent SDK that slice 2 will likely use has a Python SDK, and the spike's environment already uses it.

Containers keep tool versions exact and recorded, and make the scan portable to whichever runtime we choose later.

**Alternatives:** tools installed on the host make tool versions drift between machines. A single all-in-one image hides which tool version produced which result.

### 2. Renovate is the main discovery and lookup engine

Renovate runs with `--platform=local --dry-run=lookup` and a read-only token, writing its report as a file (`reportType=file`). It covers NuGet, Go modules, Dockerfiles, GitHub Actions and devcontainer features in one pass, and finds patch, minor and major candidates per dependency.

The gaps get Renovate `customManagers` in the scan's own configuration, not new adapters:

- inline `pip install "PyJWT[crypto]==…"` → regex manager with the PyPI datasource;
- `br/public:avm/...` module tags → regex manager with the Docker datasource on `mcr.microsoft.com/bicep/avm/...`, where the public Bicep registry publishes its modules;
- devcontainer tool versions such as the Aspire CLI → regex manager with the matching datasource.

Managers that apply to any repository live in this repository's scan configuration. Managers that describe one subject's own files, such as the Aspire CLI `ARG` in the devcontainer, live in that subject's policy file (decision 4), next to the code they describe. Renovate combines both.

Task 1.3 verifies the report-file output, and task 1.4 the custom managers. If the report file proves incomplete, the fallback is Renovate's JSON logs (`LOG_FORMAT=json`), parsed by message type. A custom manager that can't be made to work leaves its source reported as unsupported.

**Alternatives:**
- **Dependabot CLI:** the same engine as Dependabot, so parity would come by construction, but so would Dependabot's gaps (Bicep modules, inline pip, the Go directive).
- **Our own parsers per ecosystem:** far more code, and worse coverage than a tool that already handles lockfiles, digests and version schemes.

### 3. Native queries cross-check Renovate

`dotnet list package --outdated --include-transitive` after a locked restore, and `go list -m -u -json all`, run on the same copy. Where they disagree with Renovate, the record says so. This catches a Renovate blind spot before it becomes a missed update, and costs one container run each. It can be dropped later if it never finds anything.

### 4. The update policy lives in the subject repository, in Renovate's format

There is no cross-tool standard for update policy. `dependabot.yml` and Renovate's config are tool-specific formats, and Renovate's is the more expressive one. It can hold a .NET-runtime-coupled NuGet major (`packageRules` with `matchUpdateTypes: ["major"]` and `allowedVersions`), ignore a dependency, and group updates.

So the policy is `.github/renovate.json5` in the subject repository: JSON5 allows a comment with the reason next to each rule. The scan reads it at the scanned revision, so a policy change is reviewed in the same PR as the code it affects.

Until the maintainer merges a policy into the subject, a trial policy kept in this repository is supplied explicitly per run (task 3.2). The record names whichever file was used. The scan places the trial file in its disposable copy of the subject and commits it there, because Renovate's local mode only reads tracked files. The subject repository itself is not touched.

The file is inert while no Renovate app is installed on the subject repository. When Dependabot is retired, the same file can drive Renovate directly, if that is the route taken.

An invalid policy fails the scan: falling back to "everything in scope" would widen the policy silently.

The autonomy and merge policy of slice 3 is a separate concern, and gets its own file when that slice is designed.

**Alternatives:**
- **Our own YAML format:** it would still need translating into Renovate's rules to drive the lookups.
- **Policy in this repository:** rejected by the maintainer; the policy stays with the code it governs.

### 5. Advisories come from OSV-Scanner, govulncheck and Dependabot alerts

- **OSV-Scanner,** pinned, scans the lockfiles: `packages.lock.json` and `go.sum`. Packages without a resolved version are reported as unknown, which the spike already saw.
- **govulncheck** runs with the toolchain `go.mod` declares and supplies reachability for Go. Every other ecosystem's reachability is `unknown`.
- **Dependabot alerts** are read through the API when the credential has `Dependabot alerts: read`. Otherwise they are listed as an unavailable source. They are a comparison source, the same way open PRs are.

Image OS packages are not scanned here. That arrives with the image build, which already plans Syft and Grype.

### 6a. Lifecycle data comes from endoflife.date

The public endoflife.date API publishes support and end-of-life dates for Go, .NET, Python, Alpine, Debian and many other products, with no account needed. A mapping table in this repository links inventory entries to its product names: the Go toolchain, .NET SDK and runtime images, `python` and `alpine` tags, and distroless `debian12`. Entries without a mapping report `unknown`.

Renovate knows versions, not support windows. Without this, staying on a line that no longer gets security fixes looks the same as being up to date within that line, which is what happened with Go 1.25.

**Alternative:** maintaining dates by hand goes stale without anyone noticing.

### 6. A small alias table drives the consistency check

Logical dependencies declared through different ecosystems are listed in a table in this repository:

- **Go toolchain:** the `go` and `toolchain` directives, `setup-go` `go-version`, and `golang` image tags.
- **.NET SDK and runtime:** `global.json`, `setup-dotnet` `dotnet-version`, and `mcr.microsoft.com/dotnet/*` tags.
- **Aspire:** the AppHost SDK version and the CLI version in the devcontainer.

Versions are compared at the precision each declares: `1.25` agrees with `1.25.14`, and `1.25` disagrees with `1.27`. The table is extended when a missed inconsistency is found.

**Alternative:** inferring aliases automatically produces false matches across unrelated packages, and there are only a few of these.

### 7. Dependabot parity reads commit metadata first

Open PRs by `dependabot[bot]` are read with the read-only credential:

- **Names, target versions and groups** come from the `updated-dependencies` YAML block Dependabot writes in its commit messages. The block doesn't always carry an update type (the grouped Docker PR #76 has none), so the update type is derived from the from- and to-versions.
- **From-versions** come from the `Updates <name> from A to B` lines in the PR body, or the title for a single update, matched with fixed patterns only. PR text is never interpreted beyond that.
- **Unparseable PRs** are reported as such.

A PR is current for the revision when its from-versions equal the versions declared in the scanned revision or resolved in its lock files; otherwise it is stale. Lock files count because Dependabot also updates transitive versions: #77 moves AppHost's locked `Microsoft.Extensions.Http` from 10.0.11 to the 10.0.12 already declared centrally.

Parity holds only at a point in time, because registries move. So the PR list and the lookups are captured in the same run, and both times are recorded.

### 8. One record, one schema, Markdown rendered from it

- The record is JSON and validated against a versioned JSON Schema in this repository.
- The Markdown report is rendered only from the record.
- Runs write to a run directory outside the subject repository, by default `runs/<repo>/<commit>/<timestamp>/`, which is git-ignored.
- Runs chosen as evidence are copied under `fixtures/` and committed.

### 9. Untrusted text is data

Release notes, PR bodies and changelogs come from upstream authors, not the maintainer. In this slice they are only matched by fixed patterns. That rule carries into slice 2, where an agent reads them: text read from a source never lowers a risk score or relaxes a gate.

## Risks / Trade-offs

- **Renovate's local platform is experimental** → pinned by digest, native cross-checks (decision 3), and the JSON-log fallback. An upgrade is a reviewed change with a parity run.
- **Lookups hit rate limits** → a read-only token. Failed lookups are `unknown`, so the record shows the damage instead of reporting "up to date".
- **The AVM regex manager doesn't resolve through MCR** → AVM tags stay reported as unsupported. A small adapter that queries the registry's tag list can follow.
- **Dependabot's PR format changes** → affected PRs become `unparseable`, and the parity result says it is incomplete.
- **`dependabot.yml` and the trial policy disagree while both exist** → disagreements show up as `held by policy` or scan-only entries, which is useful evidence for retiring Dependabot.
- **A tool reports nothing for a source it doesn't understand** → the scan detects dependency-bearing files by pattern itself (task 2.3), so silence from a tool doesn't hide a file.

## Migration Plan

Nothing is deployed. The subject repository gains `.github/renovate.json5` only through a PR the maintainer reviews, after the trial policy has been checked against real scans. Discontinuing the scan means removing this code. The subject loses at most an inert policy file.

## Open Questions

- Whether read access uses a fine-grained token or a GitHub App installation token. Both work for this slice; the choice belongs with the runtime decision.
- Retention of run directories. Irrelevant while runs are local and git-ignored.
