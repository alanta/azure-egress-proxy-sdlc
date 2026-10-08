# Tooling spike: report-only dependency assessment

- **Date:** 2026-10-06
- **Subject snapshot:** `alanta/azure-egress-proxy` `main` at `064aa099ecf7ffea9664b89df29f7d89d6859358`
- **Mode:** Exploratory only. Tools ran against a disposable copy; no files in the subject repository were changed.

## Questions tested

- What does Renovate discover beyond native package-manager queries, and can it cover the non-package inputs in this repository?
- Can source vulnerability scanning provide usable, machine-readable evidence alongside existing checks?
- Can PydanticAI use the current GitHub Copilot subscription without Azure model provisioning, and does a typed output make the LLM assessment trustworthy?

## Findings

### Renovate versus native package-manager queries

Renovate `44.138.0` ran in local lookup mode against a read-only disposable copy. Its extraction pass found **191 dependency entries across 30 files**:

| Manager | Files | Entries |
|---|---:|---:|
| Bicep | 6 | 17 |
| Devcontainer | 2 | 2 |
| Dockerfile | 6 | 21 |
| GitHub Actions | 4 | 38 |
| Go modules | 1 | 47 |
| NuGet | 11 | 66 |

This shows the main benefit over native package-manager queries: one tool can inventory several kinds of versioned inputs, including Docker bases, action references, and devcontainer features, alongside NuGet and Go modules. It does not replace native package-manager views of ecosystem-specific dependency graphs or vulnerability tools.

A `dotnet list package --outdated --no-restore` query, after locked restore in the disposable copy, returned NuGet-specific latest versions and project context. For example, it showed `Microsoft.OpenApi` 2.12.2 → 3.10.2, while the repository's discovery notes record that 3.x is intentionally ignored. This is useful package-manager evidence, but it says nothing about the Docker, GitHub Actions, Go, Bicep, or VM image inputs.

Limits observed:

- Renovate's local platform is experimental. The run needed onboarding disabled, and its local-preset warning disappeared only after that setting was supplied.
- Without a GitHub token, action lookups hit the public API rate limit; the run identified affected actions but could not reliably finish those lookups. Do not give the pilot a write-capable token just to address this.
- The Renovate Bicep manager reports resource API-version references; it does **not** update the AVM module version tags used by this project.
- The run did not report a Python manager for the inline `pip install` in `mock-idp/Dockerfile`, nor a Packer manager for the planned image source inputs. Those require explicit coverage or a custom adapter.
- The useful extraction result was a log summary, not yet the normalized report contract this system needs. A follow-up should test candidate lookup output and whether it can be consumed reliably without parsing unstable logs.

**Preliminary conclusion:** Renovate is a promising cross-ecosystem candidate source, especially for Docker, Actions, and devcontainer references. It is not a complete inventory or an authoritative risk/vulnerability assessor. Keep it as a candidate in the spike; do not make it the sole source of truth until lookup results, authentication, and machine-readable output are verified.

### Follow-up: Renovate's report file (2026-10-08)

Renovate `44.145.1`, pinned by digest, ran in local lookup mode with `--report-type=file` and a read-only, single-repository token, against the same `064aa09` snapshot. The report and its run details are in `fixtures/azure-egress-proxy/renovate/064aa09/`.

- **The report file is the contract, not the logs.** It is structured JSON per manager and package file: each dependency has its name, current value, datasource, and candidates per update type (`patch`, `minor`, `major`, `digest`). A dependency Renovate can't handle carries a `skipReason`. No log parsing is needed, so the JSON-log fallback in the design isn't used.
- **The token fixed lookups.** Without it, 27 entries were skipped with `github-token-required`, every action and the `setup-go` version. With it, none were, and 29 entries had candidates instead of 22. The run took under a minute.
- **Skip reasons map onto the scan's gap and unknown states:** `unspecified-version` (11 unpinned `apt`/`apk` packages), `invalid-value` (`distroless/static-debian12:nonroot`, trackable only by digest), `invalid-version` (50, mostly `runs-on: ubuntu-latest` and version-less `PackageReference`s whose version is central), and `disabled` (39 indirect Go modules, off by Renovate's default).
- **Compared with the open Dependabot PRs at that time:**
  - **#75, #76 and #98:** Renovate found the same updates. #98's Azure.Core, coverlet and Scalar updates still showed up after Dependabot closed that PR on an internal error.
  - **#99:** Renovate proposed azcore 1.23.3, newer than #99's 1.23.2.
  - **#77:** not found. The central version is already 10.0.12; #77 fixes AppHost's lock file, which still resolves 10.0.11 through the Aspire SDK. Parity therefore has to compare against lock-file versions, not only declarations.
- **Found by Renovate only:**
  - Aspire.AppHost.Sdk 13.5.4 → 13.6.1, from the `Sdk` attribute in `AppHost.csproj`, which no Dependabot PR covered;
  - Azure.Storage.Blobs 12.29.2 → 12.30.1;
  - `setup-go` 1.25 → 1.27;
  - the docker-in-docker devcontainer feature 2 → 4;
  - four Bicep resource API versions;
  - the majors a policy would hold: Microsoft.OpenApi 3.x and .NET 11 images.
- **Still not covered, as expected:** AVM module tags, the inline PyJWT pin, and the Aspire CLI version in the devcontainer Dockerfile's `ARG`. These are task 1.4.

### Follow-up: extra Renovate rules (2026-10-08)

Three regex `customManagers` cover the sources Renovate doesn't read by itself. They live in two places:
- **`src/sdlc/config/scan.renovate.json5`**, applied to every subject: inline `pip install` pins in Dockerfiles, and Bicep public registry modules, looked up as OCI tags at `mcr.microsoft.com/bicep/<path>`.
- **The subject's trial policy, `policies/azure-egress-proxy.renovate.json5`**: the devcontainer's Aspire CLI `ARG`. It describes that repository's files, so it belongs with its policy.

The scan of `064aa09` with both found 225 entries instead of 191:
- **PyJWT:** 2.15.0 → 2.15.1.
- **Aspire CLI:** 13.5.4 → 13.6.1, the same release as the Aspire SDK candidate.
- **AVM modules:** 32 references, all current. Lookups were confirmed by setting one module back to 0.9.0, which produced 0.11.1.

The report is `fixtures/azure-egress-proxy/renovate/064aa09/report-with-scan-config.json`.

Three things that weren't obvious:
- **Local mode reads only tracked files.** The trial policy has to be committed into the disposable copy, or Renovate reports "no renovate config file found" and silently skips it. The subject repository itself is never touched.
- **NuGet versioning reads a bare `13.5.4` as `>= 13.5.4`.** A custom manager on the NuGet datasource therefore reports no update, because 13.6.1 satisfies that range. An exact pin needs `versioningTemplate: "semver"`.
- **A `/regex/` file pattern containing a `/` breaks** (for example `.devcontainer/Dockerfile`), and the manager matches nothing without a warning. Use a glob instead.

### Vulnerability evidence

OSV-Scanner `2.6.0` scanned source and lockfiles from the disposable snapshot and emitted JSON. It read the Go module and .NET `packages.lock.json` files; it reported three OSV entries for `golang.org/x/crypto@0.55.0` (`GO-2026-5932`, `GO-2026-6354`, `GO-2026-6355`). This is vulnerability-match evidence, not proof that affected Go code is reachable. The repository already uses `govulncheck` for Go reachability, so adding OSV must demonstrate useful coverage beyond that existing check rather than duplicate its conclusion.

The run also reported packages without resolved versions in centrally managed project files. Lockfiles were available, but the pilot must preserve parser gaps as unknown instead of treating them as clean.

Syft and Grype were not run in this spike. They are already part of the proposed Marketplace image pipeline for OS-package SBOM and vulnerability gates; reuse that pipeline's evidence for image assessments rather than adding a second image-scanning path without a demonstrated gap.

### Python and GitHub Copilot

A disposable Python 3.12.3 environment installed PydanticAI `2.54.0`. Using the GitHub Copilot provider with the existing GitHub CLI authentication, the model-list endpoint returned 30 models; six advertised the Chat Completions endpoint PydanticAI uses. A minimal structured-output call to `claude-haiku-4.5` succeeded without Azure provisioning. The available model IDs depend on the user's Copilot plan and GitHub's current endpoint support; they must be queried at runtime or documented as an environment prerequisite.

The first test used a plain string for the risk field. The model returned `LOW` and added a claim not established by the supplied evidence. PydanticAI enforced the output shape, but not evidence faithfulness. A real pilot needs a constrained risk type/rubric, explicit evidence references, validation that references resolve to collected facts, and evaluation against known cases. A successful model call is not a quality or safety result.

## Recommendation for the next spike

1. Compare Renovate lookup candidates with native NuGet and Go results on the same pinned revision; record candidate precision, coverage, API requirements, and output stability.
2. Add fixture checks for the uncovered inputs: AVM module tags, inline PyJWT, Packer plugins/image source, and the VMSS Marketplace image reference. Keep each uncovered source visible if no reliable query exists.
3. Compare OSV matches with existing `govulncheck` and Dependabot evidence, separating package advisories from code reachability and image OS findings.
4. Test PydanticAI with GitHub Copilot using a rubric-constrained schema and historical PR evidence. Measure unsupported claims and invalid evidence citations, not only whether the API returns a response.
5. Only after those results, revise the OpenSpec design to choose the smallest tool set that meets the functional contract. Do not build the orchestrator in this spike.

## Reproduction notes

The subject input was a clean clone at `~/Projects/Alanta/azure-egress-proxy-agentic-sdlc`, pinned to the snapshot listed above. Tool runs used a disposable copy under `$DELTA_SCRATCH_DIR`; scanner containers mounted that copy read-only.

- Renovate: `docker.io/renovate/renovate:44.138.0 --platform=local --dry-run=lookup`, with `RENOVATE_ONBOARDING=false`. The unauthenticated lookup reached the GitHub API rate limit for action-related data. No credential was written to disk or supplied to this run.
- NuGet native query: `dotnet restore AzureEgressProxy.slnx --locked-mode`, then `dotnet list AzureEgressProxy.slnx package --outdated --no-restore` in the disposable copy.
- OSV-Scanner: `ghcr.io/google/osv-scanner:v2 scan source -r /src --format json`; the mutable `v2` tag resolved to 2.6.0 during this run. Pin a version or digest for repeatable future runs.
- Copilot: PydanticAI 2.54.0 used `gh auth token` only through an ephemeral environment variable for model listing and one synthetic structured-output call. No token value or subject-repository content was logged or saved.

## Handoff

> **Superseded, 2026-10-06.** The OpenSpec change was reviewed with the maintainer and rewritten as `revision-dependency-scan` (slice 1). It keeps Renovate as the main engine, with custom managers for the gaps below and native queries as a cross-check. PydanticAI is not carried forward: slices 2 and 3 use a coding agent. The notes below are kept as the original handoff.

- The OpenSpec change `report-only-dependency-assessment` is committed in the current Delta branch, but it is **not ready to apply as written**; no orchestration or implementation tasks have started (0/13 complete).
- Before implementation, revise the spec/design/tasks to record the tool-spike findings and decide which candidate sources are in scope. In particular, do not rely on Renovate alone for AVM module tags, inline Python, or Packer/Azure Marketplace image inputs.
- Continue the spike with a least-privilege read-only GitHub credential only if needed to test Renovate's authenticated action lookups and structured output. Never use or store a write-capable token for this pilot.
- Syft and Grype remain untested here; the planned Marketplace image workflow is the likely place to evaluate them against an actual custom image.

## References

- [Renovate local platform](https://docs.renovatebot.com/modules/platform/local/)
- [Renovate supported managers](https://docs.renovatebot.com/modules/manager/)
- [Renovate Bicep support and limits](https://docs.renovatebot.com/bicep/)
- [OSV-Scanner supported source inputs](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)
- [PydanticAI GitHub Copilot provider](https://pydantic.dev/docs/ai/models/github-copilot/)
