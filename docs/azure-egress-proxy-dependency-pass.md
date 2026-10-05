# Azure Egress Proxy dependency and validation discovery

**Snapshot date:** 2026-10-05  
**Subject repository:** [`alanta/azure-egress-proxy`](https://github.com/alanta/azure-egress-proxy)  
**Subject revision:** `main` at `064aa099ecf7ffea9664b89df29f7d89d6859358`  
**Mode:** Read-only discovery. No files in the subject repository were changed.

## Executive summary

Dependabot already covers weekly grouped updates for NuGet, Go modules, Dockerfiles, and GitHub Actions. The repo also has scheduled `govulncheck` coverage. However, a green dependency PR is not always evidence that every changed dependency or affected output was exercised:

- The CI path filter does not cover `mock-idp/` or most workflow files, so some changes leave relevant jobs skipped.
- The grouped Docker PR currently includes a mock IdP image change that CI does not build.
- Several update sources are not clearly covered by configured Dependabot ecosystems, including inline pip installation, pinned Bicep modules, Azure Linux VMSS image updates, and some devcontainer tooling.
- The VMSS consumes the Azure Linux 3 Marketplace image tagged `latest` and has automatic OS upgrades enabled. This is an Azure-managed image lifecycle, not a repo-built custom VM image. The current GitHub release workflow publishes binaries and container images; no Marketplace image-publishing workflow was found.

This makes a report-only dependency inventory and update assessment a useful first pilot: it can show what is covered, what changed, and which checks actually ran before the system is allowed to edit or merge anything.

## Dependency surface

| Area | Sources found | Existing update or validation path | Discovery notes |
|---|---|---|---|
| .NET packages | `Directory.Packages.props`; project `packages.lock.json` files; `src/AppHost/AppHost.csproj` | Weekly grouped NuGet updates; CI runs locked restore, Release build, and tests | `Microsoft.OpenApi` 3.x is intentionally ignored. Aspire SDK version is specified in the AppHost project file. |
| Go proxy | `proxy/go.mod`, `proxy/go.sum`; Go directive `1.25.14` | Weekly Go module updates; weekly `govulncheck`; Go tests and vet run inside the proxy Docker build | CI/release use the Go 1.25 line with `check-latest`; Dependabot does not bump the Go directive. The proxy Dockerfile has its own Go builder tag. |
| Container bases | Dockerfiles under `proxy/`, `src/SampleApp/`, `src/ControlPlane/`, `src/Portal/`, `.devcontainer/`, and `mock-idp/` | Dependabot Docker updates are configured for these directories. CI builds the proxy image; release builds and pushes four application images. | .NET images use floating `10.0` tags. Proxy builder uses `golang:1.25-alpine`; runtime uses `gcr.io/distroless/static-debian12:nonroot`. Mock IdP uses `python:3.12-alpine`. |
| Python package | Inline `pip install "PyJWT[crypto]==2.15.0"` in `mock-idp/Dockerfile` | No Python package manifest or Python Dependabot entry found | A Dockerfile image update does not provide a normal independent Python dependency update lane for this inline package. |
| GitHub Actions | Workflow `uses:` references are pinned to commit SHAs | Weekly grouped `github-actions` updates | Current CI path filters do not run normal validation for the action updates in the open PR. |
| Bicep / Azure Verified Modules | Versioned `br/public:avm/...` module references in `infra/**/*.bicep` | CI builds Bicep templates and checks NSG description lengths | No Bicep/module update entry is configured in Dependabot. Compile validation is not an Azure deployment. |
| VM operating system | `infra/modules/hub.bicep` VMSS image reference is Azure Linux 3 ARM64 with version `latest`; automatic OS upgrade is enabled | Azure VMSS image and OS upgrade mechanisms | This is runtime infrastructure update behavior, not a checked-in VM image build. Deployment evidence should identify the actual image version applied. |
| Devcontainer tools | `.devcontainer/Dockerfile`, devcontainer feature lock files, Aspire CLI version `13.5.4`, Azure CLI and OS packages installed through apt | Dockerfile base image is within the Docker update configuration | Feature lock and tool/package versions are not all covered by the configured update entries; apt installs are not version-pinned in the Dockerfile. |

### Bicep module versions observed

The currently referenced public AVM module tags include:

- `avm/res/app/container-app:0.23.0`
- `avm/res/app/managed-environment:0.16.0`
- `avm/res/compute/virtual-machine-scale-set:0.11.1`
- `avm/res/container-registry/registry:0.13.1`
- `avm/res/insights/component:0.8.0`
- `avm/res/insights/data-collection-rule:0.11.0`
- `avm/res/managed-identity/user-assigned-identity:0.6.0`
- `avm/res/network/network-security-group:0.5.3`
- `avm/res/network/private-dns-zone:0.8.1`
- `avm/res/network/public-ip-prefix:0.8.0`
- `avm/res/network/virtual-network:0.10.2`
- `avm/res/operational-insights/workspace:0.16.1`
- `avm/res/resources/resource-group:0.4.4`
- `avm/res/storage/storage-account:0.33.1`
- `avm/ptn/authorization/resource-role-assignment:0.1.2`

This pass inventoried the tags; it did not query each registry to determine whether a newer tag is available.

## Validation and release process observed

The [CI workflow](https://github.com/alanta/azure-egress-proxy/blob/main/.github/workflows/ci.yml) runs on pull requests, pushes to `main`, and a weekly schedule. Its path filter gates checks for proxy code, .NET, infrastructure, scripts, and the CI workflow itself. The jobs include:

- Proxy Docker build, which runs `go vet`, `go test`, and builds the proxy binary inside the Dockerfile.
- Scheduled and change-triggered `govulncheck` for the Go module.
- Locked .NET restore, Release build, and tests.
- Bicep compilation and NSG description-length checks.
- ShellCheck for shell scripts.

The current filters omit `mock-idp/**`, and the workflow filter only names `ci.yml`. Consequently, a mock IdP-only Docker update or most workflow dependency updates can leave the relevant checks skipped. A Docker base update to a .NET application does not itself trigger a build of that specific Docker image.

The [release workflow](https://github.com/alanta/azure-egress-proxy/blob/main/.github/workflows/release.yml) builds Linux amd64/arm64 binaries with SHA-256 sidecars, publishes a GitHub Release, and builds/pushes four container images on release tags. The [deploy workflow](https://github.com/alanta/azure-egress-proxy/blob/main/.github/workflows/deploy.yml) is manually dispatched, uses Azure OIDC, deploys via the repo's scripts/Bicep, and can run application smoke tests. No custom VM image build or Azure Marketplace publishing step was found in these workflows.

## Open Dependabot PRs at snapshot time

All four were open at the time of inspection. Aikido's code check reported success on each; that does not establish that the repository has no Dependabot alerts.

| PR | Current checks | Assessment |
|---|---|---|
| [#89 — three NuGet updates](https://github.com/alanta/azure-egress-proxy/pull/89) | .NET build/test failed; other path-gated jobs skipped | Hold. The Azure.Core release notes mention managed-identity mTLS proof-of-possession behavior. Review its impact and diagnose the failing build before any merge. The public check annotation did not include the cause; unauthenticated retrieval of the Actions log returned 403. |
| [#77 — Microsoft.Extensions.Http 10.0.11 → 10.0.12](https://github.com/alanta/azure-egress-proxy/pull/77) | .NET build/test passed | Potentially routine, but the diff adds an explicit `PackageReference` in `AppHost.csproj`, not just a package version/lock-file update. Understand why it became direct before classifying it as low risk. |
| [#76 — grouped Docker updates](https://github.com/alanta/azure-egress-proxy/pull/76) | Proxy image build and `govulncheck` passed; unrelated jobs skipped | The group changes Go 1.25 → 1.27 and Python 3.12 → 3.14. The proxy update is exercised by the proxy image build; the mock IdP update is not. The Go toolchain now differs from the Go 1.25 line used by release builds. Do not infer low risk from Dependabot's minor/patch group label. |
| [#75 — grouped GitHub Actions updates](https://github.com/alanta/azure-egress-proxy/pull/75) | CI jobs were skipped; Aikido check passed | The changed actions are used by deployment and release workflows. Their updated behavior was not exercised by the normal path-gated CI checks, so skipped checks are not sufficient merge evidence. |

This pass did not have access to the repository's Dependabot alert list. It therefore cannot claim that there are no unresolved vulnerabilities. It also did not run package-manager latest-version queries or fetch private CI logs.

## Implications for the SDLC pilot

1. Represent dependency coverage per source and ecosystem, including uncovered sources and unknowns; do not equate "Dependabot configured" with "all dependencies covered."
2. Map each changed dependency to components, artifacts, and the checks that should validate them.
3. Report check state as **passed**, **failed**, **skipped/not applicable**, or **unknown**. A skipped test must never count as a pass.
4. Assess actual compatibility and impact, not only SemVer labels or Dependabot group names. PR #76 is a useful test case because grouped runtime/toolchain jumps span Go and Python.
5. Treat workflow, Bicep, VM base-image, and security-sensitive identity/network changes as special impact classes that require specific evidence.
6. Keep the first implementation slice report-only: inventory dependencies, correlate candidate updates and PRs, summarize release/advisory evidence, and identify validation gaps. Do not edit the subject repository or merge updates as part of that slice.

## Source links

- [Dependabot configuration](https://github.com/alanta/azure-egress-proxy/blob/main/.github/dependabot.yml)
- [CI workflow](https://github.com/alanta/azure-egress-proxy/blob/main/.github/workflows/ci.yml)
- [Release workflow](https://github.com/alanta/azure-egress-proxy/blob/main/.github/workflows/release.yml)
- [Deploy workflow](https://github.com/alanta/azure-egress-proxy/blob/main/.github/workflows/deploy.yml)
- [NuGet central versions](https://github.com/alanta/azure-egress-proxy/blob/main/Directory.Packages.props)
- [Go module](https://github.com/alanta/azure-egress-proxy/blob/main/proxy/go.mod)
- [VMSS module](https://github.com/alanta/azure-egress-proxy/blob/main/infra/modules/hub.bicep)
- [Open Dependabot PRs](https://github.com/alanta/azure-egress-proxy/pulls?q=is%3Apr+is%3Aopen+author%3Aapp%2Fdependabot)
