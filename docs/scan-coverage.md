# What the scan covers

What `sdlc scan` reads, where its versions come from, and what it knowingly leaves out. The counts are from a scan of `alanta/azure-egress-proxy` at `064aa09` on 2026-10-09: 233 entries, 1 coverage gap.

## Sources

| Source | Read by | Files | Entries | Notes |
|---|---|---:|---:|---|
| NuGet central versions and project files | Renovate `nuget` | 11 | 66 | Includes the Aspire SDK in `AppHost.csproj`'s `Sdk` attribute. A `PackageReference` without its own version is listed but skipped: its central version governs it. |
| Go modules | Renovate `gomod` | 1 | 47 | Includes the `go` directive. Indirect modules are listed but skipped, which is Renovate's default. |
| Dockerfile base images and OS packages | Renovate `dockerfile` | 6 | 21 | `apt-get`/`apk add` packages without a version are listed but skipped. |
| GitHub Actions | Renovate `github-actions` | 4 | 38 | Action pins, `setup-go`/`setup-dotnet` versions, and `runs-on` labels (skipped). |
| Devcontainer features | Renovate `devcontainer` | 2 | 2 | |
| Bicep resource API versions | Renovate `bicep` | 6 | 17 | |
| Bicep public registry modules (AVM) | Scan rule: OCI tags at `mcr.microsoft.com/bicep/…` | 9 | 32 | |
| `pip install pkg==x.y.z` in Dockerfiles | Scan rule: PyPI | 1 | 1 | |
| `go install module@vX.Y.Z` in workflows, scripts and Dockerfiles | Scan rule: Go proxy | 1 | 1 | govulncheck at `064aa09`; actionlint on later commits. |
| The devcontainer's Aspire CLI `ARG` | Subject's trial policy | 1 | 1 | Specific to this repository, so it lives with its policy. |
| Lock files lagging behind a declared version | `dotnet list package --include-transitive` | 7 lock files | 7 | See [Locked entries](#locked-entries). |

**"Scan rule"** means a Renovate custom manager in `src/sdlc/config/scan.renovate.json5`, applied to every subject. Rules that describe one subject's own files belong in that subject's policy instead.

## Lookup states

Every entry has exactly one state:
- **`current`:** looked up, and nothing newer exists.
- **`outdated`:** looked up, and at least one candidate exists. The scan reports the newest patch, minor and major version separately.
- **`unknown`:** the lookup failed: no token, rate limited, an unreachable registry, or an update type the scan doesn't handle. It is never reported as current.
- **`skipped`:** deliberately not looked up, with the reason. Three reasons occur:
  - the value isn't a version (51 entries);
  - Renovate skips the dependency by default (39);
  - no version is pinned (11).

## Cross-check

`dotnet list package --outdated` and `go list -m -u` run on the same checkout. A direct dependency they call outdated, without a matching scan candidate, is recorded as a disagreement: a Renovate blind spot. At `064aa09` and on `main` there are none.

## Locked entries

Dependencies that appear only in lock files are listed in two cases (design decision 3a):
1. **Drift:** a lock file resolves an older version than the repository declares for the package, for example a central version. The candidate is the declared version.
2. **A known vulnerability** concerns the dependency (task 4.1, not built yet).

At `064aa09` there are seven drift entries, all caused by central versions not applying to transitive packages. AppHost locks `Microsoft.Extensions.Http` 10.0.11 while 10.0.12 is declared, which is Dependabot's #77. `EgressProxy.Client` and its tests lock Azure.Core 1.53.0 while 1.62.0 is declared. About 270 other outdated transitive packages and indirect modules are not listed.

## Coverage gaps

The scan reports a gap rather than staying silent when:
- **a file type declares dependencies but no adapter reads it.** Today these are Packer templates and cloud-init configs. At `064aa09`, `infra/assets/cloud-init.yaml`, which installs packages without versions and downloads the proxy binary, is the one gap.
- **a lock file can't be parsed.** Renovate doesn't parse lock files in lookup mode, so the scan checks them itself.
- **a line installs a package without a version**, such as `pip install pkg` or `go install …@latest`.
- **a package manager query fails**, for example when a locked restore breaks.

A file type Renovate does read, such as a project file with only project references, isn't a gap when Renovate finds nothing in it.

## Known limits

- **The VM scale set's Marketplace image** (`version: 'latest'` in `hub.bicep`) isn't tracked. It's managed by Azure and upgraded automatically.
- **`gcr.io/distroless/static-debian12:nonroot`** has no version tag. It could only be tracked by digest, so it is skipped. End-of-life detection (task 4.5) covers its Debian base.
- **The Marketplace image build** (Packer, platform image, OS packages) isn't covered yet. A Packer template shows up as a coverage gap until it is.
- **Policy classification, vulnerabilities, end-of-life lines, cross-file consistency and the Dependabot comparison** are later tasks in `openspec/changes/revision-dependency-scan/tasks.md`.
