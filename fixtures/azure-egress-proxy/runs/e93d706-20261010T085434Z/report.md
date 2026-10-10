# Dependency scan of alanta/azure-egress-proxy

| | |
|---|---|
| Repository | alanta/azure-egress-proxy |
| Ref | main |
| Commit | e93d7062b075352f151f8e6b5a15f60913e7bd98 |
| Scanned at | 2026-10-10T08:54:34+00:00 |
| Update policy | trial file policies/azure-egress-proxy.renovate.json5, supplied for this scan |
| Tools | renovate 44.145.1, dotnet 10.0, go 1.27, osv-scanner 2.6.0, govulncheck v1.8.0, go toolchain for govulncheck (proxy/go.mod, linux/amd64, linux/arm64) go1.25.14, govulncheck database `https://vuln.go.dev` 2026-10-08T22:31:09Z, endoflife.date v1 (details under Tools) |
| Record schema | version 1 |

## Summary

- **End of life:** 1 line in use:
  - go 1.25: ended 2026-08-19; still supported: 1.26, 1.27 (proxy/Dockerfile:5, .github/workflows/ci.yml:134, .github/workflows/ci.yml:160, .github/workflows/release.yml:86, proxy/go.mod:3)
- **Nearing end of life:** none found, but 2 lines are unknown
- **Reachable vulnerabilities:** 14 advisories on 2 dependencies:
  - golang.org/x/net v0.58.0 (proxy/go.mod): GO-2026-6603, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6617; 5 reachable; fixed in v0.60.0; an in-scope candidate reaches the fix: yes
  - go 1.25.14 (proxy/go.mod:3): GO-2026-6603, GO-2026-6605, GO-2026-6607, GO-2026-6608, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6613, GO-2026-6617; 9 reachable; fixed in 1.26.9; an in-scope candidate reaches the fix: yes
- **Vulnerabilities no in-scope candidate is known to fix:** 1 advisory on 1 dependency:
  - golang.org/x/crypto v0.55.0 (proxy/go.mod): GO-2026-5932; 1 not reachable; no fixed version; an in-scope candidate reaches the fix: no fix to reach
- **Missed Dependabot updates:** none
- **Inconsistent declarations:** 0 of 3 logical dependencies
- **Unknown:** 2:
  - 102 of 231 dependencies not looked up (skipped), with the reasons under Not looked up
  - lifecycle of 2 lines
- **Coverage gaps:** 1, all listed under Coverage gaps
- **Totals:** 231 dependencies, 38 update candidates (31 in scope, 7 held by policy), 21 advisories on 3 dependencies

## Lifecycle

From endoflife.date, read at 2026-10-10T08:56:45+00:00: `https://endoflife.date/api/v1/products/dotnet`, `https://endoflife.date/api/v1/products/python`, `https://endoflife.date/api/v1/products/go`, `https://endoflife.date/api/v1/products/debian`, `https://endoflife.date/api/v1/products/ubuntu`.

| State | Product | Line | End of life | Still supported | Used in |
|---|---|---|---|---|---|
| end of life | go | 1.25 | 2026-08-19 | 1.26, 1.27 | proxy/Dockerfile:5, .github/workflows/ci.yml:134, .github/workflows/ci.yml:160, .github/workflows/release.yml:86, proxy/go.mod:3 |
| supported | dotnet | 10 | 2028-11-14 | 8, 9, 10 | .devcontainer/Dockerfile:1, src/ControlPlane/Dockerfile:1, src/ControlPlane/Dockerfile:16, src/Portal/Dockerfile:1, src/Portal/Dockerfile:16, src/SampleApp/Dockerfile:1, src/SampleApp/Dockerfile:17, .github/workflows/ci.yml:183 |
| supported | ubuntu | 24.04 | 2029-05-31 | 22.04, 24.04, 26.04 | .devcontainer/Dockerfile:1 |
| supported | python | 3.12 | 2028-10-31 | 3.11, 3.12, 3.13, 3.14, 3.15 | mock-idp/Dockerfile:1 |
| supported | debian | 12 | 2028-06-30 | 12, 13 | proxy/Dockerfile:26 |
| unknown | alpine-linux | alpine | unknown: 'alpine' names no release: it follows whichever one the image was last built on. |  | mock-idp/Dockerfile:1, proxy/Dockerfile:5 |
| unknown | ubuntu | latest | unknown: No lifecycle mapping: the table in sdlc/lifecycle.py doesn't link it to an endoflife.date product. |  | .github/workflows/allowlist.yml:19, .github/workflows/ci.yml:20, .github/workflows/ci.yml:93, .github/workflows/ci.yml:107, .github/workflows/ci.yml:120, .github/workflows/ci.yml:143, .github/workflows/ci.yml:148, .github/workflows/ci.yml:174, .github/workflows/ci.yml:198, .github/workflows/ci.yml:215, .github/workflows/deploy.yml:23, .github/workflows/images.yml:35, .github/workflows/release.yml:25 |

## Vulnerabilities

21 advisories on 3 dependencies (13 from govulncheck, 8 from osv).
Reachability, from govulncheck for Go: 14 reachable, 0 unknown, 7 not reachable.

| Advisory | Dependency | Where | Reachability | Fix | In-scope candidate reaches fix | Source | Dependabot alerts |
|---|---|---|---|---|---|---|---|
| GO-2026-6603 (CVE-2026-78659) | golang.org/x/net v0.58.0 | proxy/go.mod | reachable | fixed in v0.60.0 | yes | osv |  |
| GO-2026-6610 (CVE-2026-78660) | golang.org/x/net v0.58.0 | proxy/go.mod | reachable | fixed in v0.60.0 | yes | osv |  |
| GO-2026-6611 (CVE-2026-78669) | golang.org/x/net v0.58.0 | proxy/go.mod | reachable | fixed in v0.60.0 | yes | osv |  |
| GO-2026-6612 (CVE-2026-78663) | golang.org/x/net v0.58.0 | proxy/go.mod | reachable | fixed in v0.60.0 | yes | osv |  |
| GO-2026-6617 (CVE-2026-97032) | golang.org/x/net v0.58.0 | proxy/go.mod | reachable | fixed in v0.60.0 | yes | osv |  |
| GO-2026-6603 (CVE-2026-78659) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6605 (CVE-2026-56866) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6607 (CVE-2026-97031) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6608 (CVE-2026-94440) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6610 (CVE-2026-78660) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6611 (CVE-2026-78669) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6612 (CVE-2026-78663) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6613 (CVE-2026-94439) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6617 (CVE-2026-97032) | go 1.25.14 | proxy/go.mod:3 | reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-5932 | golang.org/x/crypto v0.55.0 | proxy/go.mod | not reachable | no fixed version | no fix to reach | osv |  |
| GO-2026-6354 (CVE-2026-78662) | golang.org/x/crypto v0.55.0 | proxy/go.mod | not reachable | fixed in v0.56.0 | yes | osv |  |
| GO-2026-6355 (CVE-2026-56855) | golang.org/x/crypto v0.55.0 | proxy/go.mod | not reachable | fixed in v0.56.0 | yes | osv |  |
| GO-2026-6599 (CVE-2026-94448) | go 1.25.14 | proxy/go.mod:3 | not reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6600 (CVE-2026-97030) | go 1.25.14 | proxy/go.mod:3 | not reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6604 (CVE-2026-56857) | go 1.25.14 | proxy/go.mod:3 | not reachable | fixed in 1.26.9 | yes | govulncheck |  |
| GO-2026-6609 (CVE-2026-78667) | go 1.25.14 | proxy/go.mod:3 | not reachable | fixed in 1.26.9 | yes | govulncheck |  |

### Dependabot alerts

Read at 2026-10-10T08:56:37+00:00. They describe the default branch as Dependabot last analysed it: main at e93d706, the scanned commit.

0 open alerts: 0 match the scan's advisories in the same file, 0 only in another file, 0 don't. 21 of the scan's 21 advisories have no open alert.

## Parity with Dependabot

3 open Dependabot PRs, read at 2026-10-10T08:56:37+00:00; the scan's lookups ran at 2026-10-10T08:54:34+00:00. Parity holds only for that moment.

7 proposed updates: 0 missed, 0 stale, 0 held by policy, 7 matched.
The comparison is complete.

### #75: ci: bump the actions-minor-patch group across 1 directory with 3 updates

At dd10dde on main, **current**.

| Result | Dependency | From | To | Type | Where | Detail |
|---|---|---|---|---|---|---|
| matched | azure/login | 3.0.2 | 3.1.0 | minor | github-actions / group actions-minor-patch | scan has v3.1.0 |
| matched | docker/setup-buildx-action | 4.3.0 | 4.4.1 | minor | github-actions / group actions-minor-patch | scan has v4.4.1 |
| matched | docker/setup-qemu-action | 4.3.0 | 4.4.0 | minor | github-actions / group actions-minor-patch | scan has v4.4.0 |

### #76: docker: bump the docker-minor-patch group across 2 directories with 2 updates

At bdf6a9d on main, **current**.

| Result | Dependency | From | To | Type | Where | Detail |
|---|---|---|---|---|---|---|
| matched | library/golang | 1.25-alpine | 1.27-alpine | minor, derived | docker /proxy group docker-minor-patch | scan has 1.27-alpine |
| matched | python | 3.12-alpine | 3.14-alpine | minor, derived | docker /mock-idp group docker-minor-patch | scan has 3.14-alpine |

### #99: proxy: bump the gomod-minor-patch group across 1 directory with 2 updates

At 5dde1e0 on main, **current**.

| Result | Dependency | From | To | Type | Where | Detail |
|---|---|---|---|---|---|---|
| matched | github.com/Azure/azure-sdk-for-go/sdk/azcore | 1.23.1 | 1.23.2 | patch | gomod /proxy group gomod-minor-patch | scan has v1.23.3 |
| matched | github.com/Azure/azure-sdk-for-go/sdk/storage/azblob | 1.8.1 | 1.8.2 | patch | gomod /proxy group gomod-minor-patch | scan has v1.8.2 |

### Scan only

23 entries with in-scope candidates that no open Dependabot PR proposes.

| Ecosystem | Dependency | Where | Current | Candidates |
|---|---|---|---|---|
| azure-bicep-resource | Microsoft.Network/loadBalancers | infra/modules/hub.bicep:327 | 2024-05-01 | 2024-10-01 |
| azure-bicep-resource | Microsoft.Network/virtualNetworks | infra/modules/peering.bicep:10 | 2025-01-01 | 2025-05-01 |
| azure-bicep-resource | Microsoft.Network/virtualNetworks/virtualNetworkPeerings | infra/modules/peering.bicep:14 | 2025-01-01 | 2025-05-01 |
| azure-bicep-resource | Microsoft.Resources/resourceGroups | infra/main.bicep:147 | 2024-03-01 | 2024-07-01 |
| docker | ghcr.io/devcontainers/features/docker-in-docker | .devcontainer/devcontainer.json:13 | 2 | 4 |
| docker | ghcr.io/devcontainers/features/docker-in-docker | .devcontainer/worktree/devcontainer.json:17 | 2 | 4 |
| docker | mcr.microsoft.com/devcontainers/dotnet | .devcontainer/Dockerfile:1 | 2.2.3-10.0-noble | 2.3.2-10.0-noble |
| github-releases | go | .github/workflows/ci.yml:134 | 1.25 | 1.27 |
| github-releases | go | .github/workflows/ci.yml:160 | 1.25 | 1.27 |
| github-releases | go | .github/workflows/release.yml:86 | 1.25 | 1.27 |
| github-tags | actions/upload-artifact | .github/workflows/release.yml:106 | v7 | v7 |
| go | golang.org/x/crypto | proxy/go.mod | v0.55.0 | v0.56.0 |
| go | golang.org/x/net | proxy/go.mod | v0.58.0 | v0.60.0 |
| go | golang.org/x/vuln/cmd/govulncheck | .github/workflows/ci.yml:165 | v1.7.0 | v1.8.0 |
| golang-version | go | proxy/go.mod:3 | 1.25.14 | 1.27.2 |
| nuget | Aspire.AppHost.Sdk | src/AppHost/AppHost.csproj:1 | 13.5.4 | 13.6.1 |
| nuget | Aspire.Cli | .devcontainer/Dockerfile:4 | 13.5.4 | 13.6.1 |
| nuget | Azure.Core | Directory.Packages.props:14 | 1.62.0 | 1.63.0 |
| nuget | Azure.Storage.Blobs | Directory.Packages.props:23 | 12.29.2 | 12.30.1 |
| nuget | Scalar.AspNetCore | Directory.Packages.props:40 | 2.17.9 | 2.17.14 |
| nuget | coverlet.collector | Directory.Packages.props:24 | 10.0.1 | 10.1.0 |
| nuget | xunit.runner.visualstudio | Directory.Packages.props:43 | 4.0.0 | 4.0.1 |
| pypi | PyJWT | mock-idp/Dockerfile:2 | 2.15.0 | 2.15.1 |

## Declared versions

Every logical dependency compared is declared consistently.

### What was compared

| Logical dependency | Result | Declarations compared |
|---|---|---|
| Go toolchain | consistent | docker.io/library/golang 1.25-alpine (proxy/Dockerfile:5), go 1.25 (.github/workflows/ci.yml:134), go 1.25 (.github/workflows/ci.yml:160), go 1.25 (.github/workflows/release.yml:86), go 1.25.14 (proxy/go.mod:3) |
| .NET | consistent | mcr.microsoft.com/devcontainers/dotnet 2.2.3-10.0-noble (.devcontainer/Dockerfile:1), mcr.microsoft.com/dotnet/sdk 10.0 (src/ControlPlane/Dockerfile:1), mcr.microsoft.com/dotnet/aspnet 10.0 (src/ControlPlane/Dockerfile:16), mcr.microsoft.com/dotnet/sdk 10.0 (src/Portal/Dockerfile:1), mcr.microsoft.com/dotnet/aspnet 10.0 (src/Portal/Dockerfile:16), mcr.microsoft.com/dotnet/sdk 10.0 (src/SampleApp/Dockerfile:1), mcr.microsoft.com/dotnet/aspnet 10.0 (src/SampleApp/Dockerfile:17), dotnet-sdk 10.0.x (.github/workflows/ci.yml:183) |
| Aspire | consistent | Aspire.AppHost.Sdk 13.5.4 (src/AppHost/AppHost.csproj:1), Aspire.Cli 13.5.4 (.devcontainer/Dockerfile:4) |

## Update candidates

38 candidates on 38 dependencies: 31 in scope, 7 held by policy. Dependencies whose lookup failed have no candidates; they are listed under Inventory as unknown.

### Held by policy

| Dependency | Where | Current | Type | Candidate | Held by |
|---|---|---|---|---|---|
| Microsoft.OpenApi | Directory.Packages.props:34 | 2.12.2 | major | 3.10.2 | Microsoft.OpenApi stays on 2.x |
| mcr.microsoft.com/dotnet/sdk | src/ControlPlane/Dockerfile:1 | 10.0 | major | 11.0 | .NET SDK and images stay on the .NET runtime's major |
| mcr.microsoft.com/dotnet/aspnet | src/ControlPlane/Dockerfile:16 | 10.0 | major | 11.0 | .NET SDK and images stay on the .NET runtime's major |
| mcr.microsoft.com/dotnet/sdk | src/Portal/Dockerfile:1 | 10.0 | major | 11.0 | .NET SDK and images stay on the .NET runtime's major |
| mcr.microsoft.com/dotnet/aspnet | src/Portal/Dockerfile:16 | 10.0 | major | 11.0 | .NET SDK and images stay on the .NET runtime's major |
| mcr.microsoft.com/dotnet/sdk | src/SampleApp/Dockerfile:1 | 10.0 | major | 11.0 | .NET SDK and images stay on the .NET runtime's major |
| mcr.microsoft.com/dotnet/aspnet | src/SampleApp/Dockerfile:17 | 10.0 | major | 11.0 | .NET SDK and images stay on the .NET runtime's major |

### In scope

| Dependency | Where | Current | Type | Candidate |
|---|---|---|---|---|
| mcr.microsoft.com/devcontainers/dotnet | .devcontainer/Dockerfile:1 | 2.2.3-10.0-noble | minor | 2.3.2-10.0-noble |
| Aspire.Cli | .devcontainer/Dockerfile:4 | 13.5.4 | minor | 13.6.1 |
| ghcr.io/devcontainers/features/docker-in-docker | .devcontainer/devcontainer.json:13 | 2 | major | 4 |
| ghcr.io/devcontainers/features/docker-in-docker | .devcontainer/worktree/devcontainer.json:17 | 2 | major | 4 |
| azure/login | .github/workflows/allowlist.yml:56 | v3.0.2 | minor | v3.1.0 |
| go | .github/workflows/ci.yml:134 | 1.25 | minor | 1.27 |
| go | .github/workflows/ci.yml:160 | 1.25 | minor | 1.27 |
| golang.org/x/vuln/cmd/govulncheck | .github/workflows/ci.yml:165 | v1.7.0 | minor | v1.8.0 |
| azure/login | .github/workflows/deploy.yml:69 | v3.0.2 | minor | v3.1.0 |
| docker/setup-qemu-action | .github/workflows/images.yml:60 | v4.3.0 | minor | v4.4.0 |
| docker/setup-buildx-action | .github/workflows/images.yml:61 | v4.3.0 | minor | v4.4.1 |
| go | .github/workflows/release.yml:86 | 1.25 | minor | 1.27 |
| actions/upload-artifact | .github/workflows/release.yml:106 | v7 | digest | v7 |
| Azure.Core | Directory.Packages.props:14 | 1.62.0 | minor | 1.63.0 |
| Azure.Storage.Blobs | Directory.Packages.props:23 | 12.29.2 | minor | 12.30.1 |
| coverlet.collector | Directory.Packages.props:24 | 10.0.1 | minor | 10.1.0 |
| Scalar.AspNetCore | Directory.Packages.props:40 | 2.17.9 | patch | 2.17.14 |
| xunit.runner.visualstudio | Directory.Packages.props:43 | 4.0.0 | patch | 4.0.1 |
| Microsoft.Resources/resourceGroups | infra/main.bicep:147 | 2024-03-01 | major | 2024-07-01 |
| Microsoft.Network/loadBalancers | infra/modules/hub.bicep:327 | 2024-05-01 | major | 2024-10-01 |
| Microsoft.Network/virtualNetworks | infra/modules/peering.bicep:10 | 2025-01-01 | major | 2025-05-01 |
| Microsoft.Network/virtualNetworks/virtualNetworkPeerings | infra/modules/peering.bicep:14 | 2025-01-01 | major | 2025-05-01 |
| python | mock-idp/Dockerfile:1 | 3.12-alpine | minor | 3.14-alpine |
| PyJWT | mock-idp/Dockerfile:2 | 2.15.0 | patch | 2.15.1 |
| docker.io/library/golang | proxy/Dockerfile:5 | 1.25-alpine | minor | 1.27-alpine |
| github.com/Azure/azure-sdk-for-go/sdk/azcore | proxy/go.mod | v1.23.1 | patch | v1.23.3 |
| github.com/Azure/azure-sdk-for-go/sdk/storage/azblob | proxy/go.mod | v1.8.1 | patch | v1.8.2 |
| golang.org/x/crypto | proxy/go.mod | v0.55.0 | minor | v0.56.0 |
| golang.org/x/net | proxy/go.mod | v0.58.0 | minor | v0.60.0 |
| go | proxy/go.mod:3 | 1.25.14 | minor | 1.27.2 |
| Aspire.AppHost.Sdk | src/AppHost/AppHost.csproj:1 | 13.5.4 | minor | 13.6.1 |

## Package manager cross-checks

Direct dependencies `dotnet list package --outdated` or `go list -m -u` call outdated without a matching scan candidate: a blind spot of Renovate's.

No disagreements with the tools that ran.

## Coverage gaps

What the scan couldn't cover: files no adapter reads or that can't be parsed, and sources that couldn't be read. Nothing here is known to be up to date.

| Kind | Subject | Reason |
|---|---|---|
| unsupported source | infra/assets/cloud-init.yaml | cloud-init config that no scan adapter reads. |

## Inventory

231 dependencies: 38 outdated, 91 current, 0 unknown, 102 skipped; 231 declared in a manifest, 0 resolved in a lock file (0 lock drift: the lock file resolves an older version than the repository declares; 0 added because an advisory concerns a package only a lock file or an indirect module has).

By ecosystem: apk 1, azure-bicep-resource 17, deb 10, docker 44, dotnet-version 1, github-releases 3, github-runners 13, github-tags 25, go 48, golang-version 1, nuget 67, pypi 1.

### Not looked up

An unknown lookup failed: whether the dependency is up to date is unknown. A skipped one wasn't attempted, for the reason given.

| Lookup | Dependency | Where | Current | Reason |
|---|---|---|---|---|
| skipped | apt-transport-https | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | ca-certificates | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | curl | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | git | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | gnupg | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | jq | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | lsb-release | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | shellcheck | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | unzip | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | azure-cli | .devcontainer/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | git | proxy/Dockerfile | unknown | No version is pinned, so there is nothing to compare. |
| skipped | gcr.io/distroless/static-debian12 | proxy/Dockerfile:26 | nonroot | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/allowlist.yml:19 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:20 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:93 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:107 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:120 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:143 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:148 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:174 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:198 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/ci.yml:215 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/deploy.yml:23 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/images.yml:35 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | ubuntu | .github/workflows/release.yml:25 | latest | The declared value isn't a version, so it can't be compared. |
| skipped | github.com/Azure/azure-sdk-for-go/sdk/internal | proxy/go.mod | v1.12.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/AzureAD/microsoft-authentication-library-for-go | proxy/go.mod | v1.8.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/DataDog/datadog-go | proxy/go.mod | v4.8.3+incompatible | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/MicahParks/jwkset | proxy/go.mod | v0.11.3 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/Microsoft/go-winio | proxy/go.mod | v0.6.2 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/apache/arrow-go/v18 | proxy/go.mod | v18.7.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/armon/go-proxyproto | proxy/go.mod | v0.1.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/beorn7/perks | proxy/go.mod | v1.0.1 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/carlmjohnson/versioninfo | proxy/go.mod | v0.22.5 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/cespare/xxhash/v2 | proxy/go.mod | v2.3.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/goccy/go-json | proxy/go.mod | v0.10.6 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/google/flatbuffers | proxy/go.mod | v25.12.19+incompatible | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/google/uuid | proxy/go.mod | v1.6.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/hashicorp/golang-lru | proxy/go.mod | v1.0.2 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/klauspost/compress | proxy/go.mod | v1.19.2 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/klauspost/cpuid/v2 | proxy/go.mod | v2.4.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/kylelemons/godebug | proxy/go.mod | v1.1.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/munnerz/goautoneg | proxy/go.mod | v0.0.0-20191010083416-a7dc8b61c822 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/patrickmn/go-cache | proxy/go.mod | v2.1.0+incompatible | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/pierrec/lz4/v4 | proxy/go.mod | v4.1.28 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/pkg/browser | proxy/go.mod | v0.0.0-20240102092130-5ac0b6a4141c | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/prometheus/client\_golang | proxy/go.mod | v1.24.1 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/prometheus/client\_model | proxy/go.mod | v0.6.2 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/prometheus/common | proxy/go.mod | v0.70.1 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/prometheus/procfs | proxy/go.mod | v0.21.1 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/rs/xid | proxy/go.mod | v1.6.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/stretchr/objx | proxy/go.mod | v0.5.3 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/stripe/goproxy | proxy/go.mod | v0.0.0-20260826103935-0cd07c409a76 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | github.com/zeebo/xxh3 | proxy/go.mod | v1.1.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | golang.org/x/exp | proxy/go.mod | v0.0.0-20260813180055-c1d0aacb2297 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | golang.org/x/sync | proxy/go.mod | v0.22.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | golang.org/x/sys | proxy/go.mod | v0.47.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | golang.org/x/text | proxy/go.mod | v0.41.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | golang.org/x/time | proxy/go.mod | v0.15.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | google.golang.org/protobuf | proxy/go.mod | v1.36.11 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | gopkg.in/urfave/cli.v1 | proxy/go.mod | v1.20.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | gopkg.in/yaml.v2 | proxy/go.mod | v2.4.0 | Not looked up: Renovate skips this kind of dependency by default. |
| skipped | Azure.Storage.Blobs | src/AppHost/AllowlistSeeder/AllowlistSeeder.csproj:10 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit.runner.visualstudio | src/ControlPlane.Tests/ControlPlane.Tests.csproj:16 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit | src/ControlPlane.Tests/ControlPlane.Tests.csproj:15 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | System.IdentityModel.Tokens.Jwt | src/ControlPlane.Tests/ControlPlane.Tests.csproj:14 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.NET.Test.Sdk | src/ControlPlane.Tests/ControlPlane.Tests.csproj:13 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.AspNetCore.Mvc.Testing | src/ControlPlane.Tests/ControlPlane.Tests.csproj:12 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | coverlet.collector | src/ControlPlane.Tests/ControlPlane.Tests.csproj:11 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Scalar.AspNetCore | src/ControlPlane/ControlPlane.csproj:21 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.OpenApi | src/ControlPlane/ControlPlane.csproj:20 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.AspNetCore.OpenApi | src/ControlPlane/ControlPlane.csproj:16 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.AspNetCore.Authentication.JwtBearer | src/ControlPlane/ControlPlane.csproj:15 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.Storage.Blobs | src/ControlPlane/ControlPlane.csproj:14 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit.runner.visualstudio | src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:14 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit | src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:13 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.NET.Test.Sdk | src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:12 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | coverlet.collector | src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:11 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.Extensions.Http | src/EgressProxy.Client/EgressProxy.Client.csproj:12 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.Identity | src/EgressProxy.Client/EgressProxy.Client.csproj:11 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit.runner.visualstudio | src/Portal.Tests/Portal.Tests.csproj:15 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit | src/Portal.Tests/Portal.Tests.csproj:14 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.NET.Test.Sdk | src/Portal.Tests/Portal.Tests.csproj:13 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.AspNetCore.Mvc.Testing | src/Portal.Tests/Portal.Tests.csproj:12 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | coverlet.collector | src/Portal.Tests/Portal.Tests.csproj:11 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.ResourceManager.Network | src/Portal/Portal.csproj:22 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.ResourceManager.Compute | src/Portal/Portal.csproj:21 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.Monitor.Query | src/Portal/Portal.csproj:20 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.Identity | src/Portal/Portal.csproj:19 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit.runner.visualstudio | src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:20 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | xunit | src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:19 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.NET.Test.Sdk | src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:18 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | coverlet.collector | src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:17 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | OpenTelemetry.Instrumentation.Runtime | src/ServiceDefaults/ServiceDefaults.csproj:22 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | OpenTelemetry.Instrumentation.Http | src/ServiceDefaults/ServiceDefaults.csproj:21 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | OpenTelemetry.Instrumentation.AspNetCore | src/ServiceDefaults/ServiceDefaults.csproj:20 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | OpenTelemetry.Extensions.Hosting | src/ServiceDefaults/ServiceDefaults.csproj:19 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | OpenTelemetry.Exporter.OpenTelemetryProtocol | src/ServiceDefaults/ServiceDefaults.csproj:18 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.Extensions.ServiceDiscovery | src/ServiceDefaults/ServiceDefaults.csproj:17 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Microsoft.Extensions.Http.Resilience | src/ServiceDefaults/ServiceDefaults.csproj:16 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.Monitor.OpenTelemetry.AspNetCore | src/ServiceDefaults/ServiceDefaults.csproj:15 | unknown | The declared value isn't a version, so it can't be compared. |
| skipped | Azure.Core | src/ServiceDefaults/ServiceDefaults.csproj:13 | unknown | The declared value isn't a version, so it can't be compared. |

### All dependencies

| Where | Dependency | Current | Origin | Ecosystem | Lookup | Candidates |
|---|---|---|---|---|---|---|
| .devcontainer/Dockerfile | apt-transport-https | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | azure-cli | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | ca-certificates | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | curl | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | git | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | gnupg | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | jq | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | lsb-release | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | shellcheck | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile | unzip | unknown | declared | deb | skipped |  |
| .devcontainer/Dockerfile:1 | mcr.microsoft.com/devcontainers/dotnet | 2.2.3-10.0-noble | declared | docker | outdated | 2.3.2-10.0-noble |
| .devcontainer/Dockerfile:4 | Aspire.Cli | 13.5.4 | declared | nuget | outdated | 13.6.1 |
| .devcontainer/devcontainer.json:13 | ghcr.io/devcontainers/features/docker-in-docker | 2 | declared | docker | outdated | 4 |
| .devcontainer/worktree/devcontainer.json:17 | ghcr.io/devcontainers/features/docker-in-docker | 2 | declared | docker | outdated | 4 |
| .github/workflows/allowlist.yml:19 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/allowlist.yml:21 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/allowlist.yml:56 | azure/login | v3.0.2 | declared | github-tags | outdated | v3.1.0 |
| .github/workflows/ci.yml:20 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:35 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:39 | dorny/paths-filter | v4.0.3 | declared | github-tags | current |  |
| .github/workflows/ci.yml:93 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:99 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:107 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:112 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:120 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:128 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:132 | actions/setup-go | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:134 | go | 1.25 | declared | github-releases | outdated | 1.27 |
| .github/workflows/ci.yml:139 | github.com/rhysd/actionlint/cmd/actionlint | v1.7.12 | declared | go | current |  |
| .github/workflows/ci.yml:143 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:148 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:152 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:156 | actions/setup-go | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:160 | go | 1.25 | declared | github-releases | outdated | 1.27 |
| .github/workflows/ci.yml:165 | golang.org/x/vuln/cmd/govulncheck | v1.7.0 | declared | go | outdated | v1.8.0 |
| .github/workflows/ci.yml:174 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:178 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:181 | actions/setup-dotnet | v6 | declared | github-tags | current |  |
| .github/workflows/ci.yml:183 | dotnet-sdk | 10.0.x | declared | dotnet-version | current |  |
| .github/workflows/ci.yml:198 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:202 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/ci.yml:215 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/ci.yml:219 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/deploy.yml:23 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/deploy.yml:25 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/deploy.yml:69 | azure/login | v3.0.2 | declared | github-tags | outdated | v3.1.0 |
| .github/workflows/images.yml:35 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/images.yml:56 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/images.yml:60 | docker/setup-qemu-action | v4.3.0 | declared | github-tags | outdated | v4.4.0 |
| .github/workflows/images.yml:61 | docker/setup-buildx-action | v4.3.0 | declared | github-tags | outdated | v4.4.1 |
| .github/workflows/images.yml:65 | docker/login-action | v4 | declared | github-tags | current |  |
| .github/workflows/images.yml:72 | docker/build-push-action | v7.4.0 | declared | github-tags | current |  |
| .github/workflows/release.yml:25 | ubuntu | latest | declared | github-runners | skipped |  |
| .github/workflows/release.yml:32 | actions/checkout | v7 | declared | github-tags | current |  |
| .github/workflows/release.yml:80 | actions/setup-go | v7 | declared | github-tags | current |  |
| .github/workflows/release.yml:86 | go | 1.25 | declared | github-releases | outdated | 1.27 |
| .github/workflows/release.yml:106 | actions/upload-artifact | v7 | declared | github-tags | outdated | v7 |
| .github/workflows/release.yml:114 | softprops/action-gh-release | v3.0.3 | declared | github-tags | current |  |
| Directory.Packages.props:14 | Azure.Core | 1.62.0 | declared | nuget | outdated | 1.63.0 |
| Directory.Packages.props:15 | Azure.Identity | 1.21.0 | declared | nuget | current |  |
| Directory.Packages.props:16 | Azure.Monitor.OpenTelemetry.AspNetCore | 1.6.0 | declared | nuget | current |  |
| Directory.Packages.props:20 | Azure.Monitor.Query | 1.7.1 | declared | nuget | current |  |
| Directory.Packages.props:21 | Azure.ResourceManager.Compute | 1.17.0 | declared | nuget | current |  |
| Directory.Packages.props:22 | Azure.ResourceManager.Network | 1.17.0 | declared | nuget | current |  |
| Directory.Packages.props:23 | Azure.Storage.Blobs | 12.29.2 | declared | nuget | outdated | 12.30.1 |
| Directory.Packages.props:24 | coverlet.collector | 10.0.1 | declared | nuget | outdated | 10.1.0 |
| Directory.Packages.props:25 | Microsoft.AspNetCore.Authentication.JwtBearer | 10.0.12 | declared | nuget | current |  |
| Directory.Packages.props:26 | Microsoft.AspNetCore.Mvc.Testing | 10.0.12 | declared | nuget | current |  |
| Directory.Packages.props:27 | Microsoft.AspNetCore.OpenApi | 10.0.12 | declared | nuget | current |  |
| Directory.Packages.props:28 | Microsoft.Extensions.Http | 10.0.12 | declared | nuget | current |  |
| Directory.Packages.props:29 | Microsoft.Extensions.Http.Resilience | 10.10.0 | declared | nuget | current |  |
| Directory.Packages.props:30 | Microsoft.Extensions.ServiceDiscovery | 10.10.0 | declared | nuget | current |  |
| Directory.Packages.props:31 | Microsoft.NET.Test.Sdk | 18.10.1 | declared | nuget | current |  |
| Directory.Packages.props:34 | Microsoft.OpenApi | 2.12.2 | declared | nuget | outdated | 3.10.2 (held) |
| Directory.Packages.props:35 | OpenTelemetry.Exporter.OpenTelemetryProtocol | 1.19.1 | declared | nuget | current |  |
| Directory.Packages.props:36 | OpenTelemetry.Extensions.Hosting | 1.19.1 | declared | nuget | current |  |
| Directory.Packages.props:37 | OpenTelemetry.Instrumentation.AspNetCore | 1.19.0 | declared | nuget | current |  |
| Directory.Packages.props:38 | OpenTelemetry.Instrumentation.Http | 1.19.0 | declared | nuget | current |  |
| Directory.Packages.props:39 | OpenTelemetry.Instrumentation.Runtime | 1.19.0 | declared | nuget | current |  |
| Directory.Packages.props:40 | Scalar.AspNetCore | 2.17.9 | declared | nuget | outdated | 2.17.14 |
| Directory.Packages.props:41 | System.IdentityModel.Tokens.Jwt | 8.23.0 | declared | nuget | current |  |
| Directory.Packages.props:42 | xunit | 2.9.3 | declared | nuget | current |  |
| Directory.Packages.props:43 | xunit.runner.visualstudio | 4.0.0 | declared | nuget | outdated | 4.0.1 |
| infra/bootstrap.bicep:44 | avm/res/resources/resource-group | 0.4.4 | declared | docker | current |  |
| infra/bootstrap.bicep:62 | avm/res/storage/storage-account | 0.33.1 | declared | docker | current |  |
| infra/bootstrap.bicep:119 | avm/res/container-registry/registry | 0.13.1 | declared | docker | current |  |
| infra/main.bicep:147 | Microsoft.Resources/resourceGroups | 2024-03-01 | declared | azure-bicep-resource | outdated | 2024-07-01 |
| infra/main.bicep:151 | avm/res/resources/resource-group | 0.4.4 | declared | docker | current |  |
| infra/main.bicep:166 | avm/res/resources/resource-group | 0.4.4 | declared | docker | current |  |
| infra/main.bicep:326 | avm/res/network/private-dns-zone | 0.8.1 | declared | docker | current |  |
| infra/modules/hub-identity.bicep:22 | avm/res/managed-identity/user-assigned-identity | 0.6.0 | declared | docker | current |  |
| infra/modules/hub.bicep:122 | Microsoft.ContainerRegistry/registries | 2023-07-01 | declared | azure-bicep-resource | current |  |
| infra/modules/hub.bicep:129 | Microsoft.Storage/storageAccounts | 2023-05-01 | declared | azure-bicep-resource | current |  |
| infra/modules/hub.bicep:172 | avm/res/network/network-security-group | 0.5.3 | declared | docker | current |  |
| infra/modules/hub.bicep:181 | avm/res/network/virtual-network | 0.10.2 | declared | docker | current |  |
| infra/modules/hub.bicep:253 | Microsoft.Authorization/roleAssignments | 2022-04-01 | declared | azure-bicep-resource | current |  |
| infra/modules/hub.bicep:265 | Microsoft.Authorization/roleAssignments | 2022-04-01 | declared | azure-bicep-resource | current |  |
| infra/modules/hub.bicep:288 | avm/ptn/authorization/resource-role-assignment | 0.1.2 | declared | docker | current |  |
| infra/modules/hub.bicep:300 | avm/ptn/authorization/resource-role-assignment | 0.1.2 | declared | docker | current |  |
| infra/modules/hub.bicep:312 | avm/res/network/public-ip-prefix | 0.8.0 | declared | docker | current |  |
| infra/modules/hub.bicep:327 | Microsoft.Network/loadBalancers | 2024-05-01 | declared | azure-bicep-resource | outdated | 2024-10-01 |
| infra/modules/hub.bicep:396 | avm/res/storage/storage-account | 0.33.1 | declared | docker | current |  |
| infra/modules/hub.bicep:494 | avm/res/compute/virtual-machine-scale-set | 0.11.1 | declared | docker | current |  |
| infra/modules/mgmt-identity.bicep:21 | avm/res/managed-identity/user-assigned-identity | 0.6.0 | declared | docker | current |  |
| infra/modules/mgmt-identity.bicep:35 | avm/res/managed-identity/user-assigned-identity | 0.6.0 | declared | docker | current |  |
| infra/modules/mgmt-identity.bicep:49 | avm/res/managed-identity/user-assigned-identity | 0.6.0 | declared | docker | current |  |
| infra/modules/mgmt.bicep:358 | avm/res/network/network-security-group | 0.5.3 | declared | docker | current |  |
| infra/modules/mgmt.bicep:367 | avm/res/network/virtual-network | 0.10.2 | declared | docker | current |  |
| infra/modules/mgmt.bicep:387 | avm/res/insights/component | 0.8.0 | declared | docker | current |  |
| infra/modules/mgmt.bicep:400 | avm/res/app/managed-environment | 0.16.0 | declared | docker | current |  |
| infra/modules/mgmt.bicep:434 | Microsoft.App/managedEnvironments | 2024-03-01 | declared | azure-bicep-resource | current |  |
| infra/modules/mgmt.bicep:441 | Microsoft.Insights/diagnosticSettings | 2021-05-01-preview | declared | azure-bicep-resource | current |  |
| infra/modules/mgmt.bicep:478 | avm/res/app/container-app | 0.23.0 | declared | docker | current |  |
| infra/modules/mgmt.bicep:582 | avm/res/app/container-app | 0.23.0 | declared | docker | current |  |
| infra/modules/mgmt.bicep:717 | Microsoft.App/containerApps/authConfigs | 2024-03-01 | declared | azure-bicep-resource | current |  |
| infra/modules/observability.bicep:47 | avm/res/operational-insights/workspace | 0.16.1 | declared | docker | current |  |
| infra/modules/observability.bicep:75 | Microsoft.OperationalInsights/workspaces/tables | 2023-09-01 | declared | azure-bicep-resource | current |  |
| infra/modules/observability.bicep:109 | avm/res/insights/data-collection-rule | 0.11.0 | declared | docker | current |  |
| infra/modules/observability.bicep:175 | Microsoft.Compute/virtualMachineScaleSets | 2024-11-01 | declared | azure-bicep-resource | current |  |
| infra/modules/observability.bicep:179 | Microsoft.Compute/virtualMachineScaleSets/extensions | 2024-11-01 | declared | azure-bicep-resource | current |  |
| infra/modules/observability.bicep:200 | Microsoft.Insights/dataCollectionRuleAssociations | 2022-06-01 | declared | azure-bicep-resource | current |  |
| infra/modules/peering.bicep:10 | Microsoft.Network/virtualNetworks | 2025-01-01 | declared | azure-bicep-resource | outdated | 2025-05-01 |
| infra/modules/peering.bicep:14 | Microsoft.Network/virtualNetworks/virtualNetworkPeerings | 2025-01-01 | declared | azure-bicep-resource | outdated | 2025-05-01 |
| infra/modules/spoke-identity.bicep:15 | avm/res/managed-identity/user-assigned-identity | 0.6.0 | declared | docker | current |  |
| infra/modules/spoke-identity.bicep:34 | avm/res/managed-identity/user-assigned-identity | 0.6.0 | declared | docker | current |  |
| infra/modules/spoke.bicep:244 | avm/res/network/network-security-group | 0.5.3 | declared | docker | current |  |
| infra/modules/spoke.bicep:253 | avm/res/network/virtual-network | 0.10.2 | declared | docker | current |  |
| infra/modules/spoke.bicep:273 | avm/res/insights/component | 0.8.0 | declared | docker | current |  |
| infra/modules/spoke.bicep:284 | avm/res/app/managed-environment | 0.16.0 | declared | docker | current |  |
| infra/modules/spoke.bicep:318 | Microsoft.App/managedEnvironments | 2024-03-01 | declared | azure-bicep-resource | current |  |
| infra/modules/spoke.bicep:325 | Microsoft.Insights/diagnosticSettings | 2021-05-01-preview | declared | azure-bicep-resource | current |  |
| infra/modules/spoke.bicep:342 | avm/res/app/container-app | 0.23.0 | declared | docker | current |  |
| mock-idp/Dockerfile:1 | python | 3.12-alpine | declared | docker | outdated | 3.14-alpine |
| mock-idp/Dockerfile:2 | PyJWT | 2.15.0 | declared | pypi | outdated | 2.15.1 |
| proxy/Dockerfile | git | unknown | declared | apk | skipped |  |
| proxy/Dockerfile:5 | docker.io/library/golang | 1.25-alpine | declared | docker | outdated | 1.27-alpine |
| proxy/Dockerfile:26 | gcr.io/distroless/static-debian12 | nonroot | declared | docker | skipped |  |
| proxy/go.mod | github.com/Azure/azure-sdk-for-go/sdk/azcore | v1.23.1 | declared | go | outdated | v1.23.3 |
| proxy/go.mod | github.com/Azure/azure-sdk-for-go/sdk/azidentity | v1.14.1 | declared | go | current |  |
| proxy/go.mod | github.com/Azure/azure-sdk-for-go/sdk/internal | v1.12.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/Azure/azure-sdk-for-go/sdk/storage/azblob | v1.8.1 | declared | go | outdated | v1.8.2 |
| proxy/go.mod | github.com/AzureAD/microsoft-authentication-library-for-go | v1.8.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/DataDog/datadog-go | v4.8.3+incompatible | declared | go | skipped |  |
| proxy/go.mod | github.com/MicahParks/jwkset | v0.11.3 | declared | go | skipped |  |
| proxy/go.mod | github.com/MicahParks/keyfunc/v3 | v3.8.2 | declared | go | current |  |
| proxy/go.mod | github.com/Microsoft/go-winio | v0.6.2 | declared | go | skipped |  |
| proxy/go.mod | github.com/apache/arrow-go/v18 | v18.7.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/armon/go-proxyproto | v0.1.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/beorn7/perks | v1.0.1 | declared | go | skipped |  |
| proxy/go.mod | github.com/carlmjohnson/versioninfo | v0.22.5 | declared | go | skipped |  |
| proxy/go.mod | github.com/cespare/xxhash/v2 | v2.3.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/goccy/go-json | v0.10.6 | declared | go | skipped |  |
| proxy/go.mod | github.com/golang-jwt/jwt/v5 | v5.3.1 | declared | go | current |  |
| proxy/go.mod | github.com/google/flatbuffers | v25.12.19+incompatible | declared | go | skipped |  |
| proxy/go.mod | github.com/google/uuid | v1.6.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/hashicorp/golang-lru | v1.0.2 | declared | go | skipped |  |
| proxy/go.mod | github.com/klauspost/compress | v1.19.2 | declared | go | skipped |  |
| proxy/go.mod | github.com/klauspost/cpuid/v2 | v2.4.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/kylelemons/godebug | v1.1.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/munnerz/goautoneg | v0.0.0-20191010083416-a7dc8b61c822 | declared | go | skipped |  |
| proxy/go.mod | github.com/patrickmn/go-cache | v2.1.0+incompatible | declared | go | skipped |  |
| proxy/go.mod | github.com/pierrec/lz4/v4 | v4.1.28 | declared | go | skipped |  |
| proxy/go.mod | github.com/pkg/browser | v0.0.0-20240102092130-5ac0b6a4141c | declared | go | skipped |  |
| proxy/go.mod | github.com/prometheus/client\_golang | v1.24.1 | declared | go | skipped |  |
| proxy/go.mod | github.com/prometheus/client\_model | v0.6.2 | declared | go | skipped |  |
| proxy/go.mod | github.com/prometheus/common | v0.70.1 | declared | go | skipped |  |
| proxy/go.mod | github.com/prometheus/procfs | v0.21.1 | declared | go | skipped |  |
| proxy/go.mod | github.com/rs/xid | v1.6.0 | declared | go | skipped |  |
| proxy/go.mod | github.com/sirupsen/logrus | v1.10.2 | declared | go | current |  |
| proxy/go.mod | github.com/stretchr/objx | v0.5.3 | declared | go | skipped |  |
| proxy/go.mod | github.com/stripe/goproxy | v0.0.0-20260826103935-0cd07c409a76 | declared | go | skipped |  |
| proxy/go.mod | github.com/stripe/smokescreen | v0.1.0 | declared | go | current |  |
| proxy/go.mod | github.com/zeebo/xxh3 | v1.1.0 | declared | go | skipped |  |
| proxy/go.mod | golang.org/x/crypto | v0.55.0 | declared | go | outdated | v0.56.0 |
| proxy/go.mod | golang.org/x/exp | v0.0.0-20260813180055-c1d0aacb2297 | declared | go | skipped |  |
| proxy/go.mod | golang.org/x/net | v0.58.0 | declared | go | outdated | v0.60.0 |
| proxy/go.mod | golang.org/x/sync | v0.22.0 | declared | go | skipped |  |
| proxy/go.mod | golang.org/x/sys | v0.47.0 | declared | go | skipped |  |
| proxy/go.mod | golang.org/x/text | v0.41.0 | declared | go | skipped |  |
| proxy/go.mod | golang.org/x/time | v0.15.0 | declared | go | skipped |  |
| proxy/go.mod | google.golang.org/protobuf | v1.36.11 | declared | go | skipped |  |
| proxy/go.mod | gopkg.in/urfave/cli.v1 | v1.20.0 | declared | go | skipped |  |
| proxy/go.mod | gopkg.in/yaml.v2 | v2.4.0 | declared | go | skipped |  |
| proxy/go.mod:3 | go | 1.25.14 | declared | golang-version | outdated | 1.27.2 |
| src/AppHost/AllowlistSeeder/AllowlistSeeder.csproj:10 | Azure.Storage.Blobs | unknown | declared | nuget | skipped |  |
| src/AppHost/AppHost.csproj:1 | Aspire.AppHost.Sdk | 13.5.4 | declared | nuget | outdated | 13.6.1 |
| src/ControlPlane.Tests/ControlPlane.Tests.csproj:11 | coverlet.collector | unknown | declared | nuget | skipped |  |
| src/ControlPlane.Tests/ControlPlane.Tests.csproj:12 | Microsoft.AspNetCore.Mvc.Testing | unknown | declared | nuget | skipped |  |
| src/ControlPlane.Tests/ControlPlane.Tests.csproj:13 | Microsoft.NET.Test.Sdk | unknown | declared | nuget | skipped |  |
| src/ControlPlane.Tests/ControlPlane.Tests.csproj:14 | System.IdentityModel.Tokens.Jwt | unknown | declared | nuget | skipped |  |
| src/ControlPlane.Tests/ControlPlane.Tests.csproj:15 | xunit | unknown | declared | nuget | skipped |  |
| src/ControlPlane.Tests/ControlPlane.Tests.csproj:16 | xunit.runner.visualstudio | unknown | declared | nuget | skipped |  |
| src/ControlPlane/ControlPlane.csproj:14 | Azure.Storage.Blobs | unknown | declared | nuget | skipped |  |
| src/ControlPlane/ControlPlane.csproj:15 | Microsoft.AspNetCore.Authentication.JwtBearer | unknown | declared | nuget | skipped |  |
| src/ControlPlane/ControlPlane.csproj:16 | Microsoft.AspNetCore.OpenApi | unknown | declared | nuget | skipped |  |
| src/ControlPlane/ControlPlane.csproj:20 | Microsoft.OpenApi | unknown | declared | nuget | skipped |  |
| src/ControlPlane/ControlPlane.csproj:21 | Scalar.AspNetCore | unknown | declared | nuget | skipped |  |
| src/ControlPlane/Dockerfile:1 | mcr.microsoft.com/dotnet/sdk | 10.0 | declared | docker | outdated | 11.0 (held) |
| src/ControlPlane/Dockerfile:16 | mcr.microsoft.com/dotnet/aspnet | 10.0 | declared | docker | outdated | 11.0 (held) |
| src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:11 | coverlet.collector | unknown | declared | nuget | skipped |  |
| src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:12 | Microsoft.NET.Test.Sdk | unknown | declared | nuget | skipped |  |
| src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:13 | xunit | unknown | declared | nuget | skipped |  |
| src/EgressProxy.Client.Tests/EgressProxy.Client.Tests.csproj:14 | xunit.runner.visualstudio | unknown | declared | nuget | skipped |  |
| src/EgressProxy.Client/EgressProxy.Client.csproj:11 | Azure.Identity | unknown | declared | nuget | skipped |  |
| src/EgressProxy.Client/EgressProxy.Client.csproj:12 | Microsoft.Extensions.Http | unknown | declared | nuget | skipped |  |
| src/Portal.Tests/Portal.Tests.csproj:11 | coverlet.collector | unknown | declared | nuget | skipped |  |
| src/Portal.Tests/Portal.Tests.csproj:12 | Microsoft.AspNetCore.Mvc.Testing | unknown | declared | nuget | skipped |  |
| src/Portal.Tests/Portal.Tests.csproj:13 | Microsoft.NET.Test.Sdk | unknown | declared | nuget | skipped |  |
| src/Portal.Tests/Portal.Tests.csproj:14 | xunit | unknown | declared | nuget | skipped |  |
| src/Portal.Tests/Portal.Tests.csproj:15 | xunit.runner.visualstudio | unknown | declared | nuget | skipped |  |
| src/Portal/Dockerfile:1 | mcr.microsoft.com/dotnet/sdk | 10.0 | declared | docker | outdated | 11.0 (held) |
| src/Portal/Dockerfile:16 | mcr.microsoft.com/dotnet/aspnet | 10.0 | declared | docker | outdated | 11.0 (held) |
| src/Portal/Portal.csproj:19 | Azure.Identity | unknown | declared | nuget | skipped |  |
| src/Portal/Portal.csproj:20 | Azure.Monitor.Query | unknown | declared | nuget | skipped |  |
| src/Portal/Portal.csproj:21 | Azure.ResourceManager.Compute | unknown | declared | nuget | skipped |  |
| src/Portal/Portal.csproj:22 | Azure.ResourceManager.Network | unknown | declared | nuget | skipped |  |
| src/SampleApp/Dockerfile:1 | mcr.microsoft.com/dotnet/sdk | 10.0 | declared | docker | outdated | 11.0 (held) |
| src/SampleApp/Dockerfile:17 | mcr.microsoft.com/dotnet/aspnet | 10.0 | declared | docker | outdated | 11.0 (held) |
| src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:17 | coverlet.collector | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:18 | Microsoft.NET.Test.Sdk | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:19 | xunit | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults.Tests/ServiceDefaults.Tests.csproj:20 | xunit.runner.visualstudio | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:13 | Azure.Core | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:15 | Azure.Monitor.OpenTelemetry.AspNetCore | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:16 | Microsoft.Extensions.Http.Resilience | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:17 | Microsoft.Extensions.ServiceDiscovery | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:18 | OpenTelemetry.Exporter.OpenTelemetryProtocol | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:19 | OpenTelemetry.Extensions.Hosting | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:20 | OpenTelemetry.Instrumentation.AspNetCore | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:21 | OpenTelemetry.Instrumentation.Http | unknown | declared | nuget | skipped |  |
| src/ServiceDefaults/ServiceDefaults.csproj:22 | OpenTelemetry.Instrumentation.Runtime | unknown | declared | nuget | skipped |  |

## Tools

| Tool | Version | Image or source | Read at |
|---|---|---|---|
| renovate | 44.145.1 | docker.io/renovate/renovate:44.145.1@sha256:6f1f3e2d9d0c3f99aa1f61f7509d302185de7deb173ac8c5ff88a5ce283ec435 |  |
| dotnet | 10.0 | mcr.microsoft.com/dotnet/sdk:10.0@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317 |  |
| go | 1.27 | docker.io/library/golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 |  |
| osv-scanner | 2.6.0 | ghcr.io/google/osv-scanner:v2.6.0@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa |  |
| govulncheck | v1.8.0 | docker.io/library/golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 |  |
| go toolchain for govulncheck (proxy/go.mod, linux/amd64, linux/arm64) | go1.25.14 |  |  |
| govulncheck database `https://vuln.go.dev` | 2026-10-08T22:31:09Z |  |  |
| endoflife.date | v1 | `https://endoflife.date/api/v1/products/dotnet` | 2026-10-10T08:56:45+00:00 |
| endoflife.date | v1 | `https://endoflife.date/api/v1/products/python` | 2026-10-10T08:56:45+00:00 |
| endoflife.date | v1 | `https://endoflife.date/api/v1/products/go` | 2026-10-10T08:56:45+00:00 |
| endoflife.date | v1 | `https://endoflife.date/api/v1/products/debian` | 2026-10-10T08:56:45+00:00 |
| endoflife.date | v1 | `https://endoflife.date/api/v1/products/ubuntu` | 2026-10-10T08:56:46+00:00 |
