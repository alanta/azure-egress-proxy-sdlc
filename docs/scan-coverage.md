# What the scan covers

What `sdlc scan` reads, where its versions come from, and what it knowingly leaves out. The counts are from a scan of `alanta/azure-egress-proxy` at `064aa09` on 2026-10-09: 233 entries, 1 coverage gap.

## Sources

| Source | Read by | Files | Entries | Notes |
|---|---|---:|---:|---|
| NuGet central versions and project files | Renovate `nuget` | 11 | 66 | Includes the Aspire SDK in `AppHost.csproj`'s `Sdk` attribute. A `PackageReference` without its own version is listed but skipped: its central version governs it. |
| Go modules | Renovate `gomod` | 1 | 47 | Includes the `go` directive, with newer Go releases as its candidates (see below). Indirect modules are listed but skipped, which is Renovate's default. |
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

The same file has one package rule: the `go` directive gets `rangeStrategy: "bump"`. Renovate's `go-mod-directive` versioning reads `go 1.25.14` as a minimum that every newer Go release satisfies, so under the default strategy it proposes nothing and the directive would look current while Go 1.26 and 1.27 exist. With bump, newer releases are its patch and minor candidates. The `toolchain` directive is an exact version and needs no rule.

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
2. **A known vulnerability** concerns the dependency, and no inventory entry exists for it in that file, such as a transitive NuGet package. The candidate is the newest fixed version among its advisories; without a fix, the entry is listed but skipped.

At `064aa09` there are seven drift entries, all caused by central versions not applying to transitive packages. AppHost locks `Microsoft.Extensions.Http` 10.0.11 while 10.0.12 is declared, which is Dependabot's #77. `EgressProxy.Client` and its tests lock Azure.Core 1.53.0 while 1.62.0 is declared. About 270 other outdated transitive packages and indirect modules are not listed.

Indirect Go modules are an exception: Renovate already lists them, and skips them by default. An advisory on one refers to Renovate's entry, which keeps its id and location and gets the fixed version as its candidate, so each module is listed once. If the policy has Renovate look indirect modules up, the entry keeps Renovate's lookup and candidates, and gets the fixed version only when none of its candidates reaches it. At `064aa09` that's `golang.org/x/crypto` v0.55.0 and `golang.org/x/net` v0.58.0.

## Vulnerabilities

OSV-Scanner reads every `packages.lock.json` and `go.mod` (it has no extractor for `go.sum`) and matches the resolved versions against osv.dev. It runs with an empty configuration of the scan's own, so an `osv-scanner.toml` in the subject can't ignore advisories. Each advisory refers to an inventory entry: the declared version it affects, Renovate's entry for an indirect Go module, a lock-drift entry, or a locked entry added for it.

The record gives the fixed version: the end of the advisory's range that contains the version, which every entry of the advisory's group must agree on. When the advisory only names the last affected version, the record gives that instead. It also says whether an in-scope candidate is past the advisory: `true`, `false`, or `unknown` when the lookup failed or the ranges can't be evaluated. When only a candidate the policy holds gets there, it is `false`, with the rule that holds it.

At `064aa09`, there are 8 advisories on two indirect Go modules: three on `golang.org/x/crypto` (one without a fix, two fixed in v0.56.0) and five on `golang.org/x/net` (fixed in v0.60.0). No NuGet package has one.

What it doesn't cover:
- **A package without a resolved version** is a gap: whether an advisory concerns it is unknown. References to the subject's own projects in NuGet lock files are not packages, so they don't count.
- **When OSV-Scanner fails**, the record has an `unavailable_source` gap, and makes no claim about vulnerabilities. A lock file missing from its output is a gap too.
- **Image OS packages, Docker images and GitHub Actions** aren't scanned. The Go standard library is only checked by govulncheck, so when it fails, it isn't checked. Dependabot alerts are compared separately; see [Dependabot alerts](#dependabot-alerts).

### Reachability

govulncheck runs on each `go.mod` the go command would treat as a module (not under `testdata`, `vendor`, or a directory starting with `_` or `.`), in the pinned Go image, with the toolchain the module declares: its `toolchain` directive, or else its `go` directive (`go 1.25.14` → go1.25.14; `go 1.25` → go1.25.0). The image builds govulncheck itself, then `GOTOOLCHAIN` has the `go` command download that exact toolchain from the Go module proxy, checked against the checksum database. The module is analysed on its own (`GOWORK=off`), from its vendored sources when it has `vendor/modules.txt`. The govulncheck version, the toolchain it reports using, the platforms and its database's modification time are recorded as tools.

It analyses the module's packages without tests, with cgo off, for linux/amd64 and linux/arm64, the platforms the subject releases for, so the result doesn't depend on the host. Each advisory counts at the most precise level found on either platform:
- **`reachable`:** a call path leads from the module's code to a vulnerable function.
- **`not reachable`:** a vulnerable package is imported but none of its vulnerable functions is called, or the module is only required at an affected version.
  So `not reachable` means there is no static call path from non-test code on the analysed platforms. Reflection, `go:linkname`, cgo and tests are outside the analysis.
- **`unknown`:** everything else. That covers every ecosystem other than Go, a Go advisory govulncheck has no finding for (its database lacks it, or it judges the version unaffected), and every Go advisory of a module where govulncheck failed. A failure is an `unavailable_source` gap, and the scan carries on.

The reachability sits next to OSV-Scanner's version match and doesn't change it. OSV-Scanner doesn't check the Go standard library, so govulncheck's standard library advisories are added with source `govulncheck`, against the `go.mod` directive that sets the toolchain, with the fixed version from the advisory. An advisory govulncheck finds on another module that OSV-Scanner didn't report is added with source `govulncheck` the way OSV-Scanner's are, with a locked entry when the inventory has none for the module.

At `064aa09`, the five `golang.org/x/net` advisories are reachable and the three `golang.org/x/crypto` ones are not: no package of it is imported. Go 1.25.14 has 13 standard library advisories, all fixed in 1.26.9: 9 reachable, 4 not. Both platforms give the same answers. That scan's Renovate proposed no newer `go` directive, so no candidate reached those fixes; with the bump rule above, the directive's minor candidate (1.27.2 on `main` at `e93d706`) reaches all 13.

### Dependabot alerts

The repository's open Dependabot alerts are read through the API with the scan's token, which needs `Dependabot alerts: read`. They are a comparison source, like Dependabot's PRs, not findings of the scan: they describe the default branch as Dependabot last analysed it, which need not be the scanned commit. So the record keeps them in their own section, with the branch, its head read just before the alerts, whether that head is the scanned commit, and the time they were read. When it isn't the scanned commit, a difference may be the branch's rather than a miss of the scan, and the report says so.

An alert that shares a GHSA or CVE id with one of the scan's advisories on the same package, in the alert's manifest or a file beside it (such as the lock file next to a project file), is `matched`. When the scan has that advisory on the package only in other files, such as a central version, the alert is `matched_elsewhere`. Either way the vulnerabilities it matched list the alert's number. Any other alert is `unmatched`, so the disagreement shows. A malformed answer, a redirect away from `api.github.com` (never followed, so the token stays with GitHub's API) or a pagination loop makes the source unavailable. Each alert also names the inventory entry for its package in its manifest, when the scan has one.

When the alerts can't be read (no token, no permission, alerts disabled, rate limited, GitHub unreachable), the record has no alerts section and an `unavailable_source` gap for `dependabot-alerts` with the reason. It then says nothing about what the alerts would have said.

On 2026-10-09 the token can read them, and `main` has no open alerts, while it requires the same `golang.org/x/crypto` and `golang.org/x/net` versions as `064aa09`. GitHub's advisory database has no entry for the two of their CVEs checked (CVE-2026-78662 and CVE-2026-78659), which would explain why Dependabot is silent. None of the scan's 21 advisories is corroborated.

## Consistency

Some dependencies are declared in several places that Renovate updates separately. The alias table in `src/sdlc/consistency.py` lists which declarations belong together (design decision 6):
- **Go toolchain:** go.mod's `toolchain` directive, or its `go` directive when there is none; `setup-go`'s `go-version`; `golang` image tags, from Docker Hub or a mirror such as `mirror.gcr.io`.
- **.NET:** the SDK in `setup-dotnet`'s `dotnet-version`, `global.json` and the `sdk` image at `mcr.microsoft.com/dotnet/`; the runtime in the `aspnet`, `runtime` and `runtime-deps` images there, and the .NET line in the devcontainer image's tag (`2.2.3-10.0-noble`). SDK declarations compare with each other by feature band: 10.0.401 is band 4, so it agrees with `10.0.4xx` but not with `10.0.100`. An SDK and a runtime compare at major.minor only, because a runtime's third part is a patch.
- **Aspire:** the AppHost SDK and the Aspire CLI.

Image tags give their version without the suffix: `golang:1.27-alpine` declares 1.27. Two declarations disagree when they differ as far as both go: `1.25` agrees with `1.25.14`, not with `1.27`. A flagged dependency lists every declaration with its file, line and version. The inventory finds the line of declarations Renovate gives no text for: go.mod's directives, `setup-*` versions, `global.json`'s SDK and MSBuild project SDKs. The record lists, per alias, which declarations were compared, so an alias nothing declares shows as such.

Some declarations aren't compared, and are an `unparseable_source` gap instead, so they never count as agreeing:
- no version, such as `latest` or a digest alone;
- a variable, such as `golang:${GO_VERSION}-alpine`;
- a version that floats to the newest release, such as Go `1.x` or `golang:1-alpine`. Go and .NET need at least major.minor.

At `064aa09` everything agrees: Go 1.25 across go.mod (1.25.14), both workflows and the proxy's build image; .NET 10.0 across `setup-dotnet`, six images and the devcontainer; Aspire 13.5.4 in the AppHost SDK and the devcontainer's CLI. Dependabot's #76 builds the proxy with `golang:1.27-alpine` while go.mod and the workflows stay on 1.25, so a scan of its head flags the Go toolchain.

## Lifecycle

Renovate knows versions, not support windows, so the scan reads lifecycle data from the endoflife.date API (`https://endoflife.date/api/v1/products/<product>`, no account, no token sent; design decision 6a). The table in `src/sdlc/lifecycle.py` links inventory entries to its products:
- **`go`:** the Go toolchain as the consistency check reads it: go.mod's directive that sets the toolchain, `setup-go`, `golang` images.
- **`dotnet`:** `setup-dotnet`, `global.json`, the `sdk`, `aspnet`, `runtime` and `runtime-deps` images and the devcontainer image's .NET line. Lines from .NET 5 on are named by major: `10.0` is line 10.
- **`python`:** `python` image tags and `setup-python` (`3.12.x` is 3.12).
- **`nodejs`:** `node` image tags and `setup-node`, by major.
- **`alpine-linux`:** `alpine` image tags, and the Alpine suffix of any image's tag: `golang:1.25-alpine3.22` is Alpine 3.22.
- **`debian`:** `debian` image tags (`12`, `bookworm-slim`), and distroless images: `gcr.io/distroless/static-debian12` is Debian 12.
- **`ubuntu`:** `ubuntu` image tags (`24.04`, `noble`), until the end of standard support.
- **Codenames** after the version in any image's tag, past variant words such as `slim` or `chiseled`, resolve against the Debian and Ubuntu codenames in endoflife.date's data, by first word: `python:3.12-slim-bookworm` is Debian 12, `aspnet:10.0-noble-chiseled` and the devcontainer's `2.2.3-10.0-noble` are Ubuntu 24.04. A word that is neither, such as a codename not yet in the data, is `unknown`.

Each product is fetched once per scan; each product read is recorded as a tool with its URL and fetch time. Every line in use gets one result, with the entries and locations using it:
- **`end_of_life`:** the data marks it ended (even beside a later date: data that contradicts itself must not read as supported), or its end-of-life date is on or before the scan's date. Without the mark, the date decides, because the mark was computed when the data was generated.
- **`nearing_end_of_life`:** the date is within 90 days after the scan.
- **`supported`:** otherwise, with the date when one is published.
- **`unknown`:** never counted as supported. The declaration names no line (`golang:latest`, a variable, a bare `-alpine`, which follows whichever Alpine the image was last built on); the product's data lacks the line or the codename; the API couldn't be read (an `unavailable_source` gap, after which the scan carries on); or the entry has no mapping.

Go lines get no nearing-end-of-life warning: the data only gives a Go line a date once it has ended, when the release two minors later comes out.

Results for supported, nearing and ended lines list the lines still supported on the scan's date, oldest first. An image or runtime declaration (`runs-on` labels, `setup-*` versions) that no row maps is listed under its own name as `unknown`, so it shows rather than passing silently. Packages aren't: endoflife.date doesn't track them. An image built on Alpine or a codename still needs its own row: `redis:7-alpine3.22` reports Alpine 3.22, and redis 7 as unmapped.

At `064aa09` on 2026-10-09, Go 1.25 is end of life since 2026-08-19, with 1.26 the oldest supported line. .NET 10, Python 3.12, Debian 12 (distroless) and Ubuntu 24.04 (the devcontainer's `noble`) are supported. Alpine is unknown, because `golang:1.25-alpine` and `python:3.12-alpine` don't name a release, and the `ubuntu-latest` runners have no mapping.

## Dependabot PRs

Dependabot's open PRs are the baseline the scan has to match (design decision 7). The scan lists the open PRs by `dependabot[bot]` and each one's commits with the token, which needs `Pull requests: read`, and records when it read them. Each PR becomes one update per dependency: name, from- and to-version, update type, package ecosystem, directory and group.
- **Names, to-versions, update types and groups** come from the `updated-dependencies` block at the end of Dependabot's commit message. Only that block is parsed as YAML, by a loader that builds nothing but strings, lists and maps, so `3.10` stays `3.10`. A dependency the block lists more than once, as #98 does for Azure.Core, counts once.
- **From-versions** come from fixed `… from A to B` lines in the title, the commit message and the body: `Updates `x` from` for most ecosystems, `Updated [x](…) from` in NuGet bodies, `Bumps x from` in NuGet commits, and the title of a single update. The body is read only above its first `<details>` or `<blockquote>`, where upstream release notes start, so they can't set a version. A grouped PR's later lines sit below an earlier one's notes, but its commit message has them all.
- **The PR's changed files are always read**, and their removed lines give each file's version, by a fixed pattern per file type: `PackageVersion` and `PackageReference` versions, `"resolved"` inside the package's block of a `packages.lock.json`, go.mod requirements (not `exclude` or `retract` lines), Dockerfile `FROM` tags and workflow `uses:` refs (a SHA's version comment). Each update lists them; versions drop a leading `v`, and keep the file's own text beside it. A from-version the text states must be among them when there are any; other files at other versions are fine. When the text states none, the diff's versions are the from-versions, and there is one from-version only when they agree. A patch GitHub leaves out or cuts short, or a file list it doesn't give in full, makes the PR unparseable.
- **An update type the block lacks**, as in Docker's #76, is derived from the versions by the first number that differs: `3.12-alpine` to `3.14-alpine` is minor.
- **The ecosystem** comes from Dependabot's branch name. **The directory** comes from the `Bumps the … group … /dir` line or the title's `in /dir`. NuGet PRs name none.

Nothing else in a PR's text is read (decision 9). A PR is `unparseable`, with the reason and no updates, when its block is missing, malformed, over 64 KiB or nested too deeply, a dependency has no from-version or two, its text disagrees with its block or its diff, a commit isn't Dependabot's (authored by `dependabot[bot]`, committed and signed by GitHub), its head moves while it is read, or its commits or diff can't be read. So a partial reading never passes for a complete one. When the PRs can't be listed at all, the record has an `unavailable_source` gap for `dependabot-prs`, and says nothing about them.

Every PR captured on 2026-10-07 parses. #98 needs its diff: Dependabot writes only "Bumps Azure.Core to 1.63.0" and "Pinned … at 1.63.0", because the central version is 1.62.0 while `EgressProxy.Client` and its tests lock 1.53.0 and `AllowlistSeeder` locks 1.55.0. Its diff gives all three, per file. On 2026-10-09 three PRs are open, #75, #76 and #99, and all of them parse into 7 updates.

### Parity

Only PRs that target the scanned branch are compared, or the default branch when the scan names a commit or tag; the others are listed as `not_compared`, with the branch they target. Each update is compared with the inventory of the scanned revision (`src/sdlc/parity.py`). It maps to the entries of its ecosystem (Dependabot's `nuget`, `gomod`, `docker`, `github-actions`, `devcontainers` and a few more, to Renovate's managers and datasources) with its name (NuGet ids ignore case; an image is its path, so `library/golang` is `golang` and Dependabot's `dotnet/sdk` is `mcr.microsoft.com/dotnet/sdk`, with Docker Hub preferred when several registries have the path; an action is its `owner/repo`) in the files its diff changes. A lock file follows the entry that governs it: a version in the project file next to it, or else the nearest `Directory.Packages.props` above it. Then, in this order:
- **`stale`:** every file it changes that the scan can read has another version than the one it replaces. Each file is checked against the revision's version in that same file; for a lock file, the version it resolves in the checkout, which may be above the declared one. A file the revision doesn't have at all is different: the PR was made for a revision that has it, as #75 was once rebased onto a `main` with `images.yml`. A file the scan can't check, such as one in a submodule, is unknown, not different. So #98's Azure.Core is current: 1.62.0 centrally, and 1.53.0 and 1.55.0 in the drifted lock files. When only some files differ, the update isn't stale, those files are left out, and the reason names them. A PR with a stale update is stale.
- **`held by policy`:** per entry, Renovate's classification of a candidate at Dependabot's version decides; without one, the policy's hold rules are evaluated on the update itself, with the version as the entry writes it (`v1.23.2` in go.mod). The record names the rules. A rule the scan can't evaluate makes the comparison incomplete.
- **`matched`:** every entry in every file it changes, apart from the stale ones, has an in-scope candidate at the same or a newer version; a lock file's entry may be covered by the entry that governs it. Image tags compare by their numbers, and only with the same suffix: `1.27-alpine` matches `1.27-alpine` or `1.28-alpine`, not `1.27` or `1.27-bookworm`. NuGet's prerelease labels ignore case. The record names the closest candidate.
- **`missed`:** otherwise, with a reason per entry that falls short: not in the inventory in a file it changes, an unknown or skipped lookup, no candidate, or only older or held ones.

The in-scope candidates of entries no compared update maps to are scan-only; the report lists them by ecosystem. The comparison is incomplete, with the reasons, when a compared PR is unparseable or a hold can't be evaluated. When the PRs can't be read, nothing is compared and nothing is scan-only. The PRs' read time and the lookups' time are both recorded.

At `064aa09`, every update of the five PRs open then is matched, #77 by AppHost's lock-drift entry; closed #78 would be held by the trial policy, and closed #88 is stale. On `main` (`e93d706`) on 2026-10-09, all 7 updates of #75, #76 and #99 are matched, and 22 entries are scan-only, such as PyJWT, govulncheck, the Aspire CLI and Bicep API versions.

## Coverage gaps

The scan reports a gap rather than staying silent when:
- **a file type declares dependencies but no adapter reads it.** Today these are Packer templates and cloud-init configs. At `064aa09`, `infra/assets/cloud-init.yaml`, which installs packages without versions and downloads the proxy binary, is the one gap.
- **a lock file can't be parsed.** Renovate doesn't parse lock files in lookup mode, so the scan checks them itself.
- **a line installs a package without a version**, such as `pip install pkg` or `go install …@latest`.
- **a package manager query fails**, for example when a locked restore breaks.
- **a declaration in the alias table has no version to compare**, such as `golang:latest`, `golang:${GO_VERSION}` or Go `1.x`.
- **endoflife.date can't be read**, or answers with an error or malformed data. The lines of the products concerned are `unknown`.
- **Dependabot's alerts or open PRs can't be read.** Nothing is then said about them.

A file type Renovate does read, such as a project file with only project references, isn't a gap when Renovate finds nothing in it.

## Known limits

- **The VM scale set's Marketplace image** (`version: 'latest'` in `hub.bicep`) isn't tracked. It's managed by Azure and upgraded automatically.
- **`gcr.io/distroless/static-debian12:nonroot`** has no version tag. It could only be tracked by digest, so it is skipped. Its Debian release's lifecycle is reported.
- **OS releases are read from image tags only for Alpine, Debian and Ubuntu.** Others, such as Azure Linux or Windows Server Core, aren't.
- **The Marketplace image build** (Packer, platform image, OS packages) isn't covered yet. A Packer template shows up as a coverage gap until it is.
