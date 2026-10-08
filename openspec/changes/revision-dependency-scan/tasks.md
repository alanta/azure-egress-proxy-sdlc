# Tasks

## 1. Evidence, scaffolding and engine checks

- [x] 1.1 Capture evidence from the subject repository before it changes further: for open PRs #75, #76, #77, #98, #99 and closed PRs #78, #88, #89, store PR metadata, commit messages, diffs and check runs (and logs where readable) under `fixtures/azure-egress-proxy/prs/`, with the capture time and the main commit at that moment; verify every PR has metadata, commit messages and check runs on disk, and unreadable logs are listed in a manifest
- [x] 1.2 Create the Python CLI project (packaging, lint, tests, a CI workflow in this repository) with a `scan` command that prints usage; verify CI passes and `scan --help` runs
- [x] 1.3 Run pinned Renovate (by digest) in local lookup mode with `reportType=file` and a read-only token against the subject at `064aa09`; verify the report file contains extracted dependencies and lookup results for NuGet, Go modules, Dockerfiles, GitHub Actions and devcontainer features, and record the result and the fallback decision in `docs/tooling-spike.md`
- [x] 1.4 Add custom managers for the inline PyJWT install, AVM module tags (Docker datasource on MCR) and devcontainer tool versions; verify each yields a current version and candidates on `064aa09`, and record any that don't work as unsupported sources in `docs/tooling-spike.md`
- [ ] 1.5 Define the scan record JSON Schema v1 (repository, commit, times, tool versions, policy source, inventory, candidates, vulnerabilities, inconsistencies, parity, gaps); verify a valid fixture passes and fixtures with a missing commit, an unknown candidate state or an unknown parity state are rejected

## 2. Inventory, candidates and gaps

- [ ] 2.1 Resolve the ref to a commit and clone the subject into a temporary directory; verify `main` is recorded as its commit, an unknown ref fails with no record, and the clone is discarded after the run
- [ ] 2.2 Normalise Renovate's report into inventory entries and per-update-type candidates with datasource and lookup time, with failed lookups as `unknown`; verify unit tests on the report captured in 1.3, including a rate-limited lookup
- [ ] 2.3 Detect dependency-bearing files by pattern (including `*.pkr.hcl`, `requirements*.txt`, `package.json`, inline `pip install` and `apt-get install` lines) and report those no adapter covered as unsupported or unparseable; verify a fixture with a Packer template and a malformed lockfile reports both, and the scan still completes
- [ ] 2.4 Run the native NuGet and Go queries (design decision 3) and report disagreements with Renovate; verify on `064aa09` and record the disagreements found
- [ ] 2.5 Document the supported source types, the custom managers and the known gaps in `docs/scan-coverage.md`; verify the document matches the inventory and gaps of a `064aa09` scan

## 3. Update policy

- [ ] 3.1 Load the policy from `.github/renovate.json5` at the revision, or from an explicitly supplied trial file; classify candidates as `in scope` or `held by policy` with the rule; fail on an invalid policy; verify tests for a held platform-coupled major, no policy found, a trial policy recorded in the output, and an invalid policy failing with no record
- [ ] 3.2 Write the trial policy for `azure-egress-proxy` in `policies/azure-egress-proxy.renovate.json5`, carrying over `dependabot.yml`'s intent (the `Microsoft.OpenApi` 3.x hold, weekly grouping of minor and patch updates) and holding NuGet majors coupled to the .NET runtime, with a reason comment per rule; verify a scan of `064aa09` with it holds `Microsoft.OpenApi` 3.x and every runtime-coupled `11.x` candidate

## 4. Vulnerabilities and consistency

- [ ] 4.1 Run pinned OSV-Scanner on the lockfiles and map its results to inventory entries with fixed versions and whether a candidate reaches them; verify on `064aa09` (the spike found three `golang.org/x/crypto` advisories), with unresolved packages reported as unknown
- [ ] 4.2 Run govulncheck with the `go.mod` toolchain and record reachability separately from version matches; verify on `064aa09`, and that non-Go advisories report reachability `unknown`
- [ ] 4.3 Read Dependabot alerts when the credential allows it, otherwise record the source as unavailable; verify both paths, with and without the permission
- [ ] 4.4 Implement the alias table and the consistency check (design decision 6); verify `064aa09` has no Go toolchain inconsistency, and the head of PR #76 (captured in 1.1) flags `golang:1.27-alpine` against `go 1.25.14` and `setup-go 1.25`

- [ ] 4.5 Look up lifecycle data from endoflife.date for the Go toolchain, .NET images, Python, Alpine and distroless Debian, and report end-of-life and nearing-end-of-life lines; verify a scan of `064aa09` marks Go 1.25 as end of life, unmapped entries report `unknown`, and an unreachable API reports `unknown` for all

## 5. Dependabot parity

- [ ] 5.1 Read open Dependabot PRs and parse their proposed updates from the commit metadata and the from-versions from title or body; verify against the fixtures from 1.1, including grouped PRs #75, #76, #98 and #99 and a deliberately corrupted message reported as `unparseable`
- [ ] 5.2 Classify each proposed update as `matched`, `held by policy`, `missed` or `stale`, and list scan-only candidates; verify fixture tests for each state, including a removed candidate reported as `missed`

## 6. Reports and end-to-end runs

- [ ] 6.1 Render the Markdown report from the record only, and fail without a report when the record fails its schema; verify a test that every record section appears in the report, and that an invalid record produces no report
- [ ] 6.2 Run a live end-to-end scan of the subject's current `main` with the trial policy; verify every in-scope update from open Dependabot PRs is `matched` or explained, the known gaps (PyJWT, AVM tags, the Go directive) appear as candidates or gaps, and the subject's branches, PRs and runs are unchanged; commit the run under `fixtures/` and record mismatches in `docs/`
- [ ] 6.3 Write the runbook in `docs/running-a-scan.md`: inputs, the read-only credential and its permissions, the trial-policy option, outputs and how to read them; verify a fresh scan following only the runbook succeeds
