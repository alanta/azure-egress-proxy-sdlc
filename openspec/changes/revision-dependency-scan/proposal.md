# Proposal

## Why

The end goal is hands-off maintenance of `azure-egress-proxy`: updates applied, built, tested, repaired and merged, with release advice, and as little maintainer effort as possible. Everything after this depends on one thing: knowing what can be updated in a given revision. This first slice builds that scan. It must find at least what Dependabot proposes, so it can eventually replace it, and it must show what it can't cover instead of hiding it.

## What Changes

- Scan a pinned revision of a subject repository and inventory every dependency it declares: NuGet, Go modules and toolchain, Dockerfile bases, GitHub Actions, Bicep AVM modules, devcontainer tooling and inline package installs.
- Find update candidates for each dependency (patch, minor and major), and report lookups that fail as `unknown`, never as up to date.
- Apply the update policy kept in the subject repository, so that a candidate it rules out, such as a NuGet major tied to the next .NET runtime, is reported as held by policy rather than dropped.
- Report known vulnerabilities in the inventoried versions, with reachability kept separate from a version match.
- Flag one logical dependency declared at different versions in different places, such as the Go toolchain in `go.mod`, the workflows and a Dockerfile.
- Compare the result with the open Dependabot PRs at scan time. Every in-scope update Dependabot proposes is matched, or the miss is explained.
- Write a machine-readable record and a Markdown report from the same result. Nothing is written to the subject repository and no LLM is involved.

Slice 1 doesn't apply updates, run builds, assess risk or summarise release notes. Those belong to slices 2 and 3 (see the README).

## Capabilities

### New Capabilities

- `dependency-scan`: inventory, update candidates, policy classification, vulnerability matches, consistency checks and Dependabot parity for a pinned revision of a subject repository, delivered as an auditable record.

### Modified Capabilities

None.

## Impact

- **This repository:** a scan CLI, adapters around existing tools (Renovate, OSV-Scanner, govulncheck, native package-manager queries), a versioned record schema, captured evidence fixtures and a runbook.
- **Subject repository (`azure-egress-proxy`):** read only. It gains an update-policy file later, through a PR the maintainer reviews. Until then a trial policy kept here stands in for it.
- **Credentials:** a read-only GitHub credential for API lookups, PR metadata and, when granted, Dependabot alerts. No write access.
