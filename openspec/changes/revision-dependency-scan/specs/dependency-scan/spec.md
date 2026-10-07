# Spec Delta

## Purpose

The dependency scan tells the maintainer, and later slices of the SDLC system, everything that can be updated in a pinned revision of a subject repository: what is declared, what newer versions exist, what the repository's policy allows, what is known to be vulnerable, and what the scan could not cover.

## ADDED Requirements

### Requirement: Scan a pinned revision

The scan SHALL take a subject repository and a ref, resolve the ref to a commit before scanning, and scan a disposable copy of that commit. The record SHALL identify the repository, the commit, the scan time and the version of every tool that contributed to it.

#### Scenario: A branch name is resolved to a commit

- **WHEN** the scan is started with the subject repository and the ref `main`
- **THEN** the record names the commit `main` pointed to at scan time, and every result in it refers to that commit

#### Scenario: An unknown ref stops the scan

- **WHEN** the ref can't be resolved in the subject repository
- **THEN** the scan fails with that reason and writes no record

### Requirement: Inventory declared dependencies

The scan SHALL list every dependency declared in the revision for each supported source type, with its ecosystem, name, current version or constraint, whether it is direct or resolved from a lockfile, and the file and location that declares it.

#### Scenario: Supported sources appear in the inventory

- **WHEN** the revision contains NuGet central versions and lockfiles, `go.mod`, Dockerfile `FROM` lines, workflow `uses:` pins, Bicep `br/public` module references, devcontainer features or tool versions, or an inline `pip install` with a pinned version
- **THEN** each declared dependency appears in the inventory with its file and location

#### Scenario: The same dependency in several files is listed per location

- **WHEN** one dependency is declared in more than one file
- **THEN** the inventory lists each declaration with its own location and version

### Requirement: Report coverage gaps

The scan SHALL report every dependency-bearing file or declaration it detects but can't inventory, with the reason. A source the scan can't parse or doesn't support SHALL NOT be omitted silently.

#### Scenario: An unsupported source type is present

- **WHEN** the revision contains a Packer template with `required_plugins`, and no supported adapter reads it
- **THEN** the record lists the file as an unsupported source

#### Scenario: A supported file can't be parsed

- **WHEN** a file of a supported type is malformed
- **THEN** the record lists the file as unparseable with the parser's error, and the rest of the scan continues

### Requirement: Find update candidates

For each inventoried dependency the scan SHALL report the newest available version for each update type the source offers (patch, minor, major), with the source it queried and the time of the lookup. A failed lookup SHALL be reported as `unknown` with the reason, never as up to date.

#### Scenario: Newer minor and major versions exist

- **WHEN** a dependency at `2.12.2` has `2.13.0` and `3.10.2` available
- **THEN** the record lists `2.13.0` as the minor candidate and `3.10.2` as the major candidate

#### Scenario: A lookup fails

- **WHEN** the registry or API for a dependency is unreachable, rate-limited or denies access
- **THEN** the dependency's candidate state is `unknown`, with the failure reason

#### Scenario: No newer version exists

- **WHEN** the lookup succeeds and no newer version exists
- **THEN** the dependency is reported as current, citing the lookup

### Requirement: Classify candidates by the subject's update policy

The scan SHALL read the update policy from the subject repository at the scanned revision and classify each candidate as `in scope` or `held by policy`, naming the rule that holds it. Held candidates SHALL stay in the record. The record SHALL state which policy was used.

#### Scenario: A platform-coupled major is held

- **WHEN** the policy holds .NET-runtime-coupled NuGet majors until the runtime moves to the next major, and a NuGet package has an `11.x` candidate while the runtime is `10`
- **THEN** the candidate is `held by policy`, naming that rule

#### Scenario: The revision has no policy

- **WHEN** the revision contains no update policy and no trial policy is supplied
- **THEN** the record states that no policy was found, and classifies every candidate as `in scope`

#### Scenario: A trial policy is supplied

- **WHEN** the maintainer supplies a policy file explicitly for the run
- **THEN** the scan uses it instead of any policy in the revision, and the record names the trial file

#### Scenario: The policy is invalid

- **WHEN** the policy can't be parsed or contains an unknown rule
- **THEN** the scan fails with the policy error and writes no record, rather than widening scope

### Requirement: Report known vulnerabilities

The scan SHALL report known vulnerabilities in the inventoried versions, with the advisory identifier, affected package and version, the fixed version when one exists, and the advisory source. Reachability SHALL be reported separately from a version match, as `reachable`, `not reachable` or `unknown`.

#### Scenario: A vulnerable version has a fix

- **WHEN** an inventoried version matches an advisory with a fixed version
- **THEN** the record lists the advisory, the fixed version, and whether an update candidate reaches the fixed version

#### Scenario: Reachability can't be determined

- **WHEN** no reachability analysis exists for the dependency's ecosystem
- **THEN** reachability is `unknown`, not `not reachable`

#### Scenario: An advisory source is unavailable

- **WHEN** an advisory source can't be read, such as Dependabot alerts without permission
- **THEN** the record lists the source as unavailable, and does not claim the dependency has no vulnerabilities

### Requirement: Report end-of-life versions

For platforms, language toolchains and base images with published lifecycle data, the scan SHALL report whether the version line in use is supported, its end-of-life date, and the oldest supported line. Missing lifecycle data SHALL be reported as `unknown`, not as supported.

#### Scenario: A toolchain line is past end of life

- **WHEN** the revision builds with Go `1.25` and lifecycle data shows that line ended when Go `1.27` was released
- **THEN** the record marks the Go toolchain as end of life, with the date and the supported lines

#### Scenario: A version line nears end of life

- **WHEN** a line's end-of-life date falls within 90 days of the scan
- **THEN** the record marks it as nearing end of life, with the date

#### Scenario: No lifecycle data exists

- **WHEN** no lifecycle data is available for a platform or image
- **THEN** its lifecycle state is `unknown`

### Requirement: Flag inconsistent declarations

The scan SHALL flag a logical dependency whose declarations in different files resolve to different versions at the precision each declares, and list every declaring location.

#### Scenario: The Go toolchain differs between files

- **WHEN** `go.mod` declares `go 1.25.14`, the workflows set up Go `1.25`, and a Dockerfile builds with `golang:1.27-alpine`
- **THEN** the Go toolchain is flagged as inconsistent, listing all three locations and versions

#### Scenario: Declarations agree at their precision

- **WHEN** `go.mod` declares `go 1.25.14` and the workflows set up Go `1.25`
- **THEN** the Go toolchain is not flagged

### Requirement: Compare with open Dependabot PRs

The scan SHALL compare its candidates with the updates proposed by open Dependabot PRs at scan time. Every in-scope update Dependabot proposes from the revision's current version SHALL appear as a candidate at the same or a newer version, or the record SHALL report it as `missed` with a reason.

#### Scenario: Dependabot's update is matched

- **WHEN** an open Dependabot PR proposes `1.23.1 → 1.23.2` and the scan's candidate is `1.23.2` or newer
- **THEN** the PR's update is reported as `matched`, with both versions

#### Scenario: Dependabot proposes what the policy holds

- **WHEN** an open Dependabot PR proposes an update the subject's policy holds
- **THEN** the update is reported as `held by policy`, not as `missed`

#### Scenario: The scan misses an update

- **WHEN** an open Dependabot PR proposes an in-scope update that has no matching candidate
- **THEN** the update is reported as `missed`, with the reason when known

#### Scenario: A Dependabot PR is stale for the revision

- **WHEN** a PR's from-version differs from the version declared in the scanned revision
- **THEN** the PR is reported as `stale` and not counted as matched or missed

#### Scenario: The scan finds more than Dependabot

- **WHEN** an in-scope candidate has no corresponding open Dependabot PR
- **THEN** the record lists it as found by the scan only

#### Scenario: A Dependabot PR can't be parsed

- **WHEN** a PR's proposed updates can't be read from its metadata
- **THEN** the PR is listed as `unparseable` and the parity result states that it is incomplete

### Requirement: Leave the subject repository unchanged

The scan SHALL NOT write to the subject repository or its hosting: no pushes, branches, PRs, comments, labels or workflow runs. It SHALL use only read-only credentials, and SHALL store its outputs outside the subject repository.

#### Scenario: A scan has no remote effect

- **WHEN** a scan completes
- **THEN** the subject's branches, PRs, check runs and workflow runs are unchanged, and no output file is in the subject repository

### Requirement: Produce paired, versioned outputs

Each scan SHALL produce a machine-readable record conforming to a versioned schema and a Markdown report rendered from that record. Both SHALL name the repository, commit, scan time, tool versions and policy source.

#### Scenario: Both outputs describe the same scan

- **WHEN** a scan completes
- **THEN** every inventory entry, candidate, vulnerability, inconsistency, parity result and gap in the Markdown report comes from the record, and the record states its schema version

#### Scenario: A record fails its schema

- **WHEN** the generated record doesn't conform to its schema
- **THEN** the scan fails and writes no Markdown report
