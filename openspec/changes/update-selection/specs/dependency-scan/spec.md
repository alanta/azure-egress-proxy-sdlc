## MODIFIED Requirements

### Requirement: Find update candidates

For each inventoried dependency the scan SHALL report the newest available version for each update type the source offers (patch, minor, major), with the source it queried, the time of the lookup, and the candidate's release date when the source publishes one. A failed lookup SHALL be reported as `unknown` with the reason, never as up to date. A dependency listed only because an advisory concerns it is not looked up: its candidate SHALL be the advisory's fixed version, and the record SHALL say that the candidate came from the advisory, not from a registry lookup.

#### Scenario: Newer minor and major versions exist

- **WHEN** a dependency at `2.12.2` has `2.13.0` and `3.10.2` available
- **THEN** the record lists `2.13.0` as the minor candidate and `3.10.2` as the major candidate

#### Scenario: A lookup fails

- **WHEN** the registry or API for a dependency is unreachable, rate-limited or denies access
- **THEN** the dependency's candidate state is `unknown`, with the failure reason

#### Scenario: No newer version exists

- **WHEN** the lookup succeeds and no newer version exists
- **THEN** the dependency is reported as current, citing the lookup

#### Scenario: A dependency is listed only for its advisory

- **WHEN** an advisory with a fixed version concerns a dependency that only appears in a lock file or as an indirect module
- **THEN** the dependency's candidate is the fixed version, marked as coming from the advisory, and its lookup records no registry query or lookup time

#### Scenario: The source publishes release dates

- **WHEN** the source publishes a release date for a candidate
- **THEN** the record gives that date with the candidate

#### Scenario: The source publishes no release date

- **WHEN** the source publishes no release date for a candidate
- **THEN** the candidate has no release date in the record, and nothing claims one

### Requirement: Classify candidates by the subject's update policy

The scan SHALL read the update policy from the subject repository at the scanned revision and classify each candidate as `in scope` or `held by policy`, naming the rule that holds it. Held candidates SHALL stay in the record. Each candidate SHALL also carry the group that the policy's group rules put it in, or none. The record SHALL state which policy was used.

#### Scenario: A platform-coupled major is held

- **WHEN** the policy holds .NET-runtime-coupled NuGet majors until the runtime moves to the next major, and a NuGet package has an `11.x` candidate while the runtime is `10`
- **THEN** the candidate is `held by policy`, naming that rule

#### Scenario: A candidate in a policy group

- **WHEN** the policy groups minor and patch updates of Microsoft packages as `microsoft`, and a Microsoft package has a minor candidate
- **THEN** the candidate carries the group `microsoft`

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

The scan SHALL report known vulnerabilities in the inventoried versions, with the advisory identifier, affected package and version, the fixed version when one exists, and the advisory source. It SHALL also report which in-scope candidates are outside the advisory's affected ranges. Reachability SHALL be reported separately from a version match, as `reachable`, `not reachable` or `unknown`.

#### Scenario: A vulnerable version has a fix

- **WHEN** an inventoried version matches an advisory with a fixed version
- **THEN** the record lists the advisory, the fixed version, whether an update candidate reaches the fixed version, and which in-scope candidates do

#### Scenario: A higher version is affected again

- **WHEN** an advisory affects `[0, 6.0.5)` and `[6.1.0, 6.1.2)`, the dependency is at `6.0.1`, and its in-scope candidates are `6.1.1` and `7.0.0`
- **THEN** the record lists only `7.0.0` as reaching the fix

#### Scenario: A vulnerability concerns an indirect dependency

- **WHEN** an advisory matches a dependency that only appears in a lock file or as an indirect module
- **THEN** the inventory lists that dependency as a locked entry, so the vulnerability can refer to it

#### Scenario: Reachability can't be determined

- **WHEN** no reachability analysis exists for the dependency's ecosystem
- **THEN** reachability is `unknown`, not `not reachable`

#### Scenario: An advisory source is unavailable

- **WHEN** an advisory source can't be read, such as Dependabot alerts without permission
- **THEN** the record lists the source as unavailable, and does not claim the dependency has no vulnerabilities
