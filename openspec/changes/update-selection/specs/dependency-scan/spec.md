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
