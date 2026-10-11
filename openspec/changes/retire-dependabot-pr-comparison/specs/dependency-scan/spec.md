## REMOVED Requirements

### Requirement: Compare with open Dependabot PRs

**Reason**: Slice 1 has shown that the scan finds what Dependabot's version-update PRs propose. Those PRs are retired once slice 2 runs, so there will be nothing left to compare with.
**Migration**: None. Dependabot alerts stay as a second source for vulnerabilities, under "Report known vulnerabilities". Records written with the version 1 schema keep their comparison section and stay valid under that schema.

## MODIFIED Requirements

### Requirement: Produce paired, versioned outputs

Each scan SHALL produce a machine-readable record conforming to a versioned schema and a Markdown report rendered from that record. Both SHALL name the repository, commit, scan time, tool versions and policy source.

#### Scenario: Both outputs describe the same scan

- **WHEN** a scan completes
- **THEN** every inventory entry, candidate, vulnerability, inconsistency and gap in the Markdown report comes from the record, and the record states its schema version

#### Scenario: A record fails its schema

- **WHEN** the generated record doesn't conform to its schema
- **THEN** the scan fails and writes no Markdown report
