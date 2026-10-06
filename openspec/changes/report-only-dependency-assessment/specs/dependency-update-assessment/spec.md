# Spec Delta

## Purpose

The dependency update assessment gives maintainers a traceable, read-only view of dependency coverage, update candidates, likely impact, and validation evidence for a repository revision. It makes gaps and uncertainty visible before any automation is allowed to change code or release artifacts.

## ADDED Requirements

### Requirement: Inventory dependency sources and update coverage
The assessment SHALL inventory recognized dependency declarations and build inputs in the selected repository revision, identifying their source, owning component, current version when determinable, and update coverage. Unsupported, unparseable, or inaccessible sources SHALL be reported as uncovered or unknown rather than silently omitted.

#### Scenario: Recognized sources appear in the inventory
- **WHEN** the selected revision contains package manifests or lockfiles, container base-image references, CI action pins, infrastructure module versions, or image-build inputs
- **THEN** the report identifies each discovered source, its component, its current version when determinable, and whether an update mechanism covers it

#### Scenario: A source cannot be assessed
- **WHEN** a dependency declaration cannot be parsed or its update source cannot be queried
- **THEN** the report identifies the source and location as unknown or uncovered and states why it could not be assessed

#### Scenario: Inventory coverage is incomplete
- **WHEN** the assessment cannot inspect a dependency surface such as private alerts or a registry
- **THEN** the report states the coverage limitation and SHALL NOT claim that the inventory or vulnerability status is complete

### Requirement: Assess candidate updates and affected outputs
For each discovered or supplied candidate update, the assessment SHALL record the old and candidate versions, evidence sources, likely affected components and release artifacts, and relevant compatibility or security concerns. An uncertain impact SHALL be identified as uncertain and SHALL NOT be presented as verified.

#### Scenario: Candidate update has known project usage
- **WHEN** an update candidate is found or supplied for a dependency
- **THEN** the report links it to the components and outputs that consume it and explains the evidence for that mapping

#### Scenario: Candidate update has unresolved impact
- **WHEN** the dependency's consumers or affected outputs cannot be established from available evidence
- **THEN** the report marks the impact as unknown or uncertain and identifies the missing evidence

#### Scenario: Release evidence is inaccessible
- **WHEN** release notes, advisories, private alerts, or CI details cannot be retrieved
- **THEN** the report records the unavailable evidence as a limitation and does not infer that the change is safe

### Requirement: Report validation outcomes without treating skips as success
For every relevant expected check, the assessment SHALL report exactly one state: `passed`, `failed`, `skipped`, `not applicable`, or `unknown`. A check SHALL be `passed` only when evidence confirms it completed successfully for the affected change and output.

#### Scenario: Required check succeeds
- **WHEN** an applicable check completed successfully for the assessed revision or candidate
- **THEN** the report marks that check `passed` and identifies the evidence

#### Scenario: Relevant check is skipped
- **WHEN** a relevant check did not run, including because of a path filter
- **THEN** the report marks it `skipped` and SHALL NOT count it as passed

#### Scenario: Check result is unavailable
- **WHEN** the check's result or logs cannot be accessed
- **THEN** the report marks it `unknown` and explains the evidence gap

#### Scenario: Check does not apply
- **WHEN** a check is not required for the affected dependency or output
- **THEN** the report marks it `not applicable` and records the reason

### Requirement: Explain risk with traceable evidence
The assessment SHALL classify each candidate update as `low`, `medium`, `high`, or `unknown` risk, distinguishing observed facts from inference and identifying evidence, uncertainty, and relevant security or compatibility concerns. This preliminary classification SHALL NOT authorize code changes, merges, or releases.

#### Scenario: Evidence supports a risk assessment
- **WHEN** sufficient source, advisory, change, and validation evidence is available
- **THEN** the report gives a risk level and a concise rationale tied to that evidence

#### Scenario: Evidence is insufficient
- **WHEN** material evidence is missing or contradictory
- **THEN** the report classifies the assessment as `unknown` or otherwise explicitly uncertain and identifies what would resolve the uncertainty

### Requirement: Produce a revision-bound, read-only assessment
Each assessment SHALL identify the subject repository and exact revision, any assessed update or pull request, the assessment time, and the evidence sources used in both human-readable and machine-readable outputs. The pilot SHALL NOT modify the subject repository, create or update pull requests, merge changes, deploy resources, or publish artifacts.

#### Scenario: Assessment is reproducible
- **WHEN** a report is generated
- **THEN** a reader can identify the exact subject revision and candidate, distinguish collected evidence from inference, and locate the report outputs

#### Scenario: Assessment runs in report-only mode
- **WHEN** the assessment completes
- **THEN** the subject repository and its release or deployment state remain unchanged
