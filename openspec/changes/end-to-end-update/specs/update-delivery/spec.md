## Purpose

Update delivery brings checked changes to the subject repository as draft PRs from a fork, keeps those PRs in step with the selection, and reads their CI results back, so that every run reports where each unit stands.

## ADDED Requirements

### Requirement: Push only to the fork

Delivery SHALL push only to a fork of the subject owned by the system's machine account, using that account's token. It SHALL never push to the subject repository, and SHALL push a unit's branch only when its content differs from what the fork already has.

#### Scenario: Nothing changed since the last run

- **WHEN** a unit's change is identical to the branch already on the fork
- **THEN** nothing is pushed, and the PR's CI isn't started again

### Requirement: Keep one draft PR per unit

Each delivered unit SHALL have exactly one PR on the subject, from its branch on the fork, opened as a draft. Its body SHALL come from the record: the unit's reason and evidence, its targets, the check result, whether the agent made changes, and the "needs review" mark when it applies. Delivery SHALL NOT mark a PR ready, approve or merge it.

#### Scenario: A unit is delivered for the first time

- **WHEN** a unit passes its check and has no PR yet
- **THEN** a draft PR is opened from its branch, with a body taken from the record

#### Scenario: A unit's change is updated

- **WHEN** a unit with an open PR gets a different change
- **THEN** the branch is updated and the PR body is rewritten from the record

### Requirement: Close PRs whose unit is gone

A PR SHALL be closed when its unit is no longer selected, with a comment giving the reason. A batch unit's PR SHALL be left unchanged while the batch window is closed.

#### Scenario: The fix was merged another way

- **WHEN** a security unit's vulnerability is no longer present on `main`
- **THEN** its PR is closed, saying the reason no longer holds

#### Scenario: A batch PR outside the window

- **WHEN** a run outside the batch window finds an open batch PR
- **THEN** the PR is left as it is

### Requirement: Read CI results back

Each run SHALL read the check results of every open PR it manages, and record each unit's state as checks passed, checks failed or checks pending. A check that couldn't be read SHALL be recorded as unknown, never as passed.

#### Scenario: A check is still running

- **WHEN** a PR has a check in progress
- **THEN** its unit is recorded as checks pending

#### Scenario: The check results can't be read

- **WHEN** reading a PR's checks fails
- **THEN** its unit's CI state is recorded as unknown, with the reason

### Requirement: Report every unit's outcome

Each run SHALL produce a prepare record conforming to a versioned schema, and a Markdown report rendered from it. For each selected unit, they SHALL give its outcome and the link to its PR when there is one. The outcome is one of: checks passed, checks failed, checks pending, apply failed, check failed or no applier yet.

#### Scenario: A run with mixed outcomes

- **WHEN** a run delivers one unit, fails the check of another, and finds no applier for a third
- **THEN** the record and the report list all three, each with its outcome, and the delivered one with its PR link
