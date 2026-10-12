## Purpose

Update application turns each selected unit into a change on its own branch, made by a deterministic applier or by a coding agent, and accepts the change only once deterministic checks have passed.

## ADDED Requirements

### Requirement: Start every unit from the scanned commit

Each unit's change SHALL be made on a fresh branch from the commit of `main` that the scan described, in a disposable checkout. Nothing from an earlier run's branch SHALL carry over into the change.

#### Scenario: A unit already has a branch

- **WHEN** a unit's branch from an earlier run exists, and `main` has moved since
- **THEN** the change is made again from the newly scanned commit

### Requirement: Apply routine units deterministically

A routine unit SHALL be applied by replacing each target's current version at the file and location the scan recorded, then refreshing the lock files of the affected ecosystem with its own tools.

#### Scenario: A NuGet update with a central version and lock files

- **WHEN** a routine unit raises a package declared in `Directory.Packages.props`, and projects lock their packages
- **THEN** the central version is changed and the lock files are regenerated with the .NET tools

#### Scenario: A Go module update

- **WHEN** a routine unit raises a module in `go.mod`
- **THEN** `go.mod` and `go.sum` are updated with the Go tools

#### Scenario: A container image tag

- **WHEN** a routine unit raises the tag of an image in a Dockerfile
- **THEN** the tag is changed where the scan recorded it, and no other line changes

### Requirement: Report units without an applier

A routine unit with a target the applier can't change, such as a reference pinned by digest, SHALL NOT be applied in part. It SHALL be reported as "no applier yet", with the target that stopped it.

#### Scenario: An action pinned by SHA

- **WHEN** a routine unit contains an action pinned by commit SHA
- **THEN** the unit is reported as "no applier yet", naming that action, and no branch is changed

### Requirement: Let the agent apply breaking units

A breaking unit SHALL be applied by a coding agent, in a single attempt. The agent SHALL get the unit, its targets and the scan's evidence for it. It SHALL NOT get upstream release notes, changelogs or PR text.

#### Scenario: A lifecycle move

- **WHEN** a lifecycle unit moves Go from 1.25 to 1.27
- **THEN** the agent makes the change, builds and tests in its sandbox, and its result goes to the checks

### Requirement: Repair a failed unit once

When a unit's PR has failed CI checks and has had no repair yet, the next run SHALL give the agent one repair attempt. The agent SHALL get the unit, the current diff and the failed checks' output. A unit that still fails after its repair SHALL be reported as failed, without another attempt.

#### Scenario: CI fails after a routine update

- **WHEN** a routine unit's PR has a failed check and no repair yet
- **THEN** the agent gets one attempt, and its result goes to the checks

#### Scenario: CI fails after a repair

- **WHEN** a unit's PR still fails after its repair
- **THEN** the unit is reported as failed, and no further attempt is made

### Requirement: Contain the agent

The agent SHALL run in a sandbox that holds no credential for GitHub or the subject repository. Its network access SHALL be limited to the model's API and the package registries the build needs. It SHALL NOT push, open PRs or change anything outside its checkout.

#### Scenario: The agent tries to push

- **WHEN** the agent runs `git push` in its sandbox
- **THEN** the push fails for lack of a credential and a route, and only the files in the checkout are kept

### Requirement: Check every change deterministically

Every change, whoever made it, SHALL be scanned again before it is accepted. It SHALL pass only when every target of the unit is reached, and no other dependency's version has changed. A change that fails SHALL NOT be delivered, and the report SHALL say why.

#### Scenario: The change reaches its targets

- **WHEN** the re-scan shows every target at its new version, and every other dependency as before
- **THEN** the change passes the check

#### Scenario: The agent raised another dependency

- **WHEN** the re-scan shows a dependency outside the unit at a different version
- **THEN** the change fails the check, naming that dependency, and isn't delivered

### Requirement: Flag changes that need review

A change that touches `.github/workflows/` or `infra/` SHALL be marked "needs review", whatever its checks say.

#### Scenario: A repair edits a workflow

- **WHEN** the agent's repair changes a file under `.github/workflows/`
- **THEN** the change is marked "needs review"

### Requirement: Record who made each change

The record SHALL state, for each change, whether a deterministic applier or the agent made it. For the agent, it SHALL state the model and the input it was given.

#### Scenario: A repaired unit

- **WHEN** a unit was applied deterministically and then repaired by the agent
- **THEN** the record lists both steps, with the model for the repair
