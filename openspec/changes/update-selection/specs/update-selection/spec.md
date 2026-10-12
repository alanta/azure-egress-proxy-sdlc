## Purpose

Update selection decides, deterministically, which updates the system prepares for a scanned revision, why, to which versions, and whether each is breaking. It also reports what it can't prepare and why.

## ADDED Requirements

### Requirement: Select from the scan alone

Selection SHALL be decided from three inputs only: the scan record, the update policy the scan used, and the scan's date. It SHALL keep no state between scans. The same inputs SHALL always give the same selection.

#### Scenario: The same scan is selected twice

- **WHEN** selection runs twice on the same record, policy and date
- **THEN** both runs give the same units, with the same reasons, targets and breaking marks

#### Scenario: An update stays unmerged

- **WHEN** a unit's reason still holds in a scan of a later commit, because its update hasn't been merged
- **THEN** that scan selects the unit again

### Requirement: Target only in-scope candidates

Every target of a unit SHALL be one of the scan's in-scope candidates. A candidate that the policy holds SHALL never be a target, whatever the reason for the unit.

#### Scenario: Only a held candidate reaches the fix

- **WHEN** a dependency is vulnerable and every candidate that reaches the fix is held by policy
- **THEN** no unit is selected for it

### Requirement: Select security fixes

For each inventoried dependency with a known vulnerability that an in-scope candidate fixes, selection SHALL select a security unit for its package on every scan, whether the vulnerability is reachable or not. The unit SHALL cover every declaration of the package at a vulnerable version, in any file. Each declaration's target SHALL be the smallest in-scope candidate that the scan records as reaching the fix of every advisory on it. No minimum release age applies.

#### Scenario: A reachable and an unreachable vulnerability

- **WHEN** one dependency has a reachable vulnerability and another an unreachable one, both fixed by an in-scope candidate
- **THEN** both get a security unit

#### Scenario: Patch and minor both reach the fix

- **WHEN** a dependency at `1.2.0` is fixed in `1.2.3`, and its in-scope candidates are `1.2.5` (patch) and `1.4.0` (minor)
- **THEN** the security unit's target is `1.2.5`

#### Scenario: The fixing release is new

- **WHEN** the only candidate that reaches the fix was released the day before the scan
- **THEN** the security unit is still selected

#### Scenario: The vulnerability is in the Go standard library

- **WHEN** govulncheck reports a standard library vulnerability fixed in a newer Go release, and the `go` directive has an in-scope candidate that reaches it
- **THEN** the directive gets a security unit

#### Scenario: A vulnerable package declared in two files

- **WHEN** the same package is declared at a vulnerable version in two files
- **THEN** one security unit covers both declarations

### Requirement: Select end-of-life moves

For each version line in use that the scan reports as nearing its end of life or past it, selection SHALL select one lifecycle unit on every scan, covering the dependencies on that line. Each dependency's target SHALL be its smallest in-scope candidate whose version is on a supported line.

#### Scenario: A line nears its end of life

- **WHEN** Go 1.25 is nearing its end of life, `go.mod` declares `go 1.25.14`, and its in-scope minor candidate is `1.27.2`, on a supported line
- **THEN** a lifecycle unit for Go 1.25 is selected, with `1.27.2` as the directive's target

#### Scenario: A dependency on the line has no supported target

- **WHEN** one dependency on a line nearing its end of life has an in-scope candidate on a supported line, and another has none
- **THEN** the unit covers the first, and the second is reported as an early warning

#### Scenario: A dependency on two ending lines

- **WHEN** a Go image's tag is on Go 1.25 and on Alpine 3.20, and both lines are past their end of life
- **THEN** one lifecycle unit covers the image, with both lines as reasons, and the image's target is on a supported line of both

### Requirement: Batch the remaining updates monthly

Only when the scan's date falls in the batch window, by default the first seven days of the month, SHALL selection select batch updates. A batch update is each dependency's newest in-scope candidate, if it is at least the minimum release age old (7 days by default). A candidate with no known release date counts as old enough. Dependencies with a security or lifecycle unit SHALL be left out of the batch. A dependency with a security reason that selection reports but doesn't prepare SHALL stay in the batch, and its batch unit SHALL name that report in its evidence.

#### Scenario: A scan inside the window

- **WHEN** a scan on the 3rd of the month finds a dependency whose newest in-scope candidate was released 20 days earlier
- **THEN** that candidate is selected as a batch update

#### Scenario: A scan outside the window

- **WHEN** a scan on the 15th of the month finds in-scope candidates without a security or lifecycle reason
- **THEN** no batch updates are selected

#### Scenario: The newest candidate is too young

- **WHEN** a scan inside the window finds a dependency whose newest in-scope candidate was released 2 days earlier
- **THEN** the dependency is not in the batch, and the report says it waits for the next window

#### Scenario: The release date is unknown

- **WHEN** a dependency's newest in-scope candidate has no known release date
- **THEN** it is selected as a batch update and marked "age unknown"

#### Scenario: The dependency has a security unit

- **WHEN** a dependency has a security unit and a newer in-scope candidate
- **THEN** it is not in the batch

#### Scenario: The dependency's fix is held

- **WHEN** a scan inside the window finds a dependency whose security fix is held by policy, and which has an older in-scope candidate
- **THEN** that candidate is selected as a batch update, and its unit's evidence names the held fix

### Requirement: Put each dependency in one unit

A dependency SHALL be in at most one unit. When a dependency on a lifecycle unit's line also has a security reason, the lifecycle unit SHALL carry both reasons, with a target that is on a supported line and reaches every fix, and no separate security unit SHALL be selected. When no in-scope candidate does both, the dependency SHALL be an early warning for the line, and its security fix a unit of its own.

#### Scenario: Go is end of life and has standard library vulnerabilities

- **WHEN** Go 1.25 is past its end of life, and govulncheck reports standard library vulnerabilities on the `go` directive
- **THEN** one lifecycle unit covers the directive, lists both the lifecycle and the security reason, and its target reaches both the supported line and the fix

### Requirement: Group batch updates by the policy

Selection SHALL put batch updates into units by the group the scan recorded for each candidate from the update policy's group rules. Updates in the same group SHALL form one unit, named after the group. The updates of one package that no group rule matches SHALL form one unit, covering every file that declares the package. Security and lifecycle units SHALL NOT be grouped.

#### Scenario: Two Go modules in one group

- **WHEN** the policy groups minor and patch updates of Go modules, and the batch has a minor update of one Go module and a patch update of another
- **THEN** both are in one unit, named after the group

#### Scenario: A major update outside every group

- **WHEN** the batch has a major update that no group rule matches
- **THEN** it forms a unit of its own

#### Scenario: An ungrouped package in two files

- **WHEN** the batch has a major update of a devcontainer feature in two devcontainer files, and no group rule matches it
- **THEN** one unit covers both files, named after the package

### Requirement: Name units stably

Each unit SHALL have a name derived only from its reason and from its group, package or version line. The same unit SHALL keep its name across scans, even when its targets change.

#### Scenario: A newer target in a later scan

- **WHEN** a later scan selects the same group with a newer target version
- **THEN** the unit has the same name as before

### Requirement: Mark breaking units

Selection SHALL mark each unit as breaking or routine. A unit SHALL be breaking when it contains a major update or is a lifecycle unit, and routine otherwise.

#### Scenario: A security fix that needs a major

- **WHEN** a security unit's target is a major update
- **THEN** the unit is breaking

#### Scenario: A batch of minor and patch updates

- **WHEN** a batch unit has only minor and patch updates
- **THEN** the unit is routine

### Requirement: Report what can't be prepared

Selection SHALL report every security or lifecycle reason it doesn't turn into a unit, with why. That covers:
- a fix that only held candidates reach, reported as "vulnerable, fix held by policy" with the holding rule;
- an advisory without a fixed version, reported as having no route;
- a lifecycle move without an in-scope target, reported as an early warning;
- a reason that missing data stops it from evaluating, reported as not evaluated.

#### Scenario: A held fix

- **WHEN** only candidates held by the rule "NuGet packages stay on the .NET runtime's major" reach a fix
- **THEN** the report lists the vulnerability as "vulnerable, fix held by policy", naming that rule

#### Scenario: No fixed version

- **WHEN** an advisory on an inventoried version names no fixed version
- **THEN** the report lists it as having no route

#### Scenario: A failed lookup

- **WHEN** a vulnerable dependency's lookup failed, so it isn't known whether a candidate reaches the fix
- **THEN** the report lists it as not evaluated, with the lookup's reason

### Requirement: Show the selection in the record and the report

The scan record SHALL contain the selection, and the Markdown report SHALL render it as a "Would prepare" section. For each unit, they SHALL show:
- its name and reason;
- each target, with its current version, update type and release age;
- its breaking mark;
- the evidence: the advisory, the lifecycle line, or the batch window.

Both SHALL also show the defaults in use and the reports of what can't be prepared.

#### Scenario: A scan with units and a held fix

- **WHEN** a scan selects a security unit and a batch unit, and finds a held fix
- **THEN** the record and the report both list the two units with their details, the held fix, and the batch window and minimum release age they used
