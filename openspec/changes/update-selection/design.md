# Design

## Context

Most of what selection needs is already in the scan record:
- **Candidates** (`candidates`): one per update type, each with its update type, version, policy classification and, when held, the rule that holds it. Advisory fixes are added for dependencies that are only locked.
- **Vulnerabilities** (`vulnerabilities`): each with its fixed version, `fix_reached_by_candidate` (`true`, `false`, `unknown`) and `fix_held_by`. govulncheck's standard library findings are attached to the `go` directive's inventory entry, for example `gomod:proxy/go.mod:go`.
- **Lifecycle** (`lifecycle`): each line in use with its state (`supported`, `nearing_end_of_life` within 90 days, `end_of_life`, `unknown`), its supported lines, and the dependencies on it.

What's missing is a release date per candidate. Renovate's lookup report has a `releaseTimestamp` for each update, but the scan doesn't keep it yet.

The policy is evaluated by our own code in `src/sdlc/policy.py`. Today it only evaluates hold rules (`enabled: false`, `allowedVersions`), with a fixed set of matchers, and it refuses rule forms it can't evaluate. Group rules (`groupName`) are ignored.

## Goals / Non-Goals

**Goals:**
- Selection as a pure function of the record, the policy and the scan's date, testable against fixtures for any date.
- No data source beyond what the scan already reads.
- One place that evaluates the policy, for holds and for groups alike.

**Non-Goals:**
- Exact Renovate semantics for groups. The policy uses Renovate's format, but our evaluator only supports the rule forms the policy uses, and refuses the rest.
- A configurable window, minimum age or horizon. These are constants until someone needs to change them.
- Any change to how candidates are found or classified, apart from recording the release date.

## Decisions

### 1. Selection runs inside the scan, after the record is assembled

`sdlc scan` assembles the record as it does now, then calls the selection with the record, the parsed policy and the date of `scanned_at`, and adds the result as the record's `selection` section before validating it against the schema. The report renders the section from the record, like every other section.

**Why the scan's date, not today's:** the record and the selection then describe the same moment, and a stored record can be selected again with the same result.

**Alternative:** a separate `sdlc select` command over a stored record. That would only be needed once something consumes stored records. `fork-mode-delivery` can decide that.

### 2. Groups are evaluated by `policy.py`, like holds

The evaluator learns rules with a `groupName`, using the same matchers it already supports for holds (`matchManagers`, `matchDatasources`, `matchPackageNames`, `matchUpdateTypes`), and it applies them to a candidate in policy order, so that a later matching rule wins, as in Renovate. A group rule with a matcher outside that set makes the policy unusable for selection, with an error that names the rule, the same way holds are handled.

**The scan records the group.** When the scan classifies a candidate, it also records the group the policy puts it in, as `group` beside `classification` and `held_by`, and the selection reads the group from the record. Group rules match on Renovate's `packageName` and `manager`, which the record doesn't carry, and the package name can differ from the dependency's name (setup-go's `go` is `actions/go-versions`, for example). So evaluating the rules again from the record would be wrong in general. Recording the decision at scan time, as holds already are, keeps the selection a function of the record.

In the tests, Renovate's `branchName` from the lookup report serves as a cross-check. The fixtures check that our grouping puts the same updates together as Renovate does.

**Alternative:** recording `packageName` and `manager` on inventory entries, so that the selection can evaluate the group rules itself. That adds more to the record, to evaluate the same rules twice.

**Alternative:** taking Renovate's `branchName` as the unit. It is free today, but it puts a decision in Renovate's semantics, which [ADR-0002](../../../docs/adr/ADR-0002-deterministic-decisions-agent-work.md) rules out.

### 3. Security targets come from the candidates, not from the advisory's version

For a vulnerability with `fix_reached_by_candidate: true`, the target is the in-scope candidate of the lowest update type (patch, then minor, then major) that reaches the fix. The scan already compares each candidate with the advisory's affected ranges to decide `fix_reached_by_candidate`, so it also records which in-scope candidates reach the fix, as `fix_reached_by`, and the selection takes the smallest of those. Comparing a candidate with the fixed version alone would be wrong for an advisory with several ranges, where a higher version can be affected again. `fix_reached_by_candidate: false` with `fix_held_by` is a held fix. `unknown` is not evaluated. A `null` fixed version is no route.

A security unit covers a package: every declaration of the same package (the inventory's ecosystem and name) at a vulnerable version, in any file. Each declaration's target is the smallest in-scope candidate that every one of its advisories lists in `fix_reached_by`, so that one update fixes them all. When no single candidate fixes them all, the declaration is reported as such rather than guessed.

**Alternative:** the advisory's exact fixed version as the target. That is smaller, but it isn't a candidate. Its update type and policy classification would need versioning code for every ecosystem, which the scan doesn't have. The patch candidate that reaches the fix is usually the same line anyway.

### 4. A lifecycle unit covers its whole line

A line in state `nearing_end_of_life` or `end_of_life` gives one unit, named after the product and line, for example `lifecycle-go-1.25`. For each dependency on the line, the target is its in-scope candidate of the lowest update type whose version falls on one of the line's supported lines. The line is computed with the same mapping from versions to lines that the lifecycle check already uses. A dependency without such a candidate becomes an early warning, and the unit keeps the others.

A dependency on the line that also has a security reason doesn't get its own security unit. The lifecycle unit carries the security reason as well, and its target is the smallest in-scope candidate that is both on a supported line and in every advisory's `fix_reached_by`, so that one change resolves both. Without such a candidate, the dependency is an early warning for the line, and its security fix becomes a unit of its own. The scan of `main` has this case: Go 1.25 is past its end of life, and govulncheck's standard library findings are on the `go` directive.

A dependency on several ending lines at once, such as a Go image whose tag names both an ending Go and an ending Alpine release, is in one lifecycle unit, which carries every one of those lines as a reason. Its target is the smallest in-scope candidate that is on a supported line of each of them. Without one, it is an early warning naming the line it can't leave.

Moving a whole line in one unit keeps declarations that belong together, such as the `go` directive, the Go version in the workflows and the Go base image, in one change, which the consistency check would otherwise flag halfway.

### 5. Batch window and minimum age are constants, measured against the scan's date

The window is days 1 to 7 of the month, and the minimum release age is 7 days, both as named constants. The release date comes from Renovate's `releaseTimestamp`, stored as `released_at` on the candidate. Without it, the candidate is old enough and is marked "age unknown". The batch takes each dependency's newest in-scope candidate. A dependency whose newest candidate is too young waits for the next window, even when an older in-scope candidate would pass. That is the simplest rule, and the report shows that the dependency is waiting.

### 6. Unit names come from the reason and the subject of the unit

- **Security:** `security-<ecosystem>-<name>`.
- **Lifecycle:** `lifecycle-<product>-<line>`.
- **Batch:** `<group name>` for a group, `<ecosystem>-<name>` for a package that isn't in a group.

A security unit and an ungrouped batch unit cover a package across files, as Renovate's branches do. Declarations of one package that belong together, such as the same feature in two devcontainer files, then change together, and the consistency check isn't left halfway between two PRs.

Names are made safe for branch names by one function, so that `fork-mode-delivery` can use them as branch names as they are.

### 7. A new record schema version

The `selection` section, the candidates' `released_at` and `group`, and the vulnerabilities' `fix_reached_by` are new properties, and the schema forbids unknown properties, so the record needs a new schema version. It builds on the version that `retire-dependabot-pr-comparison` introduces. The older schemas stay, for the records already written.

## Risks / Trade-offs

- [The batch window passes without a scan, because runs are started by hand] → The report says whether the window is open and when the next one opens. Running on a schedule is part of the open question of where the system runs.
- [A dependency that releases every few days never has a newest candidate old enough at window time] → The report shows it as waiting every month. If that happens, the rule can fall back to the newest candidate that is old enough.
- [Our group evaluation drifts from Renovate's] → The cross-check against Renovate's `branchName` in the fixtures, and the evaluator refusing rule forms it doesn't support.
- [A lifecycle move skips lines, for example Go 1.25 to 1.27] → It's the smallest in-scope candidate the scan has, because Renovate reports only the newest version per update type. The unit is breaking, so it goes to the agent and review, not to automatic merge.
