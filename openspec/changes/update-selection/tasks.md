# Tasks

This change builds on `retire-dependabot-pr-comparison`, which introduces the version 2 record schema. Start once that change has merged.

## 1. Release dates on candidates

- [ ] 1.1 Add `scan-record.v3.json`: version 2 plus an optional `released_at` date on a candidate, with `schema_version` 3. Keep versions 1 and 2. Verify that the schema tests accept a candidate with and without `released_at` and reject a malformed date.
- [ ] 1.2 Keep Renovate's `releaseTimestamp` as the candidate's `released_at` in the normalisation (`src/sdlc/renovate.py`), and leave it out when the report has none. The scan now writes version 3 records. Verify `tests/test_renovate_normalize.py` on the `064aa09` report, with a candidate that has a date and one that doesn't.

## 2. Group rules

- [ ] 2.1 Teach `src/sdlc/policy.py` to evaluate `groupName` rules with the matchers it already supports, in policy order with the last matching rule winning, and to refuse a group rule with any other matcher, naming the rule. Verify `tests/test_policy.py` with the trial policy: the Microsoft and Aspire packages land in `microsoft`, not in `nuget-minor-patch`, a major matches no group, and an unsupported matcher fails.
- [ ] 2.2 Cross-check the grouping against the `branchName` values in the `064aa09` Renovate report. Verify that a test puts the same candidates together as Renovate's branches do.

## 3. Selection

- [ ] 3.1 Add the selection module: a pure function of the record, the policy and the scan's date that returns units and reports. Units are empty for now. It carries the constants for the batch window and the minimum release age. Verify that a test with a fixed record and date gives the same result twice.
- [ ] 3.2 Select security units, following the requirements "Select security fixes" and "Target only in-scope candidates": smallest in-scope candidate that reaches the fix, one unit per dependency, highest target across its advisories. Report held fixes, advisories without a fixed version and unknown reach. Verify a test for each scenario of those requirements and of "Report what can't be prepared".
- [ ] 3.3 Select lifecycle units, following "Select end-of-life moves" and "Put each dependency in one unit": one unit per line, with targets on a supported line from the lifecycle check's mapping of versions to lines, early warnings for dependencies without one, and security reasons absorbed with the higher target. Verify a test for each scenario, including Go 1.25 past its end of life with standard library vulnerabilities on the `go` directive.
- [ ] 3.4 Select the batch, following "Batch the remaining updates monthly" and "Group batch updates by the policy": only inside the window, the newest in-scope candidate if old enough, "age unknown" without a date, waiting when too young, dependencies with a security or lifecycle unit left out, and grouped by the group rules from 2.1. Verify a test for each scenario, on dates inside and outside the window.
- [ ] 3.5 Name every unit stably and safely for branch names, and mark it breaking or routine, following "Name units stably" and "Mark breaking units". Verify tests that a later record with a newer target gives the same name, and one for each breaking scenario.

## 4. Record and report

- [ ] 4.1 Add the `selection` section to the version 3 schema, and have `sdlc scan` run the selection on the assembled record before it is validated. Verify with `tests/test_cli.py` that a scan's record has a valid selection section, and that a record with a malformed selection fails the schema.
- [ ] 4.2 Render the "Would prepare" section in the report (`src/sdlc/report.py`). It shows the units with their reason, targets (current version, update type, release age), breaking mark and evidence, then the reports of what can't be prepared, and the window and minimum release age in use. It also says whether the window is open and when the next one opens. Verify with `tests/test_report.py` that every part of the selection in a fixture record appears in the report.
- [ ] 4.3 Remove the weekly `schedule` from `policies/azure-egress-proxy.renovate.json5`, and update its comments to match. Document the selection in `docs/running-a-scan.md`: what each reason means, how to read the "Would prepare" section, and the defaults. Verify that the policy still passes Renovate's validation in the scan, and that a fresh agent can read a report's selection with only that document.

## 5. End-to-end check

- [ ] 5.1 Run a scan of the subject's `main` with the trial policy, once with the real date and once with a date inside the window. Verify that the record validates against version 3. The Go 1.25 line should give one breaking lifecycle unit that also carries the standard library vulnerabilities, and the scan inside the window should show batch units by group. Record any surprise as a task or an issue, not as a silent fix.
