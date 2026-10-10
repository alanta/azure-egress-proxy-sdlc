# End-to-end run

A live scan of `alanta/azure-egress-proxy` `main` (`e93d706`) with the trial policy, on 2026-10-10 (task 6.2 of `revision-dependency-scan`). The run is in `fixtures/azure-egress-proxy/runs/e93d706-20261010T085434Z/`: `record.json` (139 KB), `report.md` (58 KB), snapshots of the subject before and after, and a `manifest.json`.

Command: `scripts/with-github-token.py uv run sdlc scan --repo alanta/azure-egress-proxy --ref main --trial-policy policies/azure-egress-proxy.renovate.json5`. It exited 0 on the first attempt, in about two minutes.

## What the first run found

The first run of this task, a few minutes earlier, recorded `go.mod`'s `go 1.25.14` directive as `current` with no candidate, although Go 1.26 and 1.27 exist. As a result the 13 standard library advisories said no in-scope candidate reaches the fix (1.26.9). That was a bug in the scan, found by checking the known gaps against the record. PR #29 fixed it, and this run was repeated on top of that fix. The first run is not kept; only this one is committed as evidence. The committed run also predates the verification fixes, so its record shows the advisory-fix entries (`golang.org/x/crypto`, `golang.org/x/net`) as looked up and without lines.

## Result

231 dependencies (91 current, 38 outdated, 102 skipped), 38 candidates (31 in scope, 7 held by policy), 1 coverage gap, 21 advisories (14 reachable, none with unknown reachability), 0 open Dependabot alerts, 0 inconsistent declarations. Main moved on since the earlier scan at `064aa09`, so the counts differ from `scan-coverage.md`.

## Parity with Dependabot

Three Dependabot PRs were open (#75, #76, #99), all current against `main`. Their 7 proposed updates are all `matched`: 0 held, 0 stale, 0 missed, and the comparison is complete. The 23 scan-only entries are updates no open Dependabot PR proposes, not mismatches.

Worth knowing:
- **#99, azcore:** Dependabot proposes 1.23.2, the scan has v1.23.3. That's `matched`: the scan's candidate is the newer patch.
- **#77** (the `Microsoft.Extensions.Http` lock drift) was closed on 2026-10-09 and no longer appears. The scan has no drift entries now.
- **Held updates** (the .NET 11 images and `Microsoft.OpenApi` 3.x) are held by the policy and no open PR proposes them.

## Known gaps

| Known gap | Where it shows up |
|---|---|
| PyJWT | Candidate: `regex:mock-idp/Dockerfile:PyJWT` 2.15.0 → 2.15.1, patch, in scope. Listed as scan-only, since Dependabot has no PR for it. |
| AVM module tags | Not candidates: 32 inventory entries, `regex:infra/…:avm/…`, ecosystem `docker`, all looked up and `current`. This is the same state as the spike found. |
| Go directive | `gomod:proxy/go.mod:go` is `outdated` at 1.25.14, with an in-scope minor candidate 1.27.2, scan-only. Its 13 govulncheck advisories (fixed in 1.26.9, 9 reachable) now say `fix_reached_by_candidate: true`, and the end-of-life line (Go 1.25 ended 2026-08-19) is still there. The workflow `go` versions and the proxy image have a 1.27 candidate too. |

## Things in the report that read oddly

- **"Unknown: 2" includes the 102 skipped dependencies.** They are deliberately not looked up, with reasons under Not looked up, but the summary counts them as unknown beside the two unknown lifecycle lines.
- **The two vulnerability bullets overlap.** Go 1.25.14 and `x/net` appear under reachable and again under "no in-scope candidate is known to fix", for the advisories that qualify for both. A reader may take them for different sets (14 and 14).
- **`actions/upload-artifact` v7 → v7** is listed as a `digest` candidate. It is a digest refresh of a floating tag, not a version change.
- **`Alpine`** lifecycle is `unknown` by design: the tag names no release.

None of these is wrong, and no bug was found.

## The subject was left unchanged

The scan's token is read-only. Before and after snapshots covered 9 branches with head SHAs, all 77 PRs with head, `updated_at`, comment count and labels, the 30 most recent workflow runs, and the check runs on `main`'s head. They are identical apart from the snapshot time (08:54:33Z before, 08:56:50Z after), so nothing was created or changed during the scan. The maintainer's local clones of the subject gained no files. The scan's own output went to `runs/` here.

The snapshots don't cover comments, labels or branches beyond those listed, and they can't show a read-only token's absence of permission; the token itself can't write.
