# Running a scan

How to run `sdlc scan` on a subject repository and read what it writes. The scan is read-only: it clones the subject into a temporary directory, never writes to it, and deletes the clone when it ends. For what it covers, see [scan-coverage.md](scan-coverage.md); for a real run, see [end-to-end-run.md](end-to-end-run.md).

## Before you start

Run every command from the root of this repository: `uv run sdlc`, `scripts/with-github-token.py` and the trial-policy path are all relative to it.

- **Python 3.12 or later and [uv](https://docs.astral.sh/uv/).** In a checkout of this repository, `uv run sdlc` installs the dependencies on first use.
- **git**, and a **public** subject repository. The clone is anonymous (`https://github.com/<owner>/<name>.git`) and ignores your git configuration, so the token is not used for it.
- **A container runtime**, `docker` by default. The scan runs Renovate, OSV-Scanner, govulncheck and the .NET and Go toolchains in pinned images. For podman, set `SDLC_CONTAINER_RUNTIME=podman` (or point it at its docker emulation); the scan adds `--userns=keep-id` itself.
- **Network access** to the image registries (docker.io, mcr.microsoft.com and others the pinned images come from), `api.github.com`, `github.com`, `osv.dev`, `vuln.go.dev`, `endoflife.date`, and the package registries of the subject's ecosystems (NuGet, Go proxy, PyPI and so on).
- **A read-only GitHub token** in `SDLC_GITHUB_TOKEN`; see below.

The first run pulls the images, which takes extra minutes. A scan of `alanta/azure-egress-proxy` with warm images takes about two minutes.

## The token

The scan works without a token, but then little is looked up: Renovate's GitHub lookups are rate limited or refused (those dependencies become `unknown`), and the Dependabot alerts aren't read (gap `dependabot-alerts`). The scan only makes GET requests and never needs write access.

Use a fine-grained personal access token, with the subject repository as its only repository and these read-only permissions:

| Permission | Used for | Without it |
|---|---|---|
| Metadata: read (always included) | The repository and its default branch | Nothing is read |
| Contents: read | The default branch's head (`GET /repos/{repo}/branches/{branch}`), which says whether the Dependabot alerts describe the scanned commit | `dependabot-alerts` is unavailable |
| Dependabot alerts: read | Open Dependabot alerts | `dependabot-alerts` is unavailable |

The same token also goes to Renovate as `GITHUB_COM_TOKEN`, for lookups of GitHub tags and releases, where it avoids rate limits. It is passed to containers by name, so it never appears on a command line.

An unavailable source is a coverage gap with GitHub's reason (for example "The token lacks the Dependabot alerts: read permission"), and the report claims nothing about it. It does not fail the scan.

To provide the token:

```bash
export SDLC_GITHUB_TOKEN=<token>
uv run sdlc scan ...
```

Or let `scripts/with-github-token.py` set it for one command. It reads the Login item labelled `azure-egress-proxy-sdlc read-only token` from the GNOME keyring (add exactly one with Seahorse; override the label with `SDLC_GITHUB_TOKEN_LABEL`), and does nothing if `SDLC_GITHUB_TOKEN` is already set. It needs the system Python with `python3-gi`:

```bash
scripts/with-github-token.py uv run sdlc scan ...
```

If it fails, nothing has been scanned. `error: no keyring item labelled '...'; add exactly one with Seahorse.` (or `N keyring items`) means the item is missing or duplicated: add or remove items until exactly one has that label, or set `SDLC_GITHUB_TOKEN` yourself. `error: keyring item '...' is empty.` means the item has no secret. `ModuleNotFoundError: No module named 'gi'` means the script ran under a Python without the bindings: install `python3-gi` and `gir1.2-secret-1` and run it with the system Python (the script's `#!/usr/bin/python3` line does this when you execute it directly, not through another interpreter).

## Inputs

```bash
uv run sdlc scan --repo <owner>/<name> [--ref <ref>] [--trial-policy <file>] [--out <dir>]
```

| Option | Meaning |
|---|---|
| `--repo` | Required. The subject, as `owner/name`. |
| `--ref` | A branch, a tag or a **full 40-character commit hash**; default `main`. An abbreviated hash is not a commit here: it is looked up as a branch or tag name and fails. The name is resolved to a commit once, and the whole scan uses that commit. |
| `--trial-policy` | A Renovate policy file to use instead of the subject's; see below. |
| `--out` | Where to write the run; default `runs` (relative to the current directory). |

Example, the scan used for [end-to-end-run.md](end-to-end-run.md):

```bash
scripts/with-github-token.py uv run sdlc scan --repo alanta/azure-egress-proxy --ref main \
  --trial-policy policies/azure-egress-proxy.renovate.json5
```

### The update policy

The policy says which updates are in scope, with holds, and how batch updates group. It says nothing about when: the selection decides that (see [Reading the selection](#reading-the-selection)). It is Renovate configuration, read from `.github/renovate.json5` at the scanned revision. If the subject has none, every candidate is in scope. With `--trial-policy <file>` that file is used instead, and the subject's own is ignored; use it to try a policy before it is merged into the subject. The first line of output says which one applies, and the record and report name it.

The scan fails (exit 1, nothing written) when the policy:
- doesn't exist, can't be parsed as JSON5, or isn't an object;
- is rejected by Renovate's own validator;
- uses `extends`, or sets `major`, `minor`, `patch` and the like directly (use a package rule with `matchUpdateTypes`);
- is not in `.github/renovate.json5` while the subject has Renovate configuration in another place (`renovate.json`, `.renovaterc`, a `renovate` key in `package.json`, and so on);
- has a hold rule (`enabled: false` or `allowedVersions`) that has no `description`, uses a key other than `description`, `enabled`, `allowedVersions` or the matchers `matchPackageNames`, `matchDepNames`, `matchDatasources`, `matchManagers`, `matchUpdateTypes`, sets `enabled: true`, uses an `override*` option, or uses a `matchUpdateTypes` value the scan can't evaluate (such as `bump`);
- has a group rule (`groupName`) whose `groupName` isn't a non-empty string or is a template (contains `{{`), that uses a `match*` or `exclude*` key other than those five matchers, or that can group majors because its `matchUpdateTypes` is missing or includes `major` (Renovate gives a group's majors a branch of their own);
- has two group rules with different names that Renovate would put on one branch, because they differ only in case or punctuation (such as `Go modules` and `go-modules`); rules that repeat the same name add to one group;
- sets an option that changes how Renovate puts grouped updates on branches: `groupSlug`, `group`, `branchName`, `branchPrefix` or `additionalBranchPrefix` in a package rule, `groupName`, `groupSlug`, `group` or `branchName` at the top level, or `separateMultipleMinor` anywhere unless it is `false`;
- sets `separateMinorPatch` anywhere, to any value: the scan sets it itself, so that it finds patch candidates as well as minor ones;
- has a hold that Renovate applies but the scan's matching can't explain.

A hold rule's `description` is what the report shows as the reason an update is held. [policies/azure-egress-proxy.renovate.json5](../policies/azure-egress-proxy.renovate.json5) is a working example.

## Outputs

Each scan gets its own directory, and nothing is overwritten:

```
<out>/<owner>/<name>/<commit>/<UTC time>/
    record.json    the data, validated against the version 3 record schema (`src/sdlc/schemas/scan-record.v3.json`)
    report.md      the report, rendered from record.json
```

The time is the scan's start, like `20261010T085434Z`. The directory appears only when both files are written. The terminal shows the resolved commit, the policy, the two paths and a summary:

```
alanta/azure-egress-proxy@main is e93d7062b075352f151f8e6b5a15f60913e7bd98
policy: trial file policies/azure-egress-proxy.renovate.json5
record: runs/alanta/azure-egress-proxy/e93d7062b075352f151f8e6b5a15f60913e7bd98/20261010T085434Z/record.json
report: runs/alanta/azure-egress-proxy/e93d7062b075352f151f8e6b5a15f60913e7bd98/20261010T085434Z/report.md
231 dependencies (...), 38 update candidates (31 in scope, 7 held by policy), 1 coverage gaps
...
```

If the record can't be turned into a report, the scan exits 1 and keeps the record beside where the run directory would be:
- `<time>.invalid.json`: the record fails its schema. The problems are printed. No report was written. This is a bug in the scan.
- `<time>.unrendered.json`: the record is valid but rendering the report failed, with a traceback. This is a bug in the renderer.

Report either with the file; neither is a result to rely on.

To find the newest run directory:

```bash
ls -td <out>/<owner>/<name>/*/*/ | head -1
```

The trailing slash leaves out the `.invalid.json` and `.unrendered.json` files.

## Reading the report

The report starts with a table: repository, ref, commit, time, the policy used, and the tools and their versions. Then:

**Summary.** The place to start. Each bullet says what was found, or that nothing was and why you can trust that or not:
- *End of life* and *Nearing end of life*: runtime and OS lines in use whose support has ended or ends soon. "None found, but N are unknown" means N lines couldn't be checked.
- *Reachable vulnerabilities* and *Vulnerabilities no in-scope candidate is known to fix*: advisories per dependency, with the fixed version and whether an in-scope candidate reaches it.
- *Would prepare*: how many updates the scan would prepare, how many are breaking, how many reasons stayed unprepared, and whether the batch window is open.
- *Inconsistent declarations*: the same thing (such as the Go version) declared with different values in different files.
- *Unknown*: dependencies not looked up, and lifecycle lines it couldn't determine. Deliberately skipped dependencies are counted here too.
- *Coverage gaps* and the totals.

**Sections after the summary:**
- **Would prepare:** which updates the system would prepare, and which it can't. Nothing is prepared by the scan itself. See [Reading the selection](#reading-the-selection).
- **Lifecycle:** one row per product line in use: `end of life`, `nearing end of life`, `supported` or `unknown` (with the reason, such as a tag that names no release), and where it is used.
- **Vulnerabilities:** one row per advisory, with the source (`osv` or `govulncheck`). Reachability is `reachable`, `not reachable` or `unknown`; only govulncheck decides it, and only for Go. *In-scope candidate reaches fix* is `yes`, `no`, `no fix to reach` (no fixed version exists) or unknown. A sub-section compares with Dependabot alerts: alerts that match the scan's advisories, match them only in another file, or don't match. When the alerts couldn't be read, it says *Unavailable* with the reason, and the gap is listed under Coverage gaps.
- **Declared versions:** the consistency check, and what was compared.
- **Update candidates:** *Held by policy* (with the rule) and *In scope*, each with its current version, update type and candidate. A candidate marked *advisory's fix* is the fixed version an advisory names for a dependency nothing looked up, so a newer version may exist.
- **Package manager cross-checks:** direct dependencies that `dotnet list package` or `go list -m -u` call outdated and the scan doesn't. These are a Renovate blind spot and should be none.
- **Coverage gaps:** what the scan couldn't cover: files no adapter reads or that can't be parsed (unsupported or unparseable files), and every source it couldn't read (unavailable sources), with the reason. Nothing listed here is known to be up to date.
- **Inventory:** every dependency with a lookup state. `current` and `outdated` were looked up. `unknown` means the lookup failed (no token, rate limit, unreachable registry); it is never shown as current. `skipped` was not attempted, and the reason is listed under *Not looked up*. `outdated, from advisories` wasn't looked up either: its candidates are its advisories' fixed versions, and it is listed under *Not looked up* too.
- **Tools:** the pinned images and versions that produced the result.

### Reading the selection

The scan ends by selecting updates. The selection is decided by code from the record alone, the policy and the scan's date: no agent takes part. It keeps nothing between scans, so an update that hasn't been merged is selected again for as long as its reason holds. The date is the day of the scan in UTC, and the report names it.

The selection is in `record.json` under `selection`, and the report shows it under *Would prepare*. That section has, in order:
- The date, the batch window and the minimum release age in use, and whether the window is open.
- **Units**, each with a name, a reason, a breaking mark, targets and evidence.
- **Not prepared**: the reasons that did not become a unit, grouped by kind.

#### Units

A unit is one update to prepare. Its name is stable and safe as a git branch name (lower case, letters, digits, `.`, `_` and `-`). It comes from the reason and the group, package or line, never from versions, so the same unit keeps its name from scan to scan. Its targets are a table: the dependency, the file, the current version, the update type, the target version and the target's release age (*age unknown* when the registry gave no date). Its evidence says why.

| Reason | Selected when | Unit and target |
|---|---|---|
| `security` | Every run, in or out of the batch window. A vulnerability has a fix, and an in-scope candidate reaches it. There is no minimum release age. | One unit per package, covering its declarations in every file, named `security-<ecosystem>-<package>`. The target is the smallest in-scope candidate the scan recorded as reaching the fix. When several advisories are on one declaration, the target reaches all of them. Evidence: the advisories, with fixed version, reachability and source. |
| `lifecycle` | Every run. A product line in use is nearing its end of life (within 90 days) or past it. | One unit per line, named `lifecycle-<product>-<line>`. Each dependency on the line has as target its smallest in-scope candidate on another line that is still supported. A dependency on several ending lines is in one unit, and its target leaves all of them. A security fix on a dependency in the unit goes with it: the unit then has both reasons, and the target also reaches the fix. Evidence: the lines, with their end of life and the lines still supported. |
| `batch` | Only inside the batch window: days 1 to 7 of every month. Every other dependency with an in-scope candidate is batched. | The newest in-scope candidate, if its release is at least 7 days old on the scan's date. A candidate with no release date counts as old enough, and its release age says *age unknown*. A dependency in one of the policy's groups goes in the unit named after the group; the unit's table lists each of them. A member whose newest candidate is too young waits on its own, and the rest of the group is still prepared. Any other dependency forms a unit of its own per package, across files, named `<ecosystem>-<package>`. Evidence: the window and minimum age. When the dependency also has a security report that is not prepared (see below), the evidence names it. |

**Breaking.** A unit is marked breaking when it has the `lifecycle` reason, because a move to another line changes the platform under the code, or when any target is a major update. Every other unit is routine. The mark says who will do the work once the system applies updates: a deterministic tool for a routine unit, the coding agent for a breaking one, with review either way. It does not hold anything back.

**Holds always win.** Only candidates the policy puts in scope can be targets, whatever the reason. A security fix that only a held candidate reaches is not prepared; it is reported as *fix held by policy*. A held candidate is never batched either; it shows only under *Update candidates*, *Held by policy*, with the rule that holds it.

If two units end up with the same branch-safe name, each gets a suffix from its own reason and subject, and the report marks the name collision.

#### Not prepared

*Not prepared* lists every reason that did not become a unit, so that a missing unit is never read as "nothing to do". Each entry says what it is about and why. What to do:

| Kind | Meaning | What to do |
|---|---|---|
| Vulnerable, fix held by policy | The fix is known, but only candidates a hold rule excludes reach it. The entry names the rule. | Decide whether the hold still stands. If not, change the rule in the policy; the next scan prepares the fix. |
| Vulnerable, no fixed version recorded | The advisory names no fixed version, or the scan couldn't read one from its ranges. | Read the advisory. Without a fix, consider removing or replacing the dependency. |
| Vulnerable, no candidate reaches the fix | A fix exists, but no in-scope candidate is at or past it (or no single candidate reaches the fix of all advisories on a declaration). | Look at what the registry offers. A fix may need a larger update than a candidate the scan found, or a manual change. |
| Early warning: line ending, no candidate leaves it | A line is nearing or past its end of life, but no in-scope candidate moves a dependency to a supported line. The entry names a hold when one is why. | Plan the move by hand, or lift the hold. This is a warning, not a failure: other dependencies on the line are still in the unit. |
| Not evaluated: data is missing | The decision needs data the record doesn't have: a failed or skipped lookup, an unread source such as OSV-Scanner or the Dependabot alerts, a Dependabot alert that matches none of the scan's advisories, or a line whose state is unknown. The entry gives the reason. | Fix the cause (see *When something goes wrong*) and scan again. Nothing is claimed about what the missing data would have said. |
| Too young to batch yet | Batch only. The newest candidate is younger than the minimum release age. It waits for the next window, even when an older candidate would be old enough. The entry gives the date it is old enough on. | Nothing. It is selected in the first window after it is old enough, if it is still the newest. |

Outside the batch window, *Not prepared* has no waiting entries and the batch units are absent. This is not a problem: the next window opens on the date the section gives.

#### Defaults

The batch window (days 1 to 7) and the minimum release age (7 days) are constants in `src/sdlc/selection.py`: `BATCH_WINDOW_FIRST_DAY`, `BATCH_WINDOW_LAST_DAY` and `MINIMUM_RELEASE_AGE_DAYS`. The record's `selection.defaults` says which values a scan used. The "nearing" distance of 90 days is the lifecycle check's. The policy supplies the holds and the groups; it has no schedule.

### Which unknowns are normal

- **Skipped lookups are normal, and many.** Renovate skips indirect Go modules, unversioned packages and non-version values by default: 102 of 231 on the evidence run. Each has its reason under *Not looked up*.
- **Some unknown lifecycle lines are expected.** A floating `alpine` tag names no release, and a `ubuntu-latest` runner label has no mapping to an endoflife.date product; the evidence run has both. The reason in the row says which case it is.
- **What deserves attention:** an `unavailable_source` gap (a token or tool problem), dependencies with lookup `unknown` (a failed lookup), and lifecycle lines whose reason is an endoflife.date failure. Those are things to fix and run again; see below.

## When something goes wrong

The scan exits 0 when it wrote a record and report, and 1 otherwise, with an `error:` line on stderr. A usage error (a missing `--repo`) exits 2.

| You see | Meaning and what to do |
|---|---|
| `error: ... has no branch or tag named 'x'`; `git ... failed` | The ref doesn't resolve (an abbreviated hash lands here), or the repository is private or misspelled. Use a branch, tag or full hash. |
| `error: policy ... ; no record written` | The policy is invalid; the message says which rule. Fix the policy and run again. A scan never falls back to "everything in scope". |
| `error: Renovate failed (N): ...` | The Renovate container failed; its last output follows. Check that the runtime works (`docker run --rm hello-world`), that the images can be pulled, and whether the output names a network error. |
| Gap `unavailable_source` for `dotnet list package`, `go list -m -u`, `osv-scanner` | That tool's container failed (`exit N: ...` with its output). The scan carries on and says nothing about what that tool would have found. |
| Gap `unavailable_source` for `dependabot-alerts` | No token, a missing permission, alerts disabled for the repository, or a rate limit. The reason is in the gap; fix the token and run again. |
| Dependencies `unknown` | Lookups failed, usually from GitHub's rate limit without a token (60 requests an hour) or an unreachable registry. Run again with a token or later; one failed lookup affects only its own dependencies. |
| `unknown` lifecycle lines with "endoflife.date" in the reason | endoflife.date couldn't be reached or answered badly. Run again. |
| `.invalid.json` or `.unrendered.json` | A bug in the scan; see Outputs. |

## Checking a scan

A scan has worked when it exits 0, the run directory holds `record.json` and `report.md`, and the Summary's gaps and *Unknown* lines are ones you can explain from the report. Scanning the same commit again produces a new run directory; compare the two reports' counts to see what changed between runs of the same revision (looked-up versions change as registries do).
