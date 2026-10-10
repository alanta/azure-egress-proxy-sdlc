"""The Markdown report, rendered from a scan record and nothing else.

The report is the maintainer's view of one record, never a second source: `render` takes the
record and returns text, and this module imports nothing that could reach the checkout, the
tools or the network. So everything the report says can be traced back to the record, and
a record that fails its schema never gets a report (see outputs.py).

Most of the text in a record comes from elsewhere: package names and file paths from the
subject, PR titles from Dependabot, reasons from tools and APIs. All of it is escaped, so it
reads as plain text and can't add HTML or formatting to the report. A word GitHub would turn
into a link by itself (a URL, `www.` or an e-mail address) goes in a code span, where nothing
is linked.
"""

import re
from collections import Counter
from typing import Any

# The gap subjects of the sources that can be unavailable as a whole, as the scan writes them.
OSV_SCANNER = "osv-scanner"
DEPENDABOT_ALERTS = "dependabot-alerts"
DEPENDABOT_PRS = "dependabot-prs"
ENDOFLIFE = "endoflife.date"
NATIVE = {"dotnet": "dotnet list package", "go": "go list -m -u"}
# Unavailable sources that say nothing about vulnerabilities. Any other unavailable source,
# including one added later, may hide an advisory, so the report never claims there are none.
NOT_ABOUT_VULNERABILITIES = {DEPENDABOT_ALERTS, DEPENDABOT_PRS, ENDOFLIFE, *NATIVE.values()}

# Where each top-level property of the record shows in the report: a heading, or a row of the
# header table. The tests check this against the schema, so a new section can't go unrendered.
SECTIONS = {
    "schema_version": "| Record schema |",
    "subject": "| Repository |",
    "scanned_at": "| Scanned at |",
    "tools": "## Tools",
    "policy": "| Update policy |",
    "inventory": "## Inventory",
    "candidates": "## Update candidates",
    "vulnerabilities": "## Vulnerabilities",
    "dependabot_alerts": "### Dependabot alerts",
    "lifecycle": "## Lifecycle",
    "consistency": "### What was compared",
    "inconsistencies": "## Declared versions",
    "cross_checks": "## Package manager cross-checks",
    "parity": "## Parity with Dependabot",
    "gaps": "## Coverage gaps",
}

LIFECYCLE_STATES = ("end_of_life", "nearing_end_of_life", "supported", "unknown")
REACHABILITY = ("reachable", "unknown", "not_reachable")
RESULTS = ("missed", "stale", "held_by_policy", "matched")

# Markdown and GitHub's extensions give these meaning in running text: emphasis, code, links,
# tables, strikethrough and math; and an @ starting a word mentions someone. A backslash makes
# each a plain character.
_SPECIAL = re.compile(r"([\\`*_\[\]|~$])")
_MENTION = re.compile(r"(?<!\S)@")
# What GitHub links without any markup: a scheme's `://` or `mailto:`, `www.`, an address.
_LINKABLE = re.compile(
    r"[a-z][a-z0-9+.-]*://|\b(?:mailto|xmpp):|\bwww\.|[\w.+-]@[\w-]+\.[\w-]", re.IGNORECASE
)
_TICKS = re.compile(r"`+")


def text(value: Any) -> str:
    """Untrusted text as plain Markdown: on one line, with no HTML, formatting or links."""
    return " ".join(_word(word) for word in str(value).split())


def _word(word: str) -> str:
    if _LINKABLE.search(word):
        # A code span shows its content as it is, so nothing in it links or formats. Its
        # fence is longer than any run of backticks in it; a pipe stays escaped for tables.
        fence = "`" * (max((len(t) for t in _TICKS.findall(word)), default=0) + 1)
        pad = " " if word[0] == "`" or word[-1] == "`" else ""
        return f"{fence}{pad}{word.replace('|', chr(92) + '|')}{pad}{fence}"
    word = word.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MENTION.sub(r"\\@", _SPECIAL.sub(r"\\\1", word))


def render(record: dict[str, Any]) -> str:
    """The report of a record that passed validation."""
    view = _View(record)
    lines: list[str] = []
    for part in (
        _header,
        _summary,
        _lifecycle,
        _vulnerabilities,
        _parity,
        _declared,
        _candidates,
        _cross_checks,
        _gaps,
        _inventory,
        _tools,
    ):
        lines += part(view)
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


class _View:
    """The record with the lookups the sections share."""

    def __init__(self, record: dict[str, Any]):
        self.record = record
        self.entries = {d["id"]: d for d in record["inventory"]}
        self.candidates: dict[str, list[dict[str, Any]]] = {}
        for c in record["candidates"]:
            self.candidates.setdefault(c["dependency"], []).append(c)
        self.unread = [g for g in record["gaps"] if g["kind"] == "unavailable_source"]
        self.unavailable: dict[str, str] = {}
        for g in self.unread:
            self.unavailable.setdefault(g["subject"], g["reason"])
        self.unchecked = [g for g in self.unread if g["subject"] not in NOT_ABOUT_VULNERABILITIES]

    def entry(self, dep_id: str) -> str:
        dep = self.entries[dep_id]
        return f"{text(dep['name'])} {version(dep['current'])}"

    def place(self, candidate: dict[str, Any]) -> tuple:
        """Where a candidate's dependency is, for listing them file by file."""
        dep = self.entries[candidate["dependency"]]
        return (dep["location"]["file"], dep["location"].get("line", 0), dep["name"])

    def where(self, dep_id: str) -> str:
        return location(self.entries[dep_id]["location"])


def version(value: str | None) -> str:
    return "unknown" if value is None else text(value)


def location(loc: dict[str, Any]) -> str:
    return text(loc["file"]) + (f":{loc['line']}" if "line" in loc else "")


LOCKED_BECAUSE = {
    "drift": "lock drift",
    "vulnerability": "added for an advisory",
}


def origin(dep: dict[str, Any]) -> str:
    """Declared, or locked with why the scan lists the lock file's version."""
    if dep["origin"] != "locked":
        return dep["origin"]
    return f"locked, {LOCKED_BECAUSE[dep['locked_because']]}"


def label(state: str) -> str:
    return state.replace("_", " ")


def count(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else plural or singular + 's'}"


def dependencies(n: int) -> str:
    return count(n, "dependency", "dependencies")


def advisories(n: int) -> str:
    return count(n, "advisory", "advisories")


def table(headings: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headings) + " |", "|" + "---|" * len(headings)]
    return lines + ["| " + " | ".join(row) + " |" for row in rows]


def _header(view: _View) -> list[str]:
    record = view.record
    subject = record["subject"]
    policy = record["policy"]
    if policy["source"] == "none":
        source = "none found, so every candidate is in scope"
    elif policy["source"] == "trial":
        source = f"trial file {text(policy['path'])}, supplied for this scan"
    else:
        source = f"the subject's {text(policy['path'])}"
    tools = ", ".join(
        dict.fromkeys(f"{text(t['name'])} {text(t['version'])}" for t in record["tools"])
    )
    return [
        f"# Dependency scan of {text(subject['repository'])}",
        "",
        "| | |",
        "|---|---|",
        f"| Repository | {text(subject['repository'])} |",
        f"| Ref | {text(subject['ref'])} |",
        f"| Commit | {text(subject['commit'])} |",
        f"| Scanned at | {text(record['scanned_at'])} |",
        f"| Update policy | {source} |",
        f"| Tools | {tools} (details under Tools) |",
        f"| Record schema | version {text(record['schema_version'])} |",
    ]


def _summary(view: _View) -> list[str]:
    """What needs the maintainer's attention, most urgent first; the sections below list it all."""
    record = view.record
    lines = ["## Summary", ""]

    lifecycle = record["lifecycle"]
    unknown_lines = [e for e in lifecycle if e["state"] == "unknown"]
    for state in ("end_of_life", "nearing_end_of_life"):
        found = [e for e in lifecycle if e["state"] == state]
        if found:
            lines.append(f"- **{label(state).capitalize()}:** {count(len(found), 'line')} in use:")
            lines += [f"  - {_line(e)}" for e in found]
        elif unknown_lines:
            lines.append(
                f"- **{label(state).capitalize()}:** none found, but "
                f"{count(len(unknown_lines), 'line is', 'lines are')} unknown"
            )
        else:
            lines.append(f"- **{label(state).capitalize()}:** none")

    vulnerabilities = record["vulnerabilities"]
    reachable = [v for v in vulnerabilities if v["reachability"] == "reachable"]
    osv_down = OSV_SCANNER in view.unavailable
    lead = "unknown, OSV-Scanner didn't run; of govulncheck's alone, " if osv_down else ""
    unknown = sum(v["reachability"] == "unknown" for v in vulnerabilities)
    more = f" ({advisories(unknown)} with reachability unknown)" if unknown else ""
    if view.unchecked:
        more += (
            f"; incomplete, {count(len(view.unchecked), 'source or file', 'sources or files')} "
            "couldn't be checked (see Unknown)"
        )
    if reachable:
        lines.append(f"- **Reachable vulnerabilities:** {lead}{_advisories_on(reachable)}{more}:")
        lines += [f"  - {line}" for line in _per_dependency(view, reachable)]
    else:
        none = "none found" if view.unchecked else "none known"
        lines.append(f"- **Reachable vulnerabilities:** {lead}{none}{more}")
    unfixed = [v for v in vulnerabilities if _fix(v)[1] != "yes"]
    if unfixed:
        lines.append(
            "- **Vulnerabilities no in-scope candidate is known to fix:** "
            f"{_advisories_on(unfixed)}:"
        )
        lines += [f"  - {line}" for line in _per_dependency(view, unfixed)]

    parity = record["parity"]
    if DEPENDABOT_PRS in view.unavailable:
        lines.append("- **Missed Dependabot updates:** unknown, Dependabot's PRs weren't read")
    else:
        missed = [
            (pr, u)
            for pr in parity["pull_requests"]
            for u in pr["updates"]
            if u["result"] == "missed"
        ]
        incomplete = "" if parity["complete"] else " (the comparison is incomplete)"
        if missed:
            lines.append(f"- **Missed Dependabot updates:** {len(missed)}{incomplete}:")
            lines += [
                f"  - #{pr['number']} {text(u['name'])} {_from(u)} → {text(u['to'])}: "
                f"{text(u['reason'])}"
                for pr, u in missed
            ]
        else:
            lines.append(f"- **Missed Dependabot updates:** none{incomplete}")

    inconsistencies = record["inconsistencies"]
    names = ", ".join(text(i["dependency"]) for i in inconsistencies)
    lines.append(
        f"- **Inconsistent declarations:** {len(inconsistencies)} of "
        f"{count(len(record['consistency']), 'logical dependency', 'logical dependencies')}"
        + (f": {names}" if names else "")
    )

    unknowns = _unknowns(view)
    if unknowns:
        lines.append(f"- **Unknown:** {len(unknowns)}:")
        lines += [f"  - {u}" for u in unknowns]
    elif record["gaps"]:
        lines.append("- **Unknown:** nothing beyond the files the coverage gaps name")
    else:
        lines.append("- **Unknown:** nothing; every source was read and every file covered")
    lines.append(f"- **Coverage gaps:** {len(record['gaps'])}, all listed under Coverage gaps")

    held = sum(c["classification"] == "held_by_policy" for c in record["candidates"])
    lines.append(
        f"- **Totals:** {dependencies(len(record['inventory']))}, "
        f"{count(len(record['candidates']), 'update candidate')} "
        f"({len(record['candidates']) - held} in scope, {held} held by policy), "
        + (
            "vulnerabilities unknown"
            if osv_down
            else f"{advisories(len(vulnerabilities))} on "
            f"{dependencies(len({v['dependency'] for v in vulnerabilities}))}"
        )
    )
    return lines


def _unknowns(view: _View) -> list[str]:
    """Everything the record says it doesn't know: every source it couldn't read, by the gap's
    own words, then what is unknown about the findings."""
    record = view.record
    found = [f"not read: {text(g['subject'])}: {text(g['reason'])}" for g in view.unread]
    inventory = record["inventory"]
    lookups = sum(d["lookup"]["state"] == "unknown" for d in inventory)
    if lookups:
        found.append(f"{count(lookups, 'lookup')} failed, listed under Not looked up")
    skipped = sum(d["lookup"]["state"] == "skipped" for d in inventory)
    if skipped:
        found.append(
            f"{skipped} of {dependencies(len(inventory))} not looked up (skipped), with the "
            "reasons under Not looked up"
        )
    reach = sum(v["reachability"] == "unknown" for v in record["vulnerabilities"])
    if reach:
        found.append(f"reachability of {advisories(reach)}")
    fixes = sum(v.get("fix_reached_by_candidate") == "unknown" for v in record["vulnerabilities"])
    if fixes:
        found.append(f"whether a candidate fixes {advisories(fixes)}")
    lines = sum(e["state"] == "unknown" for e in record["lifecycle"])
    if lines:
        found.append(f"lifecycle of {count(lines, 'line')}")
    if not record["parity"]["complete"] and DEPENDABOT_PRS not in view.unavailable:
        found.append("parity with Dependabot is incomplete")
    return found


def _line(e: dict[str, Any]) -> str:
    """A lifecycle line with its dates and where it is used."""
    where = _used_in(e)
    ends = e.get("end_of_life")
    if e["state"] == "unknown":
        detail = f"unknown: {text(e['reason'])}"
    elif ends:
        detail = f"{'ended' if e['state'] == 'end_of_life' else 'ends'} {text(ends)}"
    else:
        detail = text(e.get("reason", "no end date published"))
    if e["state"] in ("end_of_life", "nearing_end_of_life"):
        detail += f"; still supported: {_supported(e)}"
    return f"{text(e['product'])} {text(e['line'])}: {detail} ({where})"


def _used_in(e: dict[str, Any]) -> str:
    return ", ".join(dict.fromkeys(location(loc) for loc in e["locations"]))


def _supported(e: dict[str, Any]) -> str:
    if "supported_lines" not in e:
        return "unknown"
    return ", ".join(text(line) for line in e["supported_lines"]) or "none"


def _lifecycle(view: _View) -> list[str]:
    lifecycle = view.record["lifecycle"]
    sources = [t for t in view.record["tools"] if t["name"] == ENDOFLIFE]
    lines = ["## Lifecycle", ""]
    if sources:
        read = ", ".join(text(t.get("url", t["name"])) for t in sources)
        at = text(sources[0].get("fetched_at", "an unknown time"))
        lines.append(f"From endoflife.date, read at {at}: {read}.")
    else:
        lines.append("Nothing was read from endoflife.date.")
    if ENDOFLIFE in view.unavailable:
        lines.append(f"Not everything could be read: {text(view.unavailable[ENDOFLIFE])}")
    lines.append("")
    if not lifecycle:
        lines.append("No image or runtime line in use was found.")
        return lines
    order = sorted(lifecycle, key=lambda e: LIFECYCLE_STATES.index(e["state"]))
    rows = []
    for e in order:
        if e["state"] == "unknown":
            ends = f"unknown: {text(e['reason'])}"
        else:
            ends = text(e.get("end_of_life") or e.get("reason") or "no date published")
        rows.append(
            [
                label(e["state"]),
                text(e["product"]),
                text(e["line"]),
                ends,
                "" if e["state"] == "unknown" else _supported(e),
                _used_in(e),
            ]
        )
    return lines + table(
        ["State", "Product", "Line", "End of life", "Still supported", "Used in"], rows
    )


def _fix(v: dict[str, Any]) -> tuple[str, str]:
    """The advisory's fix, and whether an in-scope candidate reaches it."""
    if v["fixed_version"] is not None:
        fix = f"fixed in {text(v['fixed_version'])}"
    elif "last_affected" in v:
        fix = f"fixed after {text(v['last_affected'])}"
    else:
        return "no fixed version", "no fix to reach"
    reached = {True: "yes", False: "no"}.get(v["fix_reached_by_candidate"], "unknown")
    if "fix_held_by" in v:
        reached += f", only candidates held by {text(v['fix_held_by'])}"
    return fix, reached


def _advisories_on(found: list[dict[str, Any]]) -> str:
    return f"{advisories(len(found))} on {dependencies(len({v['dependency'] for v in found}))}"


def _per_dependency(view: _View, found: list[dict[str, Any]]) -> list[str]:
    """One line per dependency: its advisories, how many are reachable, and their fixes."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for v in found:
        groups.setdefault(v["dependency"], []).append(v)
    lines = []
    for dep_id, group in groups.items():
        reach = Counter(v["reachability"] for v in group)
        fixes = [_fix(v) for v in group]
        lines.append(
            f"{view.entry(dep_id)} ({view.where(dep_id)}): "
            + ", ".join(text(v["advisory"]) for v in group)
            + "; "
            + ", ".join(f"{reach[r]} {label(r)}" for r in REACHABILITY if reach[r])
            + "; "
            + " / ".join(dict.fromkeys(fix for fix, _ in fixes))
            + "; an in-scope candidate reaches the fix: "
            + " / ".join(dict.fromkeys(reached for _, reached in fixes))
        )
    return lines


def _vulnerabilities(view: _View) -> list[str]:
    vulnerabilities = view.record["vulnerabilities"]
    lines = ["## Vulnerabilities", ""]
    if OSV_SCANNER in view.unavailable:
        lines.append(
            f"**Unknown.** OSV-Scanner didn't run: {text(view.unavailable[OSV_SCANNER])} "
            "So nothing is claimed about the dependencies' advisories; any listed below are "
            "govulncheck's alone."
        )
    else:
        sources = Counter(v["source"] for v in vulnerabilities)
        lines.append(
            f"{advisories(len(vulnerabilities))} on "
            f"{dependencies(len({v['dependency'] for v in vulnerabilities}))}"
            + (
                " (" + ", ".join(f"{n} from {text(s)}" for s, n in sorted(sources.items())) + ")"
                if sources
                else ""
            )
            + "."
        )
    if view.unchecked:
        lines += ["", "**Incomplete.** These couldn't be checked, so they may hide advisories:"]
        lines += [f"- {text(g['subject'])}: {text(g['reason'])}" for g in view.unchecked]
        lines.append("")
    reach = Counter(v["reachability"] for v in vulnerabilities)
    lines.append(
        "Reachability, from govulncheck for Go: "
        + ", ".join(f"{reach[r]} {label(r)}" for r in REACHABILITY)
        + "."
    )
    lines.append("")
    if vulnerabilities:
        rows = []
        for v in sorted(vulnerabilities, key=lambda v: REACHABILITY.index(v["reachability"])):
            fix, reached = _fix(v)
            advisory = text(v["advisory"])
            if v.get("aliases"):
                advisory += " (" + ", ".join(text(a) for a in v["aliases"]) + ")"
            alerts = ", ".join(f"#{n}" for n in v.get("dependabot_alerts", []))
            rows.append(
                [
                    advisory,
                    view.entry(v["dependency"]),
                    view.where(v["dependency"]),
                    label(v["reachability"]),
                    fix,
                    reached,
                    text(v["source"]),
                    alerts,
                ]
            )
        lines += table(
            [
                "Advisory",
                "Dependency",
                "Where",
                "Reachability",
                "Fix",
                "In-scope candidate reaches fix",
                "Source",
                "Dependabot alerts",
            ],
            rows,
        )
        lines.append("")
    return lines + _alerts(view)


def _alerts(view: _View) -> list[str]:
    section = view.record.get("dependabot_alerts")
    lines = ["### Dependabot alerts", ""]
    if section is None:
        reason = text(view.unavailable.get(DEPENDABOT_ALERTS, "they weren't read"))
        return [*lines, f"**Unavailable:** {reason} Nothing is known from them."]
    commit = view.record["subject"]["commit"]
    head = f"{text(section['ref'])} at {text(section['commit'][:7])}"
    if section["is_scanned_commit"]:
        about = f"{head}, the scanned commit."
    else:
        about = (
            f"{head}, **not** the scanned commit {commit[:7]}: a difference between them and "
            "the scan may be the branch's, not a miss of the scan."
        )
    alerts = section["alerts"]
    results = Counter(a["result"] for a in alerts)
    without = sum("dependabot_alerts" not in v for v in view.record["vulnerabilities"])
    lines += [
        f"Read at {text(section['read_at'])}. They describe the default branch as Dependabot "
        f"last analysed it: {about}",
        "",
        f"{count(len(alerts), 'open alert')}: {results['matched']} match the scan's advisories in "
        f"the same file, {results['matched_elsewhere']} only in another file, "
        f"{results['unmatched']} don't. {without} of the scan's "
        f"{advisories(len(view.record['vulnerabilities']))} have no open "
        "alert.",
    ]
    if alerts:
        rows = [
            [
                f"#{a['number']}",
                text(a["advisory"]),
                text(a["package"]),
                text(a["manifest"])
                + ("" if "dependency" in a else " (not in the inventory there)"),
                f"fixed in {text(a['fixed_version'])}"
                if a["fixed_version"]
                else "no fixed version",
                label(a["result"]),
            ]
            for a in alerts
        ]
        lines += ["", *table(["Alert", "Advisory", "Package", "Manifest", "Fix", "Result"], rows)]
    return lines


def _from(u: dict[str, Any]) -> str:
    old = u.get("from") or " or ".join(
        sorted({text(f["version"]) for f in u.get("from_versions", [])})
    )
    if not old:
        return "unknown"
    old = text(old) if "from" in u else old
    if u.get("from_source") == "diff":
        old += " (from the diff)"
    return old


def _parity(view: _View) -> list[str]:
    parity = view.record["parity"]
    lines = ["## Parity with Dependabot", ""]
    if DEPENDABOT_PRS in view.unavailable:
        return [
            *lines,
            f"**Unknown.** Dependabot's open PRs couldn't be read: "
            f"{text(view.unavailable[DEPENDABOT_PRS])} Nothing is compared, and nothing is "
            "listed as scan-only.",
        ]
    pulls = parity["pull_requests"]
    updates = [u for pr in pulls for u in pr["updates"]]
    results = Counter(u["result"] for u in updates)
    lines.append(
        f"{count(len(pulls), 'open Dependabot PR')}, read at "
        f"{text(parity.get('captured_at', 'an unknown time'))}; the scan's lookups ran at "
        f"{text(parity.get('looked_up_at', 'an unknown time'))}. Parity holds only for that "
        "moment."
    )
    lines.append("")
    lines.append(
        f"{count(len(updates), 'proposed update')}: "
        + ", ".join(f"{results[r]} {label(r)}" for r in RESULTS)
        + "."
    )
    if parity["complete"]:
        lines.append("The comparison is complete.")
    else:
        lines += ["", "**The comparison is incomplete:**"]
        lines += [f"- {text(reason)}" for reason in parity["reasons"]]
    for pr in pulls:
        title = f": {text(pr['title'])}" if "title" in pr else ""
        lines += ["", f"### #{pr['number']}{title}", ""]
        head = f"At {text(pr['head'][:7])}" if "head" in pr else "Head unknown"
        base = f" on {text(pr['base'])}" if "base" in pr else ""
        state = f"{head}{base}, **{label(pr['state'])}**"
        lines.append(state + (f": {text(pr['reason'])}" if "reason" in pr else "."))
        if not pr["updates"]:
            continue
        rows = []
        for u in pr["updates"]:
            kind = u.get("update_type", "unknown")
            if u.get("update_type_derived"):
                kind += ", derived"
            where = " ".join(text(u[k]) for k in ("ecosystem", "directory") if k in u)
            if "group" in u:
                where += f" group {text(u['group'])}"
            detail = {
                "matched": f"scan has {text(u.get('candidate', ''))}",
                "held_by_policy": text(u.get("held_by", "")),
            }.get(u["result"], "")
            if "reason" in u:
                detail = "; ".join(d for d in (detail, text(u["reason"])) if d)
            rows.append(
                [
                    label(u["result"]),
                    text(u["name"]),
                    _from(u),
                    text(u["to"]),
                    kind,
                    where,
                    detail,
                ]
            )
        headings = ["Result", "Dependency", "From", "To", "Type", "Where", "Detail"]
        lines += ["", *table(headings, rows)]
    lines += ["", "### Scan only", ""]
    scan_only = parity["scan_only"]
    lines.append(
        f"{count(len(scan_only), 'entry', 'entries')} with in-scope candidates that no open "
        "Dependabot PR proposes."
    )
    if scan_only:
        rows = []
        for dep_id in sorted(scan_only, key=lambda i: _by_ecosystem(view.entries[i])):
            dep = view.entries[dep_id]
            in_scope = [
                text(c["version"])
                for c in view.candidates.get(dep_id, [])
                if c["classification"] == "in_scope"
            ]
            rows.append(
                [
                    text(dep["ecosystem"])
                    + (f" ({origin(dep)})" if dep["origin"] == "locked" else ""),
                    text(dep["name"]),
                    view.where(dep_id),
                    version(dep["current"]),
                    ", ".join(in_scope),
                ]
            )
        lines += ["", *table(["Ecosystem", "Dependency", "Where", "Current", "Candidates"], rows)]
    return lines


def _by_ecosystem(dep: dict[str, Any]) -> tuple:
    return (dep["ecosystem"], dep["origin"], dep["name"], dep["location"]["file"])


def _declared(view: _View) -> list[str]:
    record = view.record
    lines = ["## Declared versions", ""]
    inconsistencies = record["inconsistencies"]
    if inconsistencies:
        lines.append(
            f"{count(len(inconsistencies), 'logical dependency is', 'logical dependencies are')} "
            "declared at different versions in different places."
        )
    else:
        lines.append("Every logical dependency compared is declared consistently.")
    for inconsistency in inconsistencies:
        lines += ["", f"**{text(inconsistency['dependency'])}**", ""]
        rows = [
            [location(d["location"]), view.entry(d["dependency"]), text(d["version"])]
            for d in inconsistency["declarations"]
        ]
        lines += table(["Where", "Declaration", "Declares"], rows)
    flagged = {i["dependency"] for i in inconsistencies}
    lines += ["", "### What was compared", ""]
    rows = []
    for alias in record["consistency"]:
        compared = alias["compared"]
        if not compared:
            result = "nothing declares it"
        elif len(compared) == 1:
            result = "declared once, nothing to compare"
        else:
            result = "inconsistent" if alias["dependency"] in flagged else "consistent"
        rows.append(
            [
                text(alias["dependency"]),
                result,
                ", ".join(f"{view.entry(i)} ({view.where(i)})" for i in compared),
            ]
        )
    if rows:
        lines += table(["Logical dependency", "Result", "Declarations compared"], rows)
    else:
        lines.append("No logical dependency was compared.")
    return lines


def _candidates(view: _View) -> list[str]:
    candidates = view.record["candidates"]
    held = [c for c in candidates if c["classification"] == "held_by_policy"]
    in_scope = [c for c in candidates if c["classification"] == "in_scope"]
    lines = [
        "## Update candidates",
        "",
        f"{count(len(candidates), 'candidate')} on "
        f"{dependencies(len(view.candidates))}: {len(in_scope)} in scope, "
        f"{len(held)} held by policy. Dependencies whose lookup failed have no candidates; "
        "they are listed under Inventory as unknown.",
        "",
        "### Held by policy",
        "",
    ]
    if held:
        lines += table(
            ["Dependency", "Where", "Current", "Type", "Candidate", "Held by"],
            [[*_candidate_row(view, c), text(c["held_by"])] for c in sorted(held, key=view.place)],
        )
    else:
        lines.append("None.")
    lines += ["", "### In scope", ""]
    if in_scope:
        lines += table(
            ["Dependency", "Where", "Current", "Type", "Candidate"],
            [_candidate_row(view, c) for c in sorted(in_scope, key=view.place)],
        )
    else:
        lines.append("None.")
    return lines


def _candidate_row(view: _View, c: dict[str, Any]) -> list[str]:
    dep = view.entries[c["dependency"]]
    return [
        text(dep["name"]),
        view.where(c["dependency"]),
        version(dep["current"]),
        label(c["update_type"]),
        text(c["version"]),
    ]


def _cross_checks(view: _View) -> list[str]:
    checks = view.record["cross_checks"]
    lines = [
        "## Package manager cross-checks",
        "",
        "Direct dependencies `dotnet list package --outdated` or `go list -m -u` call outdated "
        "without a matching scan candidate: a blind spot of Renovate's.",
        "",
    ]
    down = [(tool, subject) for tool, subject in NATIVE.items() if subject in view.unavailable]
    for tool, subject in down:
        lines.append(
            f"- **{tool}: unknown**, {subject} didn't run: {text(view.unavailable[subject])}"
        )
    if down:
        lines.append("")
    if checks:
        rows = [
            [
                text(c["source"]),
                text(c["name"]),
                text(c["location"]),
                text(c["current"]),
                text(c["native_latest"]),
                ", ".join(text(v) for v in c["scan_candidates"]) or "no candidate",
            ]
            for c in checks
        ]
        headings = ["Tool", "Dependency", "Where", "Current", "Tool's latest", "Scan has"]
        lines += table(headings, rows)
    else:
        lines.append("No disagreements with the tools that ran.")
    return lines


def _gaps(view: _View) -> list[str]:
    gaps = view.record["gaps"]
    lines = [
        "## Coverage gaps",
        "",
        "What the scan couldn't cover: files no adapter reads or that can't be parsed, and "
        "sources that couldn't be read. Nothing here is known to be up to date.",
        "",
    ]
    if not gaps:
        return [*lines, "None."]
    rows = [[label(g["kind"]), text(g["subject"]), text(g["reason"])] for g in gaps]
    return lines + table(["Kind", "Subject", "Reason"], rows)


def _inventory(view: _View) -> list[str]:
    inventory = view.record["inventory"]
    states = Counter(d["lookup"]["state"] for d in inventory)
    origins = Counter(d["origin"] for d in inventory)
    because = Counter(d.get("locked_because") for d in inventory)
    ecosystems = Counter(d["ecosystem"] for d in inventory)
    lines = [
        "## Inventory",
        "",
        f"{dependencies(len(inventory))}: "
        + ", ".join(f"{states[s]} {s}" for s in ("outdated", "current", "unknown", "skipped"))
        + f"; {origins['declared']} declared in a manifest, {origins['locked']} resolved in a "
        f"lock file ({because['drift']} lock drift: the lock file resolves an older version "
        f"than the repository declares; {because['vulnerability']} added because an advisory "
        "concerns a package only a lock file or an indirect module has).",
        "",
        "By ecosystem: " + ", ".join(f"{text(e)} {n}" for e, n in sorted(ecosystems.items())) + ".",
    ]
    unlooked = [d for d in inventory if d["lookup"]["state"] in ("unknown", "skipped")]
    lines += ["", "### Not looked up", ""]
    if unlooked:
        lines.append(
            "An unknown lookup failed: whether the dependency is up to date is unknown. A "
            "skipped one wasn't attempted, for the reason given."
        )
        lines.append("")
        lines += table(
            ["Lookup", "Dependency", "Where", "Current", "Reason"],
            [
                [
                    d["lookup"]["state"],
                    text(d["name"]),
                    location(d["location"]),
                    version(d["current"]),
                    text(d["lookup"]["reason"]),
                ]
                for d in unlooked
            ],
        )
    else:
        lines.append("None: every dependency was looked up.")
    lines += ["", "### All dependencies", ""]
    if not inventory:
        return [*lines, "None found."]
    ordered = sorted(
        inventory, key=lambda d: (d["location"]["file"], d["location"].get("line", 0), d["name"])
    )
    rows = []
    for d in ordered:
        candidates = view.candidates.get(d["id"], [])
        found = ", ".join(
            text(c["version"]) + (" (held)" if c["classification"] == "held_by_policy" else "")
            for c in candidates
        )
        rows.append(
            [
                location(d["location"]),
                text(d["name"]),
                version(d["current"]),
                origin(d),
                text(d["ecosystem"]),
                d["lookup"]["state"],
                found,
            ]
        )
    return lines + table(
        ["Where", "Dependency", "Current", "Origin", "Ecosystem", "Lookup", "Candidates"], rows
    )


def _tools(view: _View) -> list[str]:
    rows = [
        [
            text(t["name"]),
            text(t["version"]),
            text(t.get("image") or t.get("url") or ""),
            text(t.get("fetched_at", "")),
        ]
        for t in view.record["tools"]
    ]
    return ["## Tools", "", *table(["Tool", "Version", "Image or source", "Read at"], rows)]
