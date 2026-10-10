"""The Markdown report, rendered from a record alone."""

import ast
import copy
import json
import re
from pathlib import Path

import pytest

from sdlc import report
from sdlc.record import schema, validate_record
from sdlc.report import render, text

VALID = Path(__file__).parent / "fixtures" / "records" / "valid.json"


@pytest.fixture
def record():
    return json.loads(VALID.read_text())


@pytest.fixture
def full(record):
    """The valid record with every optional section and none of its lists empty."""
    record["gaps"] = [
        {
            "kind": "unsupported_source",
            "subject": "infra/image.pkr.hcl",
            "reason": "Packer template that no scan adapter reads.",
        }
    ]
    record["dependabot_alerts"] = {
        "ref": "main",
        "commit": "e93d7062b075352f151f8e6b5a15f60913e7bd98",
        "is_scanned_commit": False,
        "read_at": "2026-10-08T09:00:06+00:00",
        "alerts": [
            {
                "number": 5,
                "advisory": "GHSA-abcd-efgh-ijkl",
                "ecosystem": "go",
                "package": "golang.org/x/text",
                "manifest": "proxy/go.mod",
                "fixed_version": "0.3.8",
                "result": "unmatched",
            }
        ],
    }
    go, distroless = record["inventory"][4], record["inventory"][3]
    record["consistency"].append(
        {"dependency": "Go toolchain", "compared": [go["id"], distroless["id"]]}
    )
    record["inconsistencies"] = [
        {
            "dependency": "Go toolchain",
            "declarations": [
                {"dependency": go["id"], "location": go["location"], "version": "1.25.14"},
                {
                    "dependency": distroless["id"],
                    "location": distroless["location"],
                    "version": "1.27",
                },
            ],
        }
    ]
    record["cross_checks"] = [
        {
            "source": "go",
            "name": "golang.org/x/crypto",
            "location": "proxy/go.mod",
            "current": "v0.55.0",
            "native_latest": "v0.57.0",
            "scan_candidates": [],
        }
    ]
    assert validate_record(record) == []
    return record


# Per top-level property of the record, values from it that its section must show.
REPRESENTATIVE = {
    "schema_version": lambda r: [f"version {r['schema_version']}"],
    "subject": lambda r: list(r["subject"].values()),
    "scanned_at": lambda r: [r["scanned_at"]],
    "tools": lambda r: [v for t in r["tools"] for v in (t["name"], t["version"], t.get("url"))],
    "policy": lambda r: [r["policy"]["path"]],
    "inventory": lambda r: [v for d in r["inventory"] for v in (d["name"], d["current"])],
    "candidates": lambda r: [v for c in r["candidates"] for v in (c["version"], c.get("held_by"))],
    "vulnerabilities": lambda r: [v["advisory"] for v in r["vulnerabilities"]],
    "dependabot_alerts": lambda r: [
        v for a in r["dependabot_alerts"]["alerts"] for v in (a["advisory"], a["package"])
    ],
    "lifecycle": lambda r: [v for e in r["lifecycle"] for v in (e["product"], e["end_of_life"])],
    "consistency": lambda r: [a["dependency"] for a in r["consistency"]],
    "inconsistencies": lambda r: [
        d["version"] for i in r["inconsistencies"] for d in i["declarations"]
    ],
    "cross_checks": lambda r: [c["native_latest"] for c in r["cross_checks"]],
    "parity": lambda r: [
        v
        for pr in r["parity"]["pull_requests"]
        for u in pr["updates"]
        for v in (f"#{pr['number']}", u["name"], u["to"], u["reason"])
    ],
    "gaps": lambda r: [v for g in r["gaps"] for v in (g["subject"], g["reason"])],
}


def test_every_section_of_the_record_shows_in_the_report(full):
    # Driven by the schema: a section added to it without a place in the report fails here.
    properties = set(schema()["properties"])
    assert set(report.SECTIONS) == properties
    assert set(REPRESENTATIVE) == properties
    rendered = render(full)
    lines = rendered.splitlines()
    for section, start in report.SECTIONS.items():
        assert any(line.startswith(start) for line in lines), section
        values = [v for v in REPRESENTATIVE[section](full) if v is not None]
        assert values, section
        for value in values:
            assert text(value) in rendered, (section, value)


def test_every_section_shows_even_when_it_is_empty(record_from):
    from sdlc.renovate import Inventory

    empty = record_from(Inventory([], []))
    assert validate_record(empty) == []
    lines = render(empty).splitlines()
    for section, start in report.SECTIONS.items():
        assert any(line.startswith(start) for line in lines), section


def test_the_report_names_what_the_spec_requires(record):
    rendered = render(record)
    assert "| Repository | alanta/azure-egress-proxy |" in rendered
    assert "| Commit | 064aa099ecf7ffea9664b89df29f7d89d6859358 |" in rendered
    assert "| Scanned at | 2026-10-08T09:00:00+00:00 |" in rendered
    assert "| Tools | renovate 44.145.1, endoflife.date v1 (details under Tools) |" in rendered
    assert (
        "| Update policy | trial file policies/azure-egress-proxy.renovate.json5, supplied for "
        "this scan |"
    ) in rendered
    assert "| Record schema | version 1 |" in rendered


def test_the_report_reads_nothing_but_the_record():
    """Structurally: the module imports nothing that reaches files, processes or the network."""
    tree = ast.parse(Path(report.__file__).read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imported == {"re", "collections", "typing"}
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert not names & {"open", "exec", "eval", "__import__"}


def test_rendering_leaves_the_record_as_it_was(record):
    before = copy.deepcopy(record)
    render(record)
    assert record == before


def test_the_most_urgent_findings_come_first(record):
    rendered = render(record)
    headings = [line for line in rendered.splitlines() if line.startswith("## ")]
    assert headings[:3] == ["## Summary", "## Lifecycle", "## Vulnerabilities"]
    summary = rendered.split("## Summary", 1)[1].split("\n## ", 1)[0]
    assert summary.index("**End of life:**") < summary.index("**Reachable vulnerabilities:**")
    assert summary.index("**Reachable vulnerabilities:**") < summary.index("**Missed Dependabot")
    assert summary.index("**Missed Dependabot") < summary.index("**Inconsistent declarations:**")
    assert "  - go 1.25: ended 2026-08-19; still supported: 1.26, 1.27 (proxy/go.mod:3)" in summary
    assert "  - #77 Microsoft.Extensions.Http 10.0.11 → 10.0.12: the scan has no candidate" in (
        summary
    )


HOSTILE = (
    "a | b `c` <script>alert(1)</script> [link](https://x.example) *e* @someone\nnext "
    "www.evil.example me@evil.example ``https://a|b`"
)
CODE_SPAN = re.compile(r"(`+)(?!`).*?(?<!`)\1(?!`)")


def outside_code(markdown):
    return CODE_SPAN.sub("", markdown)


def test_untrusted_text_is_plain_text():
    escaped = text(HOSTILE)
    assert "\n" not in escaped
    assert "&lt;script&gt;" in escaped and "<script>" not in escaped
    assert "\\|" in escaped and "\\`c\\`" in escaped
    assert "\\*e\\*" in escaped and "\\@someone" in escaped
    # What GitHub would link by itself goes in a code span, where nothing links.
    assert "`[link](https://x.example)`" in escaped
    assert "`www.evil.example`" in escaped and "`me@evil.example`" in escaped
    assert "``` ``https://a\\|b` ```" in escaped
    rest = outside_code(escaped)
    assert "://" not in rest and "www." not in rest and "evil.example" not in rest
    # An @ inside a word, such as an image digest, mentions no one and stays as it is.
    assert text("renovate:44@sha256:abc") == "renovate:44@sha256:abc"


def test_a_hostile_pr_title_and_names_cant_change_the_report(record):
    pr = record["parity"]["pull_requests"][0]
    pr["title"] = HOSTILE
    pr["updates"][0]["reason"] = HOSTILE
    record["inventory"][0]["name"] = HOSTILE
    record["gaps"][0]["reason"] = HOSTILE
    assert validate_record(record) == []
    rendered = render(record)
    assert "<script>" not in rendered
    rest = outside_code(rendered)
    assert "://" not in rest and "www." not in rest and "evil.example" not in rest
    assert f"### #77: {text(HOSTILE)}\n" in rendered
    # Every row of every table keeps its header's columns: no pipe from the text splits a cell.
    columns = None
    for line in rendered.splitlines():
        if not line.startswith("|"):
            columns = None
            continue
        pipes = len(re.findall(r"(?<!\\)\|", line))
        if columns is None:
            columns = pipes
        assert pipes == columns, line


def test_unknown_states_are_shown_as_unknown_never_as_none(record):
    record["inventory"][2]["lookup"] = {"state": "unknown", "reason": "rate limited"}
    record["inventory"][2]["current"] = None
    record["vulnerabilities"][0] |= {
        "fixed_version": "v0.56.0",
        "fix_reached_by_candidate": "unknown",
        "reachability": "unknown",
    }
    record["lifecycle"][0] = {
        "product": "go",
        "line": "1.25",
        "state": "unknown",
        "reason": "endoflife.date couldn't be reached",
        "dependencies": record["lifecycle"][0]["dependencies"],
        "locations": record["lifecycle"][0]["locations"],
    }
    # Dependabot's PRs weren't read either.
    record["parity"] = {
        "baseline": "dependabot",
        "complete": False,
        "reasons": ["Dependabot's open PRs couldn't be read: 403"],
        "pull_requests": [],
        "scan_only": [],
    }
    record["gaps"] += [
        {"kind": "unavailable_source", "subject": "dependabot-prs", "reason": "GitHub said 403."},
        {"kind": "unavailable_source", "subject": "osv-scanner", "reason": "It crashed."},
    ]
    assert validate_record(record) == []
    rendered = render(record)

    assert "| unknown | golang.org/x/crypto | proxy/go.mod | unknown | rate limited |" in rendered
    assert "| reachability unknown" not in rendered  # the column says unknown, plainly
    assert "| unknown | fixed in v0.56.0 | unknown | osv |" in rendered
    assert "| unknown | go | 1.25 | unknown: endoflife.date couldn't be reached |" in rendered
    assert "- **End of life:** none found, but 1 line is unknown" in rendered
    assert "- **Reachable vulnerabilities:** unknown, OSV-Scanner didn't run" in rendered
    assert "## Vulnerabilities\n\n**Unknown.** OSV-Scanner didn't run: It crashed." in rendered
    assert "- **Missed Dependabot updates:** unknown, Dependabot's PRs weren't read" in rendered
    assert "**Unknown.** Dependabot's open PRs couldn't be read: GitHub said 403." in rendered
    assert "### Dependabot alerts\n\n**Unavailable:**" in rendered
    unknown = summary_item(rendered, "Unknown")
    for part in (
        "not read: osv-scanner: It crashed.",
        "not read: dependabot-alerts: The credential has no Dependabot alerts permission.",
        "not read: dependabot-prs: GitHub said 403.",
        "1 lookup failed",
        "1 of 5 dependencies not looked up (skipped)",
        "reachability of 1 advisory",
        "whether a candidate fixes 1 advisory",
        "lifecycle of 1 line",
    ):
        assert part in unknown
    assert "Missed Dependabot updates:** none" not in rendered
    assert "nothing; every source was read" not in rendered


def test_a_record_with_everything_read_says_nothing_is_unknown(record):
    record["gaps"] = []
    record["dependabot_alerts"] = {
        "ref": "main",
        "commit": record["subject"]["commit"],
        "is_scanned_commit": True,
        "read_at": "2026-10-08T09:00:06+00:00",
        "alerts": [],
    }
    record["inventory"][3]["lookup"] = {"state": "current"}
    record["vulnerabilities"] = []
    assert validate_record(record) == []
    rendered = render(record)
    assert "- **Unknown:** nothing; every source was read and every file covered" in rendered
    assert "- **Reachable vulnerabilities:** none known\n" in rendered
    assert "## Coverage gaps" in rendered and "\nNone.\n" in rendered
    assert "They describe the default branch as Dependabot last analysed it: main at 064aa09" in (
        rendered
    )


def test_every_gap_is_listed(record):
    record["gaps"] += [
        {"kind": "unsupported_source", "subject": f"infra/{n}.pkr.hcl", "reason": "Packer"}
        for n in range(30)
    ]
    rendered = render(record)
    for gap in record["gaps"]:
        assert f"| {text(gap['subject'])} | {text(gap['reason'])} |" in rendered
    assert "- **Coverage gaps:** 31, all listed under Coverage gaps" in rendered


def summary_item(rendered, name):
    """A Summary bullet with its sub-bullets."""
    summary = rendered.split("\n## Summary\n", 1)[1].split("\n## ", 1)[0]
    start = summary.index(f"- **{name}:**")
    end = summary.find("\n- ", start + 1)
    return summary[start : end if end != -1 else None]


def test_every_source_the_scan_couldnt_read_is_unknown(record):
    """Not only the sources the report knows by name: every unavailable gap, so a new source or
    a single module or lock file shows too."""
    record["vulnerabilities"] = []
    record["gaps"] += [
        {
            "kind": "unavailable_source",
            "subject": "govulncheck: proxy/go.mod",
            "reason": "govulncheck didn't run: toolchain download failed",
        },
        {
            "kind": "unavailable_source",
            "subject": "src/Portal/packages.lock.json",
            "reason": "OSV-Scanner returned no result for this lock file.",
        },
    ]
    assert validate_record(record) == []
    rendered = render(record)
    unknown = summary_item(rendered, "Unknown")
    assert unknown.startswith("- **Unknown:** 4:\n")
    assert "  - not read: govulncheck: proxy/go.mod: govulncheck didn't run" in unknown
    assert "  - not read: src/Portal/packages.lock.json: OSV-Scanner returned no result" in unknown
    assert "  - 1 of 5 dependencies not looked up (skipped), with the reasons under Not" in unknown
    # Neither a gap's source nor the lack of advisories is claimed as complete.
    assert (
        "- **Reachable vulnerabilities:** none found; incomplete, 2 sources or files couldn't be "
        "checked (see Unknown)\n"
    ) in rendered
    assert "none known" not in rendered and "every source was read" not in rendered
    section = rendered.split("\n## Vulnerabilities\n", 1)[1].split("\n### ", 1)[0]
    assert "**Incomplete.** These couldn't be checked, so they may hide advisories:" in section
    assert "- govulncheck: proxy/go.mod: govulncheck didn't run" in section
    assert "- src/Portal/packages.lock.json: OSV-Scanner returned no result" in section
    # Dependabot's alerts aren't a vulnerability source: they don't make the advisories unknown.
    assert "dependabot-alerts" not in section.split("**Incomplete.**")[1]


def test_coverage_gaps_alone_never_read_as_everything_covered(record):
    record["gaps"] = [
        {"kind": "unsupported_source", "subject": "infra/cloud-init.yaml", "reason": "cloud-init"}
    ]
    record["dependabot_alerts"] = {
        "ref": "main",
        "commit": record["subject"]["commit"],
        "is_scanned_commit": True,
        "read_at": "2026-10-08T09:00:06+00:00",
        "alerts": [],
    }
    record["inventory"][3]["lookup"] = {"state": "current"}
    assert validate_record(record) == []
    rendered = render(record)
    assert "- **Unknown:** nothing beyond the files the coverage gaps name\n" in rendered
    assert "every source was read" not in rendered


def test_a_tool_that_didnt_run_is_its_own_list_before_the_text_that_follows(record):
    record["gaps"].append(
        {"kind": "unavailable_source", "subject": "dotnet list package", "reason": "restore broke"}
    )
    rendered = render(record)
    assert (
        "- **dotnet: unknown**, dotnet list package didn't run: restore broke\n\n"
        "No disagreements with the tools that ran."
    ) in rendered


def test_locked_entries_say_why_the_scan_lists_them(record):
    drift = {
        "id": "locked:src/AppHost/packages.lock.json:Microsoft.Extensions.Http",
        "ecosystem": "nuget",
        "name": "Microsoft.Extensions.Http",
        "current": "10.0.11",
        "origin": "locked",
        "locked_because": "drift",
        "location": {"file": "src/AppHost/packages.lock.json", "line": 663},
        "lookup": {"state": "current"},
    }
    advisory = drift | {
        "id": "locked:proxy/go.mod:golang.org/x/text",
        "ecosystem": "go",
        "name": "golang.org/x/text",
        "current": "v0.3.7",
        "locked_because": "vulnerability",
        "location": {"file": "proxy/go.mod"},
    }
    record["inventory"] += [drift, advisory]
    assert validate_record(record) == []
    rendered = render(record)
    assert "| Microsoft.Extensions.Http | 10.0.11 | locked, lock drift | nuget |" in rendered
    assert "| golang.org/x/text | v0.3.7 | locked, added for an advisory | go |" in rendered
    assert "2 resolved in a lock file (1 lock drift: " in rendered
    assert "1 added because an advisory concerns a package" in rendered
