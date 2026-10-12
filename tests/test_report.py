"""The Markdown report, rendered from a record alone."""

import ast
import copy
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sdlc import report
from sdlc.policy import Policy
from sdlc.record import schema, validate_record
from sdlc.report import render, text
from sdlc.selection import KINDS, select

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
    # Every kind of thing the selection can report, decided by the selection itself.
    record["inventory"].append(
        {
            "id": "dockerfile:mock-idp/Dockerfile:python",
            "ecosystem": "docker",
            "name": "python",
            "current": "3.10-alpine",
            "origin": "declared",
            "location": {"file": "mock-idp/Dockerfile", "line": 1},
            "lookup": {"state": "current"},
        }
    )
    record["lifecycle"] += [
        {
            "product": "python",
            "line": "3.10",
            "state": "nearing_end_of_life",
            "end_of_life": "2026-10-31",
            "supported_lines": ["3.12", "3.13"],
            "source": "https://endoflife.date/api/v1/products/python",
            "dependencies": ["dockerfile:mock-idp/Dockerfile:python"],
            "locations": [{"file": "mock-idp/Dockerfile", "line": 1}],
        },
        {
            "product": "alpine",
            "line": "latest",
            "state": "unknown",
            "reason": "The tag names no release.",
            "dependencies": [distroless["id"]],
            "locations": [distroless["location"]],
        },
    ]
    record["vulnerabilities"] += [
        {
            "advisory": "GHSA-open-apis-0001",
            "dependency": record["inventory"][1]["id"],
            "affected_version": "2.12.2",
            "fixed_version": "3.0.0",
            "fix_reached_by_candidate": False,
            "fix_reached_by": [],
            "fix_held_by": record["candidates"][1]["held_by"],
            "source": "osv",
            "reachability": "unknown",
        },
        {
            "advisory": "GHSA-aspi-reap-0002",
            "dependency": record["inventory"][0]["id"],
            "affected_version": "13.5.4",
            "fixed_version": "14.0.0",
            "fix_reached_by_candidate": False,
            "fix_reached_by": [],
            "source": "osv",
            "reachability": "unknown",
        },
    ]
    trial = Policy(record["policy"], "{}", "{}")
    today = datetime.fromisoformat(record["scanned_at"]).astimezone(UTC).date()
    record["selection"] = select(record, trial, today)
    assert {r["kind"] for r in record["selection"]["not_prepared"]} == set(KINDS)
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
    "selection": lambda r: selection_values(r["selection"]),
    "lifecycle": lambda r: [
        v for e in r["lifecycle"] for v in (e["product"], e.get("end_of_life"))
    ],
    "consistency": lambda r: [a["dependency"] for a in r["consistency"]],
    "inconsistencies": lambda r: [
        d["version"] for i in r["inconsistencies"] for d in i["declarations"]
    ],
    "cross_checks": lambda r: [c["native_latest"] for c in r["cross_checks"]],
    "gaps": lambda r: [v for g in r["gaps"] for v in (g["subject"], g["reason"])],
}


def selection_values(selection):
    """Every part of a selection that the report must show."""
    values = [selection["date"], selection["batch_window"]["next_opens"]]
    values += [
        str(selection["defaults"]["batch_window"]["first_day"]),
        str(selection["defaults"]["minimum_release_age_days"]),
    ]
    for unit in selection["units"]:
        values += [unit["name"], *unit["reasons"]]
        for t in unit["targets"]:
            values += [t["current"], t["version"], t["update_type"]]
        evidence = unit["evidence"]
        for a in evidence.get("advisories", []):
            values += [a["advisory"], a["source"], *a.get("aliases", [])]
        for e in evidence.get("lifecycle", []):
            values += [e["product"], e["line"], e.get("end_of_life")]
    for r in selection["not_prepared"]:
        values.append(r["detail"])
        values += [r.get(k) for k in ("advisory", "held_by", "source", "package", "old_enough_on")]
    return values


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
    assert "| Scanned at | 2026-10-05T09:00:00+00:00 |" in rendered
    assert "| Tools | renovate 44.145.1, endoflife.date v1 (details under Tools) |" in rendered
    assert (
        "| Update policy | trial file policies/azure-egress-proxy.renovate.json5, supplied for "
        "this scan |"
    ) in rendered
    assert "| Record schema | version 3 |" in rendered


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
    assert headings[:4] == ["## Summary", "## Would prepare", "## Lifecycle", "## Vulnerabilities"]
    summary = rendered.split("## Summary", 1)[1].split("\n## ", 1)[0]
    assert summary.index("**End of life:**") < summary.index("**Reachable vulnerabilities:**")
    assert summary.index("**Reachable vulnerabilities:**") < summary.index(
        "**Inconsistent declarations:**"
    )
    assert "  - go 1.25: ended 2026-08-19; still supported: 1.26, 1.27 (proxy/go.mod:3)" in summary


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


def test_hostile_names_and_reasons_cant_change_the_report(record):
    record["inventory"][0]["name"] = HOSTILE
    record["gaps"][0]["reason"] = HOSTILE
    assert validate_record(record) == []
    rendered = render(record)
    assert "<script>" not in rendered
    rest = outside_code(rendered)
    assert "://" not in rest and "www." not in rest and "evil.example" not in rest
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
    record["gaps"] += [
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
    assert "### Dependabot alerts\n\n**Unavailable:**" in rendered
    unknown = summary_item(rendered, "Unknown")
    for part in (
        "not read: osv-scanner: It crashed.",
        "not read: dependabot-alerts: The credential has no Dependabot alerts permission.",
        "1 lookup failed",
        "1 of 7 dependencies not looked up (skipped)",
        "reachability of 1 advisory",
        "whether a candidate fixes 1 advisory",
        "lifecycle of 1 line",
    ):
        assert part in unknown
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
    drop_security_units(record)
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
    drop_security_units(record)
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
    assert "  - 1 of 7 dependencies not looked up (skipped), with the reasons under Not" in unknown
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


def test_a_candidate_from_an_advisory_reads_as_its_fix_not_as_a_lookups_find(record):
    entry = {
        "id": "locked:proxy/go.mod:golang.org/x/text",
        "ecosystem": "go",
        "name": "golang.org/x/text",
        "current": "v0.3.7",
        "origin": "locked",
        "locked_because": "vulnerability",
        "location": {"file": "proxy/go.mod", "line": 12},
        "lookup": {
            "state": "outdated",
            "basis": "advisory_fix",
            "reason": "Not looked up in a registry.",
            "datasource": "go",
        },
    }
    record["inventory"].append(entry)
    record["candidates"].append(
        {
            "dependency": entry["id"],
            "update_type": "patch",
            "version": "v0.3.8",
            "classification": "in_scope",
            "basis": "advisory_fix",
        }
    )
    record["vulnerabilities"].append(
        {
            "advisory": "GO-2022-1059",
            "dependency": entry["id"],
            "affected_version": "v0.3.7",
            "fixed_version": "v0.3.8",
            "fix_reached_by_candidate": True,
            "fix_reached_by": ["v0.3.8"],
            "source": "osv",
            "reachability": "unknown",
        }
    )
    assert validate_record(record) == []
    rendered = render(record)
    assert "| golang.org/x/text | proxy/go.mod:12 | v0.3.7 | patch | v0.3.8 (advisory's fix) |" in (
        rendered
    )
    assert "1 candidate is marked advisory's fix: the fixed version an advisory names" in rendered
    assert (
        "| outdated, from advisories | golang.org/x/text | proxy/go.mod:12 | v0.3.7 | "
        "Not looked up in a registry. |"
    ) in rendered
    assert (
        "| locked, added for an advisory | go | outdated, from advisories | "
        "v0.3.8 (advisory's fix) |"
    ) in rendered
    assert "(1 outdated by their advisories alone)" in rendered
    assert (
        "whether newer versions exist for 1 dependency not looked up, whose only candidates "
        "are their advisories' fixes"
    ) in rendered


def drop_security_units(record):
    """The units that cite advisories, for a test that takes the advisories away."""
    selection = record["selection"]
    selection["units"] = [u for u in selection["units"] if "advisories" not in u["evidence"]]


def would_prepare(rendered):
    return rendered.split("\n## Would prepare\n", 1)[1].split("\n## ", 1)[0]


def test_the_selection_shows_each_unit_with_its_targets_and_evidence(record):
    section = would_prepare(render(record))
    assert "- **Batch window:** days 1 to 7 of every month; open on 2026-10-05; the next one" in (
        section
    )
    assert "opens 2026-11-01" in section
    assert "- **Minimum release age for batch updates:** 7 days" in section
    assert "### lifecycle-go-1.25\n\n- **Reason:** lifecycle\n- **Breaking:** yes" in section
    assert "| go | proxy/go.mod:3 | 1.25.14 | minor | 1.27.2 | 33 days old |" in section
    assert "- Lifecycle: go 1.25 is end of life, 2026-08-19; still supported: 1.26, 1.27" in section
    assert "- **Reason:** security\n- **Breaking:** no" in section
    assert (
        "| golang.org/x/net | proxy/go.mod | v0.40.0 | minor | v0.45.0 | age unknown |" in section
    )
    assert (
        "- Advisory GO-2026-6100 on golang.org/x/net v0.40.0 (proxy/go.mod): fixed in v0.41.0"
        in (section)
    )
    assert "- **Reason:** batch" in section
    assert (
        "| Aspire.AppHost.Sdk | src/AppHost/AppHost.csproj:1 | 13.5.4 | minor | 13.6.1 | "
        "25 days old |" in section
    )
    assert "- Batch window: days 1 to 7 of every month; minimum release age 7 days" in section
    summary = summary_item(render(record), "Would prepare")
    assert "3 units (1 breaking)" in summary and "3 reasons not prepared" in summary
    assert "the batch window is open on 2026-10-05, the next one opens 2026-11-01" in summary


def test_the_selection_says_what_it_could_not_prepare(full):
    section = would_prepare(render(full))
    for title in report.NOT_PREPARED.values():
        assert f"#### {title}\n" in section
    assert "- **Microsoft.OpenApi 2.12.2 (Directory.Packages.props):" not in section  # no unit
    assert "GHSA-open-apis-0001:** Vulnerable, fix held by policy" in section
    assert "Held by: Microsoft.OpenApi stays on 2.x" in section
    assert "No candidate reaches the fixed version 14.0.0." in section
    assert "python 3.10:** No in-scope candidate is on another supported line" in section
    assert "**source dependabot-alerts:**" not in section  # the alerts were read in `full`
    assert "Dependabot alert 5 on golang.org/x/text" in section
    assert "age 2 days old" not in section
    assert "2 days old, old enough on 2026-10-10" in section


def test_the_selection_says_so_when_there_is_nothing_to_prepare(record_from):
    from sdlc.renovate import Inventory

    section = would_prepare(render(record_from(Inventory([], []))))
    assert "No unit would be prepared." in section
    assert "Nothing that would have been prepared was left out." in section
    assert "closed on 2026-10-08" in section


def test_the_selection_marks_a_collision_and_a_release_after_the_scan(record):
    unit = record["selection"]["units"][2]
    unit["name_collision"] = True
    unit["targets"][0]["age_days"] = -2
    record["selection"]["not_prepared"].append(
        {
            "kind": "no_candidate",
            "reason": "security",
            "dependency": record["inventory"][0]["id"],
            "advisories": ["GHSA-one", "GHSA-two"],
            "detail": "No single in-scope candidate reaches the fix of every advisory.",
        }
    )
    section = would_prepare(render(record))
    assert "changed to tell it apart" in section
    assert "released 2 days after the scan" in section
    assert "GHSA-one; GHSA-two:** No single in-scope candidate" in section


def test_a_batch_unit_shows_the_open_security_reports_of_its_dependencies(record):
    batch = record["selection"]["units"][2]
    dep_id = batch["targets"][0]["dependency"]
    reference = {
        "kind": "fix_held",
        "dependency": dep_id,
        "advisory": "GHSA-held",
        "held_by": "Aspire stays on 13.x",
    }
    record["selection"]["not_prepared"].insert(
        0, reference | {"reason": "security", "detail": "Vulnerable, fix held by policy."}
    )
    batch["evidence"]["open_security_reports"] = [reference]
    assert validate_record(record) == []
    section = would_prepare(render(record))
    assert (
        "- Open security report, not prepared: Vulnerable, fix held by policy: GHSA-held on "
        "Aspire.AppHost.Sdk 13.5.4 (src/AppHost/AppHost.csproj:1); held by: Aspire stays on 13.x"
    ) in section
    reference["held_by"] = HOSTILE
    record["selection"]["not_prepared"][0]["held_by"] = HOSTILE
    rendered = render(record)
    assert "<script>" not in rendered
    rest = outside_code(rendered)
    assert "://" not in rest and "www." not in rest and "evil.example" not in rest


def test_a_lifecycle_unit_on_several_lines_shows_each_of_them(record):
    unit = record["selection"]["units"][1]
    unit["evidence"]["lifecycle"].append(
        {
            "product": "python",
            "line": "3.10",
            "state": "nearing_end_of_life",
            "end_of_life": "2026-10-31",
        }
    )
    assert validate_record(record) == []
    section = would_prepare(render(record))
    assert "- Lifecycle: go 1.25 is end of life, 2026-08-19; still supported: 1.26, 1.27" in section
    assert (
        "- Lifecycle: python 3.10 is nearing end of life, 2026-10-31; still supported: unknown"
        in (section)
    )


def assert_plain(rendered):
    assert "<script>" not in rendered
    rest = outside_code(rendered)
    assert "://" not in rest and "www." not in rest and "evil.example" not in rest
    assert "@someone" not in rest.replace("\\@someone", "")


def test_hostile_text_in_the_selection_cant_change_the_report(full):
    selection = full["selection"]
    # A target's version must be an in-scope candidate's, so the candidate says the same.
    target = selection["units"][0]["targets"][0]
    candidate = next(
        c
        for c in full["candidates"]
        if (c["dependency"], c["version"]) == (target["dependency"], target["version"])
    )
    candidate["version"] = target["version"] = HOSTILE
    for v in full["vulnerabilities"]:
        if v["dependency"] == target["dependency"]:
            v["fix_reached_by"] = [HOSTILE]
    advisory = selection["units"][0]["evidence"]["advisories"][0]
    advisory["source"] = HOSTILE
    advisory["aliases"] = [HOSTILE]
    selection["units"][1]["evidence"]["lifecycle"][0]["product"] = HOSTILE
    for r in selection["not_prepared"]:
        r["detail"] = HOSTILE
        if "package" in r:
            r["package"] = HOSTILE
        if "held_by" in r:
            r["held_by"] = HOSTILE
    full["dependabot_alerts"]["alerts"][0]["package"] = HOSTILE
    assert validate_record(full) == []
    rendered = render(full)
    assert_plain(rendered)
    section = would_prepare(rendered)
    # The hostile text does show: escaped, in the fields the selection fills.
    assert text(HOSTILE) in section
    assert f"Dependabot alert 5 on {text(HOSTILE)}" in section
    assert f"| {text(HOSTILE)} | " in section
    assert f"- Lifecycle: {text(HOSTILE)} 1.25" in section
