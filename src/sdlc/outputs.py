"""A scan's outputs: the record, and the report rendered from it, in their own run directory.

A run directory only ever appears complete, with both files: they are written to a hidden
staging directory beside it, which is then renamed. A scan takes minutes, so when it can't
produce that pair its record is still kept, as a single file beside where the run directory
would be and never inside one:
- `<time>.invalid.json` when the record fails validation: no report, and a name nothing that
  reads records picks up;
- `<time>.unrendered.json` when the record is valid but rendering its report failed, which is
  a bug in the renderer. The record itself is sound, so it can be rendered again once the bug
  is fixed, but it never sits in a run directory without its report.
"""

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sdlc import report
from sdlc.record import validate_record

RECORD = "record.json"
REPORT = "report.md"


class Unwritten(Exception):
    """The scan's record and report couldn't be written as a pair; nothing went into a run
    directory. `kept` is where the record went instead, if anywhere; `not_kept` says why it
    couldn't be kept."""

    def __init__(self, message: str, kept: Path | None, not_kept: str | None):
        super().__init__(message)
        self.kept = kept
        self.not_kept = not_kept


class InvalidRecord(Unwritten):
    """The record fails its schema or its semantic checks, so no report is written."""

    def __init__(self, problems: list[str], kept: Path | None, not_kept: str | None):
        super().__init__(f"the record is invalid ({len(problems)} problems)", kept, not_kept)
        self.problems = problems


class Unrendered(Unwritten):
    """The record is valid, but rendering its report failed."""

    def __init__(self, error: Exception, kept: Path | None, not_kept: str | None):
        super().__init__(f"rendering the report failed: {error!r}", kept, not_kept)
        self.error = error


def run_directory(base: Path, repository: str, commit: str, scanned_at: str) -> Path:
    """`<base>/<owner>/<name>/<commit>/<UTC time>`, as design decision 8 lays it out."""
    parts = [*repository.split("/"), commit]
    if any(part in ("", ".", "..") or "\\" in part for part in parts):
        raise ValueError(f"{repository}@{commit} can't name a run directory")
    stamp = datetime.fromisoformat(scanned_at).astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return base.joinpath(*parts, stamp)


def write(record: dict[str, Any], directory: Path) -> tuple[Path, Path]:
    """Validate the record, render its report, and write both; the paths of record and report.

    Raises InvalidRecord or Unrendered, with nothing written but the kept record, when there
    can't be a report.
    """
    problems = validate_record(record)
    if problems:
        raise InvalidRecord(problems, *_keep(record, directory, "invalid"))
    try:
        text = report.render(record)
    except Exception as error:  # a renderer bug must not lose the scan
        raise Unrendered(error, *_keep(record, directory, "unrendered")) from error
    if directory.exists():
        raise FileExistsError(f"{directory} already exists")
    staging = directory.with_name(f".{directory.name}.partial")
    staging.mkdir(parents=True)
    try:
        (staging / RECORD).write_text(_json(record), encoding="utf-8")
        (staging / REPORT).write_text(text, encoding="utf-8")
        staging.rename(directory)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return directory / RECORD, directory / REPORT


def _keep(record: Any, directory: Path, why: str) -> tuple[Path | None, str | None]:
    """The record as a file of its own beside the run directory; or why it couldn't be."""
    kept = directory.with_name(f"{directory.name}.{why}.json")
    try:
        content = _json(record)
        kept.parent.mkdir(parents=True, exist_ok=True)
        with kept.open("x", encoding="utf-8") as file:  # never over an earlier one
            file.write(content)
    except (OSError, TypeError, ValueError) as error:
        return None, str(error)
    return kept, None


def _json(record: Any) -> str:
    return json.dumps(record, indent=2, ensure_ascii=False) + "\n"
