"""Writing the record and its report: both or, for an invalid record, no report."""

import json
from pathlib import Path

import pytest

from sdlc import outputs, report

VALID = Path(__file__).parent / "fixtures" / "records" / "valid.json"
COMMIT = "064aa099ecf7ffea9664b89df29f7d89d6859358"


@pytest.fixture
def record():
    return json.loads(VALID.read_text())


def test_the_run_directory_is_per_repository_commit_and_time(tmp_path):
    directory = outputs.run_directory(
        tmp_path, "alanta/azure-egress-proxy", COMMIT, "2026-10-09T11:00:00+02:00"
    )
    assert directory == tmp_path / "alanta" / "azure-egress-proxy" / COMMIT / "20261009T090000Z"


@pytest.mark.parametrize("repository", ["../x", "alanta/..", "alanta/.", "a\\b/c"])
def test_a_run_directory_stays_under_its_base(tmp_path, repository):
    with pytest.raises(ValueError, match="can't name a run directory"):
        outputs.run_directory(tmp_path, repository, COMMIT, "2026-10-09T09:00:00+00:00")


def test_a_valid_record_is_written_with_its_report(tmp_path, record):
    directory = tmp_path / "run"
    record_path, report_path = outputs.write(record, directory)
    assert json.loads(record_path.read_text()) == record
    assert report_path.read_text() == report.render(record)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["run"]
    assert sorted(p.name for p in directory.iterdir()) == ["record.json", "report.md"]


def test_an_invalid_record_gets_no_report(tmp_path, record):
    del record["subject"]["commit"]
    record["candidates"][0]["classification"] = "maybe"
    directory = tmp_path / "run"
    with pytest.raises(outputs.InvalidRecord) as raised:
        outputs.write(record, directory)
    problems = raised.value.problems
    assert any("commit" in p for p in problems)
    assert any("maybe" in p for p in problems)
    # Kept beside the run directory, under a name nothing that reads records picks up.
    assert raised.value.kept == tmp_path / "run.invalid.json"
    assert json.loads(raised.value.kept.read_text()) == record
    assert [p.name for p in tmp_path.iterdir()] == ["run.invalid.json"]


def test_a_record_failing_only_a_semantic_check_gets_no_report(tmp_path, record):
    record["candidates"][0]["dependency"] = "nuget:nowhere:Nothing"
    with pytest.raises(outputs.InvalidRecord) as raised:
        outputs.write(record, tmp_path / "run")
    assert any("unknown dependency id" in p for p in raised.value.problems)
    assert not list(tmp_path.rglob("report.md")) and not list(tmp_path.rglob("record.json"))


def test_a_failed_write_leaves_no_run_directory(tmp_path, record, monkeypatch):
    def full(self, data, encoding=None):
        if self.name == "report.md":
            raise OSError("No space left on device")
        return len(data)

    monkeypatch.setattr(Path, "write_text", full)
    with pytest.raises(OSError, match="No space"):
        outputs.write(record, tmp_path / "run")
    assert list(tmp_path.iterdir()) == []


def test_an_existing_run_directory_is_not_overwritten(tmp_path, record):
    directory = tmp_path / "run"
    directory.mkdir()
    (directory / "report.md").write_text("an earlier scan")
    with pytest.raises(FileExistsError):
        outputs.write(record, directory)
    assert (directory / "report.md").read_text() == "an earlier scan"


def test_an_invalid_record_never_goes_into_an_existing_run_directory(tmp_path, record):
    directory = tmp_path / "run"
    directory.mkdir()
    (directory / "report.md").write_text("an earlier scan")
    record["candidates"][0]["classification"] = "maybe"
    with pytest.raises(outputs.InvalidRecord) as raised:
        outputs.write(record, directory)
    assert raised.value.kept == tmp_path / "run.invalid.json"
    assert [p.name for p in directory.iterdir()] == ["report.md"]


def test_an_earlier_kept_record_is_never_overwritten(tmp_path, record):
    (tmp_path / "run.invalid.json").write_text("an earlier one")
    record["candidates"][0]["classification"] = "maybe"
    with pytest.raises(outputs.InvalidRecord) as raised:
        outputs.write(record, tmp_path / "run")
    assert raised.value.kept is None
    assert "exists" in raised.value.not_kept
    assert raised.value.problems
    assert (tmp_path / "run.invalid.json").read_text() == "an earlier one"


def test_a_render_failure_keeps_the_valid_record_without_a_report(tmp_path, record, monkeypatch):
    def broken(record):
        raise KeyError("a renderer bug")

    monkeypatch.setattr(report, "render", broken)
    with pytest.raises(outputs.Unrendered) as raised:
        outputs.write(record, tmp_path / "run")
    assert isinstance(raised.value.error, KeyError)
    assert raised.value.kept == tmp_path / "run.unrendered.json"
    assert json.loads(raised.value.kept.read_text()) == record
    assert [p.name for p in tmp_path.iterdir()] == ["run.unrendered.json"]
