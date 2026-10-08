import pytest

from sdlc.cli import main


def test_no_command_prints_usage_and_fails(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main([])
    assert exit_info.value.code == 2
    assert "usage: sdlc" in capsys.readouterr().err


def test_scan_help_describes_the_command(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--help"])
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "--repo" in out
    assert "Read-only" in out


def test_scan_requires_a_repository(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["scan"])
    assert exit_info.value.code == 2
    assert "--repo" in capsys.readouterr().err


def test_scan_of_an_unknown_ref_fails_without_a_record(monkeypatch, capsys):
    from sdlc import cli
    from sdlc.subject import SubjectError

    def unknown(repository, ref):
        raise SubjectError(f"{repository} has no branch or tag named {ref!r}")

    monkeypatch.setattr(cli, "resolve", unknown)
    assert main(["scan", "--repo", "alanta/demo", "--ref", "nope"]) == 1
    assert "no branch or tag named 'nope'; no record written" in capsys.readouterr().err
