import json
import subprocess

from sdlc.renovate import _commit_policy, validator_problems

# What renovate-config-validator 44.145.1 logs for a policy it rejects (LOG_FORMAT=json).
REJECTED = """\
{"name":"renovate","level":30,"msg":"Validating /policy/renovate.json5 as repo config"}
{"name":"renovate","level":50,"file":"/policy/renovate.json5","errors":[{"topic":"Configuration Error","message":"Invalid configuration option: ignoreDep"},{"topic":"Configuration Error","message":"packageRules[0]: packageRules cannot combine both matchUpdateTypes and allowedVersions."}],"msg":"Found errors in configuration"}
"""  # noqa: E501
UNPARSEABLE = """\
{"name":"renovate","level":40,"file":"/policy/renovate.json5","err":{"message":"JSON5: invalid character"},"msg":"File could not be parsed"}
"""  # noqa: E501


def test_validator_errors_become_problems():
    assert validator_problems(REJECTED) == [
        "Invalid configuration option: ignoreDep",
        "packageRules[0]: packageRules cannot combine both matchUpdateTypes and allowedVersions.",
    ]
    assert validator_problems(UNPARSEABLE) == ["File could not be parsed: JSON5: invalid character"]
    assert validator_problems("Emulate Docker CLI using podman.\n") == []


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def test_the_policy_is_the_only_configuration_renovate_sees(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / "renovate.json").write_text("{}")
    (tmp_path / ".github" / "renovate.json5").write_text("{old: true}")
    (tmp_path / "go.mod").write_text("module x\n")
    git(tmp_path, "init", "--quiet")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "--quiet", "-m", "subject")

    _commit_policy(tmp_path, "{new: true}")
    assert git(tmp_path, "ls-files").split() == [".github/renovate.json5", "go.mod"]
    assert (tmp_path / ".github" / "renovate.json5").read_text() == "{new: true}"
    assert git(tmp_path, "status", "--porcelain") == ""

    _commit_policy(tmp_path, None)
    assert git(tmp_path, "ls-files").split() == ["go.mod"]


def test_package_json_keeps_its_dependencies_but_loses_its_renovate_key(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "dependencies": {"a": "1.0.0"}, "renovate": {"enabled": false}}'
    )
    git(tmp_path, "init", "--quiet")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "--quiet", "-m", "subject")

    _commit_policy(tmp_path, "{}")
    package = json.loads(git(tmp_path, "show", "HEAD:package.json"))
    assert package == {"name": "x", "dependencies": {"a": "1.0.0"}}
