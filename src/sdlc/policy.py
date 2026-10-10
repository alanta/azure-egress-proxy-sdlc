"""The subject's update policy: load it, check it, and classify candidates by it.

The policy is Renovate configuration (design decision 4), but Renovate's report doesn't say
which rule held an update: a held major still appears in it, and `allowedVersions` drops
versions without a trace. So the scan runs Renovate twice, with and without the rules that
hold updates, and evaluates those rules itself to name the one that applies. The scan only
accepts hold rules it can evaluate the way Renovate does; anything else fails the scan
instead of being classified by guesswork.

Everything here is pure, apart from reading the policy file, so it can be tested without
containers.
"""

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import json5

from sdlc.renovate import CONFIG_FILES, POLICY_PATH, Inventory

# The matchers the scan evaluates itself, with the dependency field each one reads.
MATCHERS = {
    "matchPackageNames": "packageName",
    "matchDepNames": "depName",
    "matchDatasources": "datasource",
    "matchManagers": "manager",
    "matchUpdateTypes": "updateType",
}

# Renovate matches custom managers as `custom.<name>` (util/package-rules/managers.js).
CUSTOM_MANAGERS = {"regex", "jsonata"}

IGNORE_DEPS = "ignoreDeps"

# Everything a hold rule may contain: a rule that does more than hold updates would need the
# scan to understand that too.
HOLD_RULE_KEYS = {"description", "enabled", "allowedVersions", *MATCHERS}

# The update types `matchUpdateTypes` may name (config/options), apart from `bump`, which
# Renovate matches on a flag its report doesn't carry.
UPDATE_TYPES = {
    "major",
    "minor",
    "patch",
    "pin",
    "pinDigest",
    "digest",
    "lockFileMaintenance",
    "rollback",
    "replacement",
}

# Rule options that change the names and datasource later rules match on.
OVERRIDES = {"overrideDatasource", "overrideDepName", "overridePackageName"}


class PolicyError(Exception):
    """The policy can't be read, or holds updates in a way the scan can't follow."""


@dataclass(frozen=True)
class HoldRule:
    name: str  # the rule's description, which names it in the record
    rule: dict[str, Any]

    @property
    def disables(self) -> bool:
        return self.rule.get("enabled") is False


@dataclass(frozen=True)
class Policy:
    source: dict[str, str]  # the record's policy entry
    content: str | None  # the policy as Renovate reads it; None when there is none
    baseline: str | None  # the same without its holds, to see what they hold back
    holds: tuple[HoldRule, ...] = ()
    ignored: tuple[str, ...] = ()


NO_POLICY = Policy({"source": "none"}, None, None)


def load(
    checkout: Path, trial: Path | None = None, *, validate: Callable[[str], list[str]]
) -> Policy:
    """Read the policy from a trial file or the checkout, and check it.

    `validate` is Renovate's own validator: it returns the problems it finds, if any.
    """
    if trial is not None:
        if not trial.is_file():
            raise PolicyError(f"trial policy {trial} doesn't exist")
        source = {"source": "trial", "path": str(trial)}
        text = _read(trial)
    else:
        others = [
            name for name in CONFIG_FILES if name != POLICY_PATH and (checkout / name).is_file()
        ]
        if has_package_json_config(checkout):
            others.append("package.json")
        if others:
            raise PolicyError(
                f"the revision has Renovate configuration in {', '.join(others)}; "
                f"the scan reads its policy only from {POLICY_PATH}"
            )
        if not (checkout / POLICY_PATH).is_file():
            return NO_POLICY
        source = {"source": "subject", "path": POLICY_PATH}
        text = _read(checkout / POLICY_PATH)

    where = source["path"]
    try:
        config = json5.loads(text)
    except ValueError as error:
        raise PolicyError(f"policy {where} can't be parsed: {error}") from error
    if not isinstance(config, dict):
        raise PolicyError(f"policy {where} is not an object")

    problems = validate(text)
    if problems:
        raise PolicyError(f"Renovate rejects policy {where}: " + "; ".join(problems))

    holds, ignored, baseline = _split(config, where)
    return Policy(
        source,
        text,
        json.dumps(baseline, indent=2) if baseline != config else text,
        holds,
        ignored,
    )


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise PolicyError(f"policy {path} can't be read: {error}") from error


def has_package_json_config(checkout: Path) -> bool:
    """Whether the root package.json carries Renovate configuration under `renovate`."""
    try:
        package = json.loads((checkout / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(package, dict) and "renovate" in package


def _split(
    config: dict[str, Any], where: str
) -> tuple[tuple[HoldRule, ...], tuple[str, ...], dict]:
    """The hold rules and ignored dependencies, and the configuration without them.

    A hold rule is a package rule with `enabled: false` or `allowedVersions`. It must name
    itself with a description and use only the matchers in MATCHERS.
    """
    _check_not_hidden(config, where)
    rules = config.get("packageRules") or []
    holds, kept = [], []
    for index, rule in enumerate(rules):
        label = f"{where}: packageRules[{index}]"
        _check_not_hidden(rule, label)
        if rule.get("enabled") is True:
            # A later rule that re-enables updates would undo an earlier hold in Renovate's
            # rule order, which the scan doesn't follow.
            raise PolicyError(f"{label} sets enabled: true, which the scan can't follow")
        if IGNORE_DEPS in rule:
            raise PolicyError(f"{label}: use the top-level ignoreDeps, not one in a rule")
        overrides = sorted(OVERRIDES & rule.keys())
        if overrides:
            raise PolicyError(
                f"{label} uses {', '.join(overrides)}, which changes what hold rules match on"
            )
        if rule.get("enabled") is not False and "allowedVersions" not in rule:
            kept.append(rule)
            continue

        description = rule.get("description")
        if isinstance(description, list):
            description = " ".join(str(d) for d in description)
        if not isinstance(description, str) or not description.strip():
            raise PolicyError(f"{label} holds updates but has no description to name it by")
        label = f"{label} ({description})"
        unsupported = sorted(rule.keys() - HOLD_RULE_KEYS)
        if unsupported:
            raise PolicyError(
                f"{label} holds updates with {', '.join(unsupported)}; hold rules can only "
                f"use {', '.join(sorted(HOLD_RULE_KEYS))}"
            )
        # Renovate accepts a single string where it expects a list (config/massage.js).
        normalized = {k: _as_list(v) if k in MATCHERS else v for k, v in rule.items()}
        for key in MATCHERS:
            for pattern in normalized.get(key, []):
                _check_pattern(pattern, f"{label} {key}")
        for update_type in normalized.get("matchUpdateTypes", []):
            if update_type not in UPDATE_TYPES:
                # `bump` and negations match on a flag the report doesn't carry.
                raise PolicyError(
                    f"{label} matchUpdateTypes: the scan can't evaluate {update_type!r}"
                )
        holds.append(HoldRule(description.strip(), normalized))

    ignored = tuple(_as_list(config.get(IGNORE_DEPS) or []))
    baseline = {k: v for k, v in config.items() if k != IGNORE_DEPS}
    if "packageRules" in config:
        baseline["packageRules"] = kept
    return tuple(holds), ignored, baseline


def _check_not_hidden(config: dict[str, Any], where: str) -> None:
    """Fail on configuration that brings in rules the scan never sees."""
    if "extends" in config:
        raise PolicyError(f"{where} uses extends; presets can hold updates the scan can't see")
    # Configuration per update type, such as `major: {enabled: false}`: Renovate turns it into
    # rules of its own (config/massage.js) or merges it per update, out of the scan's sight.
    hidden = sorted(UPDATE_TYPES & config.keys())
    if hidden:
        raise PolicyError(
            f"{where} configures {', '.join(hidden)} updates directly; use a package rule "
            "with matchUpdateTypes instead"
        )


def _as_list(value: Any) -> list:
    return [value] if isinstance(value, str) else list(value)


def reconcile(
    baseline: Inventory,
    main: Inventory,
    dependencies: dict[str, dict[str, Any]],
    policy: Policy,
) -> tuple[Inventory, Inventory]:
    """Both runs, with a dependency only one of them could look up made `unknown` in both.

    Classifying needs both lookups: the run with the policy says which candidates it lets
    through, and the run without its holds finds the candidates they hold. When the lookup
    failed in either run (a registry hiccup, a rate limit), the difference between them says
    nothing about the policy. So the dependency becomes `unknown` with the run and Renovate's
    message, its candidates are dropped from both runs instead of being guessed at, and the
    scan carries on. A skip under the policy counts as a failure too, unless a rule turns the
    whole dependency off. Lookups that failed in both runs alike are left as they are.
    """
    main_lookups = {d["id"]: d["lookup"] for d in main.dependencies}
    failed: dict[str, str] = {}
    for dep in baseline.dependencies:
        dep_id, lookup = dep["id"], dep["lookup"]
        other = main_lookups.get(dep_id)
        if lookup["state"] in ("outdated", "current"):
            if other is None:
                failed[dep_id] = "Renovate's run with the policy didn't list it"
            elif other["state"] == "unknown":
                failed[dep_id] = f"Renovate's lookup with the policy failed: {other['reason']}"
            elif other["state"] == "skipped" and not _disabling(
                dependencies[dep_id], policy, dependency_level=True
            ):
                failed[dep_id] = f"Renovate skipped it with the policy: {other['reason']}"
        elif lookup["state"] == "unknown" and other and other["state"] in ("outdated", "current"):
            failed[dep_id] = (
                f"Renovate's lookup without the policy's holds failed: {lookup['reason']}"
            )
    if not failed:
        return baseline, main

    def unknown(dep: dict[str, Any]) -> dict[str, Any]:
        if dep["id"] not in failed:
            return dep
        reason = f"{failed[dep['id']].rstrip('.')}; so its candidates can't be classified."
        return {**dep, "lookup": {**dep["lookup"], "state": "unknown", "reason": reason}}

    def kept(inventory: Inventory) -> Inventory:
        return Inventory(
            [unknown(d) for d in inventory.dependencies],
            [c for c in inventory.candidates if c["dependency"] not in failed],
        )

    return kept(baseline), kept(main)


def classify(
    baseline: list[dict[str, Any]],
    main: Inventory | None,
    dependencies: dict[str, dict[str, Any]],
    policy: Policy,
) -> list[dict[str, Any]]:
    """Classify candidates as in scope or held by policy, naming the rules that hold them.

    `baseline` holds the candidates Renovate found without the policy's holds, `main` what
    it found with the whole policy. A candidate only the baseline has was dropped by an
    `allowedVersions` rule. `main` is None for candidates Renovate never looked up, such as
    lock-file drift: the scan then evaluates the rules, `allowedVersions` included, itself.
    `dependencies` gives each dependency id the fields Renovate matches on: depName,
    packageName, datasource, manager.
    """
    if main is None:
        return [_classified(c, _rule_holds(c, dependencies, policy)) for c in baseline]

    kept = {(c["dependency"], c["version"]) for c in main.candidates}
    lookups = {d["id"]: d["lookup"] for d in main.dependencies}
    classified = []
    for candidate in baseline:
        dep_id, version = candidate["dependency"], candidate["version"]
        dep = {**dependencies[dep_id], "updateType": candidate["update_type"]}
        holding = _disabling(dep, policy)
        if (dep_id, version) not in kept:
            if not holding:
                lookup = lookups.get(dep_id, {"state": "missing"})
                if lookup["state"] not in ("outdated", "current"):
                    # Without a lookup, a missing candidate says nothing about the policy;
                    # reconcile() turns such dependencies into `unknown` before this.
                    raise PolicyError(
                        f"Renovate's lookup of {dep_id} with the policy ended "
                        f"{lookup['state']} ({lookup.get('reason', 'no reason given')}), so "
                        "its candidates can't be classified"
                    )
                holding = [h.name for h in _limits(dep, policy)]
            if not holding:
                raise PolicyError(
                    f"Renovate held back {dep_id} {version}, but no hold rule in the policy "
                    "matches it, so it can't be classified"
                )
        elif _disabling(dep, policy, dependency_level=True):
            raise PolicyError(
                f"the policy disables {dep_id}, but Renovate still proposes {version}, so it "
                "can't be classified"
            )
        classified.append(_classified(candidate, holding))

    # A version `allowedVersions` lets through where the newest one was dropped (Humanizer
    # 2.9.9 under "<2.10.0", where 2.14.1 was the minor) is a candidate of its own.
    seen = {(c["dependency"], c["version"]) for c in baseline}
    with_candidates = {c["dependency"] for c in baseline}
    for candidate in main.candidates:
        if (candidate["dependency"], candidate["version"]) in seen:
            continue
        if candidate["dependency"] not in with_candidates:
            raise PolicyError(
                f"Renovate proposes {candidate['dependency']} {candidate['version']} only "
                "under the policy, so it can't be classified"
            )
        dep = {**dependencies[candidate["dependency"]], "updateType": candidate["update_type"]}
        classified.append(_classified(candidate, _disabling(dep, policy)))
    return classified


def _rule_holds(
    candidate: dict[str, Any], dependencies: dict[str, dict[str, Any]], policy: Policy
) -> list[str]:
    """The rules holding a candidate Renovate never saw, evaluated by the scan alone."""
    return holds(
        dependencies[candidate["dependency"]],
        candidate["update_type"],
        candidate["version"],
        policy,
    )


def holds(
    fields: dict[str, Any], update_type: str | None, version: str, policy: Policy
) -> list[str]:
    """The rules that hold this version of a dependency, evaluated by the scan alone.

    `fields` are the ones Renovate matches on (depName, packageName, datasource, manager).
    An `allowedVersions` the scan can't evaluate for the version raises PolicyError.
    """
    dep = {**fields, "updateType": update_type}
    holding = _disabling(dep, policy)
    for hold in _limits(dep, policy):
        if not allowed(version, hold.rule["allowedVersions"]):
            holding.append(hold.name)
    return holding


def _limits(dep: dict[str, Any], policy: Policy) -> list[HoldRule]:
    """The `allowedVersions` rules that apply to the dependency."""
    return [h for h in policy.holds if "allowedVersions" in h.rule and matches(h.rule, dep)]


_COMPARATOR = re.compile(r"\s*(<=|>=|<|>|=)\s*(\d+(?:\.\d+)*)\s*")


def allowed(version: str, allowed_versions: str) -> bool:
    """Whether `allowedVersions` lets a version through, for the forms the scan evaluates
    exactly: a `/regex/` (filter.js tests it against the version), or comparators such as
    `>=2.0 <3` on numeric versions. Anything else depends on the dependency's versioning,
    so it fails rather than guess."""
    if _REGEX.match(allowed_versions):
        return match_one(version, allowed_versions)
    comparators = []
    rest = allowed_versions
    while rest:
        found = _COMPARATOR.match(rest)
        if not found or found.end() == 0:
            break
        comparators.append((found[1], _numeric(found[2])))
        rest = rest[found.end() :]
    current = _numeric(version) if re.fullmatch(r"\d+(?:\.\d+)*", version) else None
    if rest or not comparators or current is None:
        raise PolicyError(
            f"the scan can't evaluate allowedVersions {allowed_versions!r} for {version} "
            "itself; use a /regex/ or comparators such as '<3.0.0' on numeric versions"
        )
    checks = {
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "=": lambda a, b: a == b,
    }
    return all(checks[op](_pad(current, bound), _pad(bound, current)) for op, bound in comparators)


def _numeric(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _pad(version: tuple[int, ...], other: tuple[int, ...]) -> tuple[int, ...]:
    """2.10 and 2.10.0 are the same version."""
    return version + (0,) * (len(other) - len(version))


def _classified(candidate: dict[str, Any], holding: list[str]) -> dict[str, Any]:
    if holding:
        return {**candidate, "classification": "held_by_policy", "held_by": "; ".join(holding)}
    return {**candidate, "classification": "in_scope"}


def _disabling(dep: dict[str, Any], policy: Policy, *, dependency_level: bool = False) -> list[str]:
    """Rules that turn the update off. With `dependency_level`, only those Renovate applies
    before its lookup, so they leave no candidate for the dependency at all."""
    names = [IGNORE_DEPS] if dep.get("depName") in policy.ignored else []
    for hold in policy.holds:
        if dependency_level and "matchUpdateTypes" in hold.rule:
            continue
        if hold.disables and matches(hold.rule, dep):
            names.append(hold.name)
    return names


def matches(rule: dict[str, Any], dep: dict[str, Any]) -> bool:
    """Whether every matcher in the rule matches, as Renovate's package rules decide.

    A rule without a matcher for a field doesn't look at it; a field the dependency lacks
    doesn't match (util/package-rules/*.js).
    """
    for key, field in MATCHERS.items():
        if key not in rule:
            continue
        value = dep.get(field)
        if not value:
            return False
        if key == "matchManagers" and value in CUSTOM_MANAGERS:
            value = f"custom.{value}"
        if not match_list(value, _as_list(rule[key])):
            return False
    return True


def match_list(value: str, patterns: Iterable[str]) -> bool:
    """Renovate's matchRegexOrGlobList (util/string-match.js).

    The value must match at least one positive pattern, if there are any, and every
    negated one (`!pattern`, `!/regex/`).
    """
    patterns = list(patterns)
    if not patterns:
        return False
    positive = [p for p in patterns if not p.startswith("!")]
    negative = [p for p in patterns if p.startswith("!")]
    if positive and not any(match_one(value, p) for p in positive):
        return False
    return all(match_one(value, p) for p in negative)


_REGEX = re.compile(r"^!?/.*/i?$", re.DOTALL)


def match_one(value: str, pattern: str) -> bool:
    """One pattern: `*`, a `/regex/` (case-sensitive unless `/i`), or a case-insensitive
    glob. A leading `!` negates either."""
    if pattern == "*":
        return True
    if _REGEX.match(pattern):
        negated = pattern.startswith("!")
        body = pattern.removeprefix("!").removeprefix("/")
        flags = re.IGNORECASE if body.endswith("i") else 0
        body = body.removesuffix("i").removesuffix("/")
        return bool(re.search(body, value, flags)) != negated
    negations = len(pattern) - len(pattern.lstrip("!"))
    found = any(
        re.fullmatch(_glob_regex(p), value, re.IGNORECASE | re.DOTALL)
        for p in _expand_braces(pattern[negations:])
    )
    return found != (negations % 2 == 1)


def _check_pattern(pattern: Any, where: str) -> None:
    """Fail on patterns the scan would evaluate differently from Renovate."""
    if not isinstance(pattern, str):
        raise PolicyError(f"{where}: {pattern!r} is not a string")
    if _REGEX.match(pattern):
        body = pattern.removeprefix("!").removeprefix("/")
        body = body.removesuffix("i").removesuffix("/")
        try:
            re.compile(body)
        except re.error as error:
            raise PolicyError(f"{where}: can't evaluate {pattern}: {error}") from error
    # Checked before a leading negation is taken off: `!(a|b)` is an extended glob too.
    elif re.search(r"[?*+@!]\(|\{[^}]*\.\.[^}]*\}", pattern):
        raise PolicyError(f"{where}: extended glob {pattern} is not supported")


def _expand_braces(pattern: str) -> list[str]:
    """`a{b,c}d` -> `abd`, `acd`, as minimatch expands it before matching."""
    match = re.search(r"\{([^{}]*,[^{}]*)\}", pattern)
    if not match:
        return [pattern]
    head, tail = pattern[: match.start()], pattern[match.end() :]
    return [e for part in match[1].split(",") for e in _expand_braces(head + part + tail)]


def _glob_regex(pattern: str) -> str:
    """Translate a minimatch glob: `*` and `?` stay within a path segment, `**` crosses."""
    segments = pattern.split("/")
    out = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            out.append(".*" if last else "(?:[^/]*/)*")
        else:
            out.append(_segment_regex(segment) + ("" if last else "/"))
    return "".join(out)


def _segment_regex(segment: str) -> str:
    out, i = [], 0
    while i < len(segment):
        char = segment[i]
        if char == "\\" and i + 1 < len(segment):
            out.append(re.escape(segment[i + 1]))
            i += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[" and "]" in segment[i + 2 :]:
            end = segment.index("]", i + 2)
            body = segment[i + 1 : end]
            if body[:1] in ("!", "^"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end + 1
            continue
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)
