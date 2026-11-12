"""Rules file loading and matching of message text against the rules.

No network and no state: text in, list of matches out.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLL_INTERVAL = 3.0
MIN_POLL_INTERVAL = 1.0

# A chat name becomes one MQTT topic level, so it must not contain "/", "+" or "#".
_CHAT_NAME = re.compile(r"-?[A-Za-z0-9_]+")
_KIND = re.compile(r"[a-z][a-z0-9_]*")


class ConfigError(ValueError):
    """The rules file is unusable; the message says where and why."""


@dataclass(frozen=True)
class Rule:
    kind: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class ChatConfig:
    name: str
    poll_interval: float
    rules: tuple[Rule, ...]
    # Words of the chat's subject; used only by the review of the rules.
    watch: re.Pattern[str] | None = None
    # Longer messages give no events: alerts are short, summaries and
    # commentary that use the same words are long.
    max_length: int | None = None

    def match(self, text: str) -> list["RuleMatch"]:
        """Events of a cleaned message text under this chat's rules."""
        if self.max_length is not None and len(text) > self.max_length:
            return []
        return match_rules(text, self.rules)


@dataclass(frozen=True)
class Config:
    chats: dict[str, ChatConfig]
    # situation.SituationConfig, when the file has a 'situation' section.
    situation: Any = None


@dataclass(frozen=True)
class RuleMatch:
    kind: str
    match: str
    fields: dict[str, str] = field(default_factory=dict)


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConfigError(f"{path}: cannot read: {error}") from error
    except yaml.YAMLError as error:
        raise ConfigError(f"{path}: invalid YAML: {error}") from error
    try:
        return parse_config(data)
    except ConfigError as error:
        raise ConfigError(f"{path}: {error}") from error


def parse_config(data: Any) -> Config:
    if not isinstance(data, dict) or not isinstance(data.get("chats"), dict):
        raise ConfigError("expected a top-level 'chats' mapping")
    unknown = set(data) - {"chats", "situation"}
    if unknown:
        raise ConfigError(f"unknown top-level keys: {sorted(unknown)}")
    if not data["chats"]:
        raise ConfigError("'chats' is empty")
    chats = {}
    for name, body in data["chats"].items():
        name = str(name)
        chats[name] = _parse_chat(name, body)
    situation = None
    if data.get("situation") is not None:
        from .situation import parse_situation  # imports this module

        situation = parse_situation(data["situation"], set(chats))
    return Config(chats=chats, situation=situation)


def _parse_chat(name: str, body: Any) -> ChatConfig:
    where = f"chats.{name}"
    if not _CHAT_NAME.fullmatch(name):
        raise ConfigError(f"{where}: chat name may contain only letters, digits and '_'")
    body = {} if body is None else body
    if not isinstance(body, dict):
        raise ConfigError(f"{where}: expected a mapping")
    unknown = set(body) - {"poll_interval", "rules", "watch", "max_length"}
    if unknown:
        raise ConfigError(f"{where}: unknown keys: {sorted(unknown)}")

    interval = body.get("poll_interval", DEFAULT_POLL_INTERVAL)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        raise ConfigError(f"{where}.poll_interval: expected a number of seconds")
    if interval < MIN_POLL_INTERVAL:
        raise ConfigError(f"{where}.poll_interval: must be at least {MIN_POLL_INTERVAL:g} s")

    raw_rules = body.get("rules")
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        raise ConfigError(f"{where}.rules: expected a list")
    rules = tuple(_parse_rule(f"{where}.rules[{index}]", raw) for index, raw in enumerate(raw_rules))
    watch = body.get("watch")
    if watch is not None:
        if not isinstance(watch, str) or not watch:
            raise ConfigError(f"{where}.watch: expected a regular expression")
        try:
            watch = re.compile(watch)
        except re.error as error:
            raise ConfigError(f"{where}.watch: invalid regular expression: {error}") from error
    max_length = body.get("max_length")
    if max_length is not None and (isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 1):
        raise ConfigError(f"{where}.max_length: expected a positive number of characters")
    return ChatConfig(
        name=name, poll_interval=float(interval), rules=rules, watch=watch, max_length=max_length
    )


def _parse_rule(where: str, raw: Any) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a mapping with 'kind' and 'pattern'")
    unknown = set(raw) - {"kind", "pattern"}
    if unknown:
        raise ConfigError(f"{where}: unknown keys: {sorted(unknown)}")
    kind, pattern = raw.get("kind"), raw.get("pattern")
    if not isinstance(kind, str) or not _KIND.fullmatch(kind):
        raise ConfigError(f"{where}.kind: expected a name of lowercase letters, digits and '_'")
    if not isinstance(pattern, str) or not pattern:
        raise ConfigError(f"{where}.pattern: expected a regular expression")
    try:
        compiled = re.compile(pattern)
    except re.error as error:
        raise ConfigError(f"{where}.pattern: invalid regular expression: {error}") from error
    if compiled.match(""):
        raise ConfigError(f"{where}.pattern: matches empty text, so it would fire on every message")
    return Rule(kind=kind, pattern=compiled)


def match_rules(text: str, rules: tuple[Rule, ...] | list[Rule]) -> list[RuleMatch]:
    """Return every rule match in the text, in the order they appear in it.

    The text is expected to be cleaned already (see text.clean_text). A
    trailing digit is dropped from a group name: two alternatives of one
    pattern cannot share a name, so "from2" also fills the field "from".
    """
    found = []
    for order, rule in enumerate(rules):
        for match in rule.pattern.finditer(text):
            if not match.group(0).strip():
                continue
            fields = {
                name.rstrip("0123456789"): value.strip()
                for name, value in match.groupdict().items()
                if value is not None and value.strip()
            }
            found.append((match.start(), order, RuleMatch(rule.kind, match.group(0).strip(), fields)))
    found.sort(key=lambda item: item[:2])
    return [item[2] for item in found]
