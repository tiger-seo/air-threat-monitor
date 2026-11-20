"""The decision module: what the channels' events mean for the home.

Rules say what one message is ("a ballistic missile toward Kyiv"). This
module keeps the course of a ballistic threat across messages and sources
and, together with the air-alert level, turns it into a severity for the
home. Weapons known only by their course (Banderol, jet drones) are tracked
the same way by `Course`, without the alert level; `Interpreter` holds them
all. It knows nothing about rooms, volume or night: that stays with the
consumer.

Pure: events and the clock come in, decisions go out.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .processor import Publication
from .rules import ConfigError

NONE, ATTENTION, TAKE_COVER, IMPACT = "none", "attention", "take_cover", "impact"
SEVERITIES = (NONE, ATTENTION, TAKE_COVER, IMPACT)
ALERT_LEVELS = ("none", "yellow", "red")

# Event kinds of the rules that this module understands.
THREAT = "ballistic_threat"
BALLISTIC_MISSILE = "ballistic_missile"
MISSILE = "missile"  # type not named: counts only during a ballistic threat
DESCENT = "ballistic_descent"
CLEAR = "ballistic_clear"
NOTHING_TRACKED = "nothing_tracked"


@dataclass(frozen=True)
class SourceConfig:
    # An official source ends the threat with its all-clear; the end reported
    # by another source only withdraws the current warning.
    official: bool = False
    # The source writes about the home area only: its missile messages
    # concern the home even when they name no place ("2 ракети!").
    about_home: bool = False


@dataclass(frozen=True)
class CourseConfig:
    """A threat known only from its course ("Бандероль курсом на Київ").

    There is no threat announcement and no all-clear: an episode lasts while
    messages name places near the home, and ends `episode_timeout` after the
    last one.
    """

    episode_timeout: timedelta = timedelta(minutes=30)
    inbound_hold: timedelta = timedelta(minutes=10)
    repeat_interval: timedelta = timedelta(minutes=5)
    # Narrower places that mean "at us" for this threat ("над Києвом"); with
    # it, the general home and region both count as the region.
    home: re.Pattern[str] | None = None
    # Every message of the rules counts as "at us", whatever places it names:
    # for a report with no place at all ("Ймовірно здійснено пуски крилатих
    # ракет").
    always_home: bool = False


@dataclass(frozen=True)
class SituationConfig:
    home: re.Pattern[str]
    region: re.Pattern[str] | None
    sources: dict[str, SourceConfig]
    episode_timeout: timedelta = timedelta(minutes=60)
    inbound_hold: timedelta = timedelta(minutes=10)
    descent_hold: timedelta = timedelta(minutes=2)
    repeat_interval: timedelta = timedelta(seconds=60)
    stale_after: timedelta = timedelta(seconds=120)
    # Threats tracked by course, by the event kind of their rules; the kind
    # is also the threat's topic.
    courses: dict[str, CourseConfig] = field(default_factory=dict)


_COURSE_NAME = re.compile(r"[a-z][a-z0-9_]*")


def _seconds(where: str, data: dict, keys: Sequence[str]) -> dict[str, timedelta]:
    seconds = {}
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ConfigError(f"{where}.{key}: expected a positive number of seconds")
        seconds[key] = timedelta(seconds=value)
    return seconds


def _parse_courses(where: str, data: Any) -> dict[str, CourseConfig]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected a mapping of event kinds")
    durations = ("episode_timeout", "inbound_hold", "repeat_interval")
    courses = {}
    for name, body in data.items():
        name = str(name)
        if not _COURSE_NAME.fullmatch(name) or name == "ballistic":
            raise ConfigError(f"{where}.{name}: expected an event kind other than 'ballistic'")
        body = {} if body is None else body
        if not isinstance(body, dict) or set(body) - {*durations, "home", "always_home"}:
            raise ConfigError(f"{where}.{name}: expected only home, always_home, {', '.join(durations)}")
        always_home = body.get("always_home", False)
        if not isinstance(always_home, bool):
            raise ConfigError(f"{where}.{name}.always_home: expected true or false")
        home = None
        if body.get("home") is not None:
            raw = body["home"]
            if not isinstance(raw, str) or not raw:
                raise ConfigError(f"{where}.{name}.home: expected a regular expression")
            try:
                home = re.compile(raw)
            except re.error as error:
                raise ConfigError(f"{where}.{name}.home: invalid regular expression: {error}") from error
            if home.search(""):
                raise ConfigError(f"{where}.{name}.home: matches empty text, so every place would count")
        courses[name] = CourseConfig(home=home, always_home=always_home, **_seconds(f"{where}.{name}", body, durations))
    return courses


def parse_situation(data: Any, chat_names: set[str]) -> SituationConfig:
    where = "situation"
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected a mapping")
    durations = ("episode_timeout", "inbound_hold", "descent_hold", "repeat_interval", "stale_after")
    unknown = set(data) - {"home", "region", "sources", "courses", *durations}
    if unknown:
        raise ConfigError(f"{where}: unknown keys: {sorted(unknown)}")

    def pattern(key: str, required: bool) -> re.Pattern[str] | None:
        raw = data.get(key)
        if raw is None and not required:
            return None
        if not isinstance(raw, str) or not raw:
            raise ConfigError(f"{where}.{key}: expected a regular expression")
        try:
            compiled = re.compile(raw)
        except re.error as error:
            raise ConfigError(f"{where}.{key}: invalid regular expression: {error}") from error
        if compiled.search(""):
            raise ConfigError(f"{where}.{key}: matches empty text, so every place would count")
        return compiled

    sources = {}
    raw_sources = data.get("sources")
    if not isinstance(raw_sources, dict) or not raw_sources:
        raise ConfigError(f"{where}.sources: expected a mapping of chat names")
    for name, body in raw_sources.items():
        name = str(name)
        if name not in chat_names:
            raise ConfigError(f"{where}.sources.{name}: no such chat under 'chats'")
        body = {} if body is None else body
        if not isinstance(body, dict) or set(body) - {"official", "about_home"}:
            raise ConfigError(f"{where}.sources.{name}: expected only 'official' and 'about_home'")
        for key, value in body.items():
            if not isinstance(value, bool):
                raise ConfigError(f"{where}.sources.{name}.{key}: expected true or false")
        sources[name] = SourceConfig(**body)

    return SituationConfig(
        home=pattern("home", True),
        region=pattern("region", False),
        sources=sources,
        courses=_parse_courses(f"{where}.courses", data.get("courses")),
        **_seconds(where, data, durations),
    )


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Situation:
    """Tracks one ballistic threat at a time and emits a decision on every change.

    A decision is a dict ready to publish; `change` is "raised", "lowered",
    "repeat" (the same severity confirmed by a new message) or "clear".
    """

    def __init__(self, config: SituationConfig):
        self.config = config
        self.alert_level: str | None = None  # None: not known
        self._reset()
        self._severity = NONE
        self._last_emit: datetime | None = None

    def _reset(self) -> None:
        self._open = False
        self._since: datetime | None = None
        self._last_activity: datetime | None = None
        self._inbound_until: datetime | None = None
        self._inbound_scope: str | None = None
        self._descent_until: datetime | None = None
        self._missile_ids: dict[str, set[int]] = {}
        self._peak = NONE

    # --- inputs ---------------------------------------------------------------

    def set_alert_level(self, level: str | None, now: datetime) -> list[dict]:
        self.alert_level = level if level in ALERT_LEVELS else None
        return self._evaluate(now, {"reason": "alert_level"}, repeat=False)

    def tick(self, now: datetime) -> list[dict]:
        """Let time pass: holds expire, a threat with no all-clear times out."""
        if not self._open:
            return []
        if now - self._last_activity > self.config.episode_timeout:
            return self._close(now, {"reason": "timeout"})
        return self._evaluate(now, {"reason": "hold_expired"}, repeat=False)

    def feed(self, source: str, publications: Sequence[Publication], now: datetime) -> list[dict]:
        """Take what the gateway published for one message of a source."""
        config = self.config.sources.get(source)
        if config is None or not publications:
            return []
        when = datetime.strptime(publications[0].payload["date"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if now - when > self.config.stale_after:
            return []
        events = [p.payload for p in publications if p.kind == "event"]
        decisions: list[dict] = []
        if events:
            for payload in events:
                decisions += self._on_event(source, config, payload, now)
        else:
            decisions += self._on_plain_message(source, config, publications[0].payload, now)
        return decisions

    # --- events ---------------------------------------------------------------

    def _on_event(self, source: str, config: SourceConfig, payload: dict, now: datetime) -> list[dict]:
        kind = payload["kind"]
        cause = {"reason": kind, "source": source, "id": payload["id"], "text": payload["text"]}

        if kind == THREAT:
            self._touch(now)
            return self._evaluate(now, cause, repeat=False)

        if kind == BALLISTIC_MISSILE or (kind == MISSILE and self._open):
            self._touch(now)
            self._missile_ids.setdefault(source, set()).add(payload["id"])
            scope = self._scope(payload["text"])
            if scope is None and config.about_home and kind == BALLISTIC_MISSILE:
                scope = "home"
            self._inbound(scope, now)
            return self._evaluate(now, cause, repeat=scope == "home")

        if not self._open:
            return []

        if kind == DESCENT:
            self._touch(now)
            self._descent_until = now + self.config.descent_hold
            self._inbound("home", now)
            return self._evaluate(now, cause, repeat=True)

        if kind == CLEAR and config.official:
            return self._close(now, cause)

        if kind in (CLEAR, NOTHING_TRACKED):
            self._inbound_until = self._inbound_scope = self._descent_until = None
            return self._evaluate(now, cause, repeat=False)
        return []

    def _on_plain_message(self, source: str, config: SourceConfig, payload: dict, now: datetime) -> list[dict]:
        """A message no rule knows counts when it answers a missile message: "Київ!"."""
        ids = self._missile_ids.get(source)
        if not self._open or not ids or payload.get("reply_to") not in ids:
            return []
        ids.add(payload["id"])
        scope = self._scope(payload["text"])
        if scope is None:
            return []
        self._touch(now)
        self._inbound(scope, now)
        cause = {"reason": "reply", "source": source, "id": payload["id"], "text": payload["text"]}
        return self._evaluate(now, cause, repeat=scope == "home")

    # --- state ----------------------------------------------------------------

    def _touch(self, now: datetime) -> None:
        if not self._open:
            self._open = True
            self._since = now
        self._last_activity = now

    def _scope(self, text: str) -> str | None:
        if self.config.home.search(text):
            return "home"
        if self.config.region is not None and self.config.region.search(text):
            return "region"
        return None

    def _inbound(self, scope: str | None, now: datetime) -> None:
        if scope is None:
            return
        home_active = self._inbound_scope == "home" and self._inbound_until and now < self._inbound_until
        if scope == "region" and home_active:
            return
        self._inbound_scope = scope
        self._inbound_until = now + self.config.inbound_hold

    def state(self, now: datetime) -> str:
        if not self._open:
            return "idle"
        if self._descent_until and now < self._descent_until:
            return "descent"
        if self._inbound_until and now < self._inbound_until:
            return f"inbound_{self._inbound_scope}"
        return "threat"

    def severity(self, now: datetime) -> str:
        state = self.state(now)
        if state == "idle":
            return NONE
        if state == "descent":
            return IMPACT
        if state == "inbound_home":
            return TAKE_COVER
        if state == "inbound_region":
            return ATTENTION
        # A threat with no destination concerns the home only when the home
        # is under an alert. Not knowing the level is treated as an alert.
        return NONE if self.alert_level == "none" else ATTENTION

    def snapshot(self, now: datetime) -> dict:
        return {
            "threat": "ballistic",
            "state": self.state(now),
            "severity": self.severity(now),
            "alert_level": self.alert_level,
            "since": _iso(self._since) if self._since else None,
            "at": _iso(now),
        }

    def _decision(self, now: datetime, change: str, cause: dict) -> dict:
        decision = self.snapshot(now)
        decision.update(change=change, peak=self._peak, source=None, id=None, text=None)
        decision.update(cause)
        self._last_emit = now
        return decision

    def _evaluate(self, now: datetime, cause: dict, repeat: bool) -> list[dict]:
        severity = self.severity(now)
        previous, self._severity = self._severity, severity
        if SEVERITIES.index(severity) > SEVERITIES.index(self._peak):
            self._peak = severity
        if severity != previous:
            raised = SEVERITIES.index(severity) > SEVERITIES.index(previous)
            return [self._decision(now, "raised" if raised else "lowered", cause)]
        confirmed = repeat and severity in (TAKE_COVER, IMPACT)
        if confirmed and now - self._last_emit >= self.config.repeat_interval:
            return [self._decision(now, "repeat", cause)]
        return []

    def _close(self, now: datetime, cause: dict) -> list[dict]:
        peak, since = self._peak, self._since
        self._reset()
        self._severity = NONE
        decision = self._decision(now, "clear", cause)
        decision.update(peak=peak, since=_iso(since) if since else None)
        return [decision]


class Course:
    """Tracks one threat known only from its course, such as "Бандероль" or a jet drone.

    Only messages that name a place near the home count: elsewhere the same
    weapon flies every day. The severity follows the place: the home gives
    "take_cover", the region "attention"; each holds `inbound_hold` after the
    last such message. A reply in a thread about the weapon continues the
    episode; one about nothing tracked ("не фікс") withdraws the warning. The
    episode ends `episode_timeout` after the last message that counted.
    Decisions have the same fields as the ballistic ones.
    """

    def __init__(self, kind: str, config: CourseConfig, situation: SituationConfig):
        self.kind = kind
        self.config = config
        self.situation = situation
        self._severity = NONE
        self._last_emit: datetime | None = None
        self._reset()

    def _reset(self) -> None:
        self._open = False
        self._since: datetime | None = None
        self._last_activity: datetime | None = None
        self._inbound_until: datetime | None = None
        self._inbound_scope: str | None = None
        self._ids: dict[str, set[int]] = {}
        self._peak = NONE

    def tick(self, now: datetime) -> list[dict]:
        if not self._open:
            return []
        if now - self._last_activity > self.config.episode_timeout:
            return self._close(now, {"reason": "timeout"})
        return self._evaluate(now, {"reason": "hold_expired"}, repeat=False)

    def feed(self, source: str, publications: Sequence[Publication], now: datetime) -> list[dict]:
        if source not in self.situation.sources or not publications:
            return []
        when = datetime.strptime(publications[0].payload["date"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if now - when > self.situation.stale_after:
            return []
        message = publications[0].payload
        ids = self._ids.setdefault(source, set())
        is_reply = message.get("reply_to") is not None and message.get("reply_to") in ids
        events = [p.payload for p in publications if p.kind == "event"]
        ours = [e for e in events if e["kind"] == self.kind]
        cause = {"source": source, "id": message["id"], "text": message["text"]}

        if ours:
            scopes = [self._scope(e["match"]) for e in ours]
            scope = "home" if "home" in scopes else "region" if "region" in scopes else None
            if scope is None and not (is_reply and self._open):
                return []
            ids.add(message["id"])
            self._touch(now)
            self._inbound(scope, now)
            # A reply follows the same weapon; only a new message is another one.
            return self._evaluate(now, {"reason": self.kind, **cause}, repeat=scope == "home" and not is_reply)

        if not self._open or not is_reply:
            return []
        ids.add(message["id"])
        if any(e["kind"] == NOTHING_TRACKED for e in events):
            self._inbound_until = self._inbound_scope = None
            return self._evaluate(now, {"reason": NOTHING_TRACKED, **cause}, repeat=False)
        if events:
            return []
        # A message no rule knows, in a thread about this weapon: "Вишгород!".
        self._touch(now)
        self._inbound(self._scope(message["text"]), now)
        return self._evaluate(now, {"reason": "reply", **cause}, repeat=False)

    def _scope(self, text: str) -> str | None:
        if self.config.always_home:
            return "home"
        own_home = self.config.home
        if own_home is not None and own_home.search(text):
            return "home"
        if self.situation.home.search(text):
            return "region" if own_home is not None else "home"
        if self.situation.region is not None and self.situation.region.search(text):
            return "region"
        return None

    def _touch(self, now: datetime) -> None:
        if not self._open:
            self._open = True
            self._since = now
        self._last_activity = now

    def _inbound(self, scope: str | None, now: datetime) -> None:
        if scope is None:
            return
        home_active = self._inbound_scope == "home" and self._inbound_until and now < self._inbound_until
        if scope == "region" and home_active:
            return
        self._inbound_scope = scope
        self._inbound_until = now + self.config.inbound_hold

    def state(self, now: datetime) -> str:
        if not self._open:
            return "idle"
        if self._inbound_until and now < self._inbound_until:
            return f"inbound_{self._inbound_scope}"
        return "nearby"

    def severity(self, now: datetime) -> str:
        return {"inbound_home": TAKE_COVER, "inbound_region": ATTENTION}.get(self.state(now), NONE)

    def snapshot(self, now: datetime, alert_level: str | None = None) -> dict:
        return {
            "threat": self.kind,
            "state": self.state(now),
            "severity": self.severity(now),
            "alert_level": alert_level,
            "since": _iso(self._since) if self._since else None,
            "at": _iso(now),
        }

    def _decision(self, now: datetime, change: str, cause: dict) -> dict:
        decision = self.snapshot(now)
        decision.update(change=change, peak=self._peak, source=None, id=None, text=None)
        decision.update(cause)
        self._last_emit = now
        return decision

    def _evaluate(self, now: datetime, cause: dict, repeat: bool) -> list[dict]:
        severity = self.severity(now)
        previous, self._severity = self._severity, severity
        if SEVERITIES.index(severity) > SEVERITIES.index(self._peak):
            self._peak = severity
        if severity != previous:
            raised = SEVERITIES.index(severity) > SEVERITIES.index(previous)
            return [self._decision(now, "raised" if raised else "lowered", cause)]
        if repeat and severity == TAKE_COVER and now - self._last_emit >= self.config.repeat_interval:
            return [self._decision(now, "repeat", cause)]
        return []

    def _close(self, now: datetime, cause: dict) -> list[dict]:
        peak, since = self._peak, self._since
        self._reset()
        self._severity = NONE
        decision = self._decision(now, "clear", cause)
        decision.update(peak=peak, since=_iso(since) if since else None)
        return [decision]


class Interpreter:
    """The ballistic threat and every threat tracked by course, side by side.

    Each decision carries its threat in "threat", which is also its topic.
    """

    def __init__(self, config: SituationConfig):
        self.ballistic = Situation(config)
        self.courses = {kind: Course(kind, course, config) for kind, course in config.courses.items()}

    @property
    def threats(self) -> list[str]:
        return ["ballistic", *self.courses]

    @property
    def alert_level(self) -> str | None:
        return self.ballistic.alert_level

    def set_alert_level(self, level: str | None, now: datetime) -> list[dict]:
        return self.ballistic.set_alert_level(level, now)

    def tick(self, now: datetime) -> list[dict]:
        decisions = self.ballistic.tick(now)
        for course in self.courses.values():
            decisions += course.tick(now)
        return decisions

    def feed(self, source: str, publications: Sequence[Publication], now: datetime) -> list[dict]:
        decisions = self.ballistic.feed(source, publications, now)
        for course in self.courses.values():
            decisions += course.feed(source, publications, now)
        return decisions

    def idle(self, now: datetime) -> bool:
        return all(t.state(now) == "idle" for t in (self.ballistic, *self.courses.values()))

    def snapshot(self, threat: str, now: datetime) -> dict:
        if threat == "ballistic":
            return self.ballistic.snapshot(now)
        return self.courses[threat].snapshot(now, self.ballistic.alert_level)
