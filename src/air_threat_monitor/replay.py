"""Replay of saved histories through the gateway and the decision module.

Shows what the home would have heard over a period: the way to judge the
decision rules, and to see what a change to them does, without waiting for
the next attack.

Limits: a saved history holds the final text of each message, so edits are
not replayed, and the air-alert level of the time is not known; one level is
assumed for the whole period.
"""

from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timedelta

from .processor import ChatProcessor, IncomingMessage
from .rules import Config
from .situation import Situation

# How soon after posting the gateway is assumed to see a message, and how
# often the clock is advanced between messages.
SEEN_AFTER = timedelta(seconds=2)
TICK = timedelta(seconds=30)


def replay(config: Config, histories: dict[str, Iterable[dict]], alert_level: str | None) -> list[dict]:
    situation = Situation(config.situation)
    processors = {name: ChatProcessor(config.chats[name]) for name in histories}
    stream = sorted(
        ((datetime.fromisoformat(message["date"]), name, message) for name, messages in histories.items() for message in messages),
        key=lambda item: (item[0], item[1], item[2]["id"]),
    )
    decisions: list[dict] = []
    if not stream:
        return decisions
    clock = stream[0][0]
    situation.set_alert_level(alert_level, clock)
    for when, name, message in stream:
        now = when + SEEN_AFTER
        while clock + TICK < now and situation.state(clock) != "idle":
            clock += TICK
            decisions += situation.tick(clock)
        clock = now
        incoming = IncomingMessage(message["id"], when, message.get("text") or "", reply_to=message.get("reply_to"))
        decisions += situation.feed(name, processors[name].handle(incoming, now), now)
    return decisions


def format_replay(decisions: list[dict], width: int = 90) -> str:
    lines = []
    episodes = 0
    peaks: Counter = Counter()
    changes: Counter = Counter()
    for decision in decisions:
        changes[(decision["change"], decision["severity"])] += 1
        if decision["change"] == "clear":
            episodes += 1
            peaks[decision["peak"]] += 1
        text = " ".join((decision.get("text") or "").split())[:width]
        source = decision.get("source") or "-"
        lines.append(
            f"{decision['at'][:10]} {decision['at'][11:19]}  {decision['change']:<7} {decision['severity']:<10} "
            f"{decision['reason']:<17} {source:<16} {text}"
        )
        if decision["change"] == "clear":
            lines.append("")
    summary = [f"episodes ended: {episodes}; highest severity reached: " + ", ".join(f"{k} {v}" for k, v in sorted(peaks.items()))]
    summary += [f"{change:<8}{severity:<11}{count}" for (change, severity), count in sorted(changes.items())]
    return "\n".join(lines + summary) + "\n"
