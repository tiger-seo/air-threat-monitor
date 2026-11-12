"""Review of a chat's rules against its saved history.

A channel's wordings drift, and a rule that stopped matching fails silently.
The review shows what each rule caught, so a false match can be seen, and
which messages contain the chat's watch words but matched nothing, so a new
wording can be seen.
"""

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .rules import ChatConfig
from .text import clean_text


@dataclass
class Review:
    chat: str
    total: int = 0
    first_date: str | None = None
    last_date: str | None = None
    # Per kind: the texts of the messages that gave an event, with counts.
    kinds: dict[str, Counter] = field(default_factory=dict)
    # Messages with a watch word and no event.
    suspects: Counter = field(default_factory=Counter)


def read_history(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def review_messages(messages: Iterable[dict], chat: ChatConfig) -> Review:
    review = Review(chat=chat.name, kinds={rule.kind: Counter() for rule in chat.rules})
    for message in messages:
        review.total += 1
        date = message.get("date")
        if date:
            review.first_date = min(review.first_date or date, date)
            review.last_date = max(review.last_date or date, date)
        text = clean_text(message.get("text") or "")
        one_line = " / ".join(text.split("\n"))
        matches = chat.match(text)
        for kind in {match.kind for match in matches}:
            review.kinds[kind][one_line] += 1
        if not matches and chat.watch is not None and chat.watch.search(text):
            review.suspects[one_line] += 1
    return review


def format_review(review: Review, limit: int = 20, width: int = 140) -> str:
    def rows(counter: Counter) -> list[str]:
        lines = [f"{count:5}  {text[:width]}" for text, count in counter.most_common(limit)]
        if len(counter) > limit:
            lines.append(f"       … and {len(counter) - limit} more wordings")
        return lines

    period = f"{(review.first_date or '?')[:10]} .. {(review.last_date or '?')[:10]}"
    lines = [f"{review.chat}: {review.total} messages, {period}", ""]
    for kind, texts in review.kinds.items():
        lines.append(f"## {kind}: {sum(texts.values())} messages, {len(texts)} wordings")
        lines += rows(texts) or ["       no matches: has the wording changed?"]
        lines.append("")
    lines.append(f"## watch words, no rule: {sum(review.suspects.values())} messages, {len(review.suspects)} wordings")
    lines += rows(review.suspects)
    return "\n".join(lines) + "\n"
