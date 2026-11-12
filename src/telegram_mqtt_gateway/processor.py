"""Turns messages of one chat into MQTT publications.

Holds what the gateway remembers about a chat: which messages it has seen and
which events it has already sent for them. No network and no clock of its
own, so the behaviour is testable message by message.
"""

from collections import Counter, OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .rules import ChatConfig, RuleMatch
from .text import clean_text

DEFAULT_STALE_AFTER = timedelta(seconds=120)
DEFAULT_REMEMBER = 500


@dataclass(frozen=True)
class IncomingMessage:
    id: int
    date: datetime
    text: str
    edit_date: datetime | None = None
    reply_to: int | None = None  # id of the message this one replies to


@dataclass(frozen=True)
class Publication:
    kind: str  # "message" or "event": the last level of the topic
    payload: dict


@dataclass
class _Seen:
    text: str
    edit_date: datetime | None
    sent: Counter  # events already sent for this message, per rule kind


class ChatProcessor:
    def __init__(
        self,
        chat: ChatConfig,
        stale_after: timedelta = DEFAULT_STALE_AFTER,
        remember: int = DEFAULT_REMEMBER,
    ):
        self.chat = chat
        self._stale_after = stale_after
        self._remember = remember
        self._seen: OrderedDict[int, _Seen] = OrderedDict()
        # Messages with an id up to the floor were there before the gateway
        # started, or have been forgotten: they are never new.
        self._floor = 0
        self.last_id = 0

    def baseline(self, ids: Iterable[int]) -> None:
        """Mark the messages that exist at start as old: nothing is published for them."""
        for message_id in ids:
            self._floor = max(self._floor, message_id)
        self.last_id = max(self.last_id, self._floor)

    def handle(self, message: IncomingMessage, now: datetime) -> list[Publication]:
        text = clean_text(message.text or "")
        matches = self.chat.match(text)
        counts = Counter(match.kind for match in matches)
        self.last_id = max(self.last_id, message.id)
        seen = self._seen.get(message.id)

        if seen is None and message.id <= self._floor:
            # An edit of a message the gateway never processed. Its events, if
            # any, belong to the past, so only the message is published.
            if message.edit_date is None:
                return []
            self._store(message.id, _Seen(text, message.edit_date, counts))
            return [self._message(message, text, edited=True)]

        if seen is None:
            # Telegram sets an edit date on every channel post within seconds
            # (reactions, view counts), so it says nothing about a real edit:
            # a message seen for the first time is new.
            edited = False
            self._store(message.id, _Seen(text, message.edit_date, counts))
            publications = [self._message(message, text, edited)]
            if not self._is_stale(message.date, now):
                publications += [self._event(message, text, match, edited) for match in matches]
            return publications

        # Polling and the update stream both deliver a message, and Telegram
        # also reports reactions and view counts as edits: same text, no news.
        if text == seen.text:
            return []
        if message.edit_date is not None and seen.edit_date is not None and message.edit_date < seen.edit_date:
            return []

        publications = [self._message(message, text, edited=True)]
        # Only matches that the earlier versions did not have give events: a
        # corrected typo must not repeat an announcement, an added line must make one.
        fresh = not self._is_stale(message.edit_date or message.date, now)
        emitted: Counter = Counter()
        for match in matches:
            emitted[match.kind] += 1
            if emitted[match.kind] > seen.sent[match.kind] and fresh:
                publications.append(self._event(message, text, match, edited=True))
        seen.text = text
        seen.edit_date = message.edit_date or seen.edit_date
        seen.sent = seen.sent | counts
        return publications

    def _is_stale(self, when: datetime, now: datetime) -> bool:
        return now - when > self._stale_after

    def _store(self, message_id: int, seen: _Seen) -> None:
        self._seen[message_id] = seen
        while len(self._seen) > self._remember:
            forgotten, _ = self._seen.popitem(last=False)
            self._floor = max(self._floor, forgotten)

    def _message(self, message: IncomingMessage, text: str, edited: bool) -> Publication:
        return Publication(
            "message",
            {
                "chat": self.chat.name,
                "id": message.id,
                "date": _iso(message.date),
                "text": text,
                "reply_to": message.reply_to,
                "edited": edited,
            },
        )

    def _event(self, message: IncomingMessage, text: str, match: RuleMatch, edited: bool) -> Publication:
        return Publication(
            "event",
            {
                "kind": match.kind,
                "chat": self.chat.name,
                "id": message.id,
                "date": _iso(message.date),
                "text": text,
                "match": match.match,
                "fields": dict(match.fields),
                "reply_to": message.reply_to,
                "edited": edited,
            },
        )


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
