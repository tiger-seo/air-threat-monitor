import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from telethon import errors

from telegram_mqtt_gateway.processor import ChatProcessor
from telegram_mqtt_gateway.rules import load_config
from telegram_mqtt_gateway.telegram import ChatPoller, LoginLost, to_incoming

T0 = datetime(2026, 11, 10, 19, 23, 7, tzinfo=timezone.utc)
THREAT = "☄️ Загроза застосування балістичного озброєння з Брянська."


def tg_message(message_id, text, date=T0, edit_date=None, action=None):
    return SimpleNamespace(id=message_id, message=text, date=date, edit_date=edit_date, action=action)


class FakeClient:
    """Answers get_messages from a list; an exception in the queue is raised once."""

    def __init__(self, history):
        self.history = list(history)
        self.failures = []
        self.calls = []

    async def get_messages(self, entity, limit=None, min_id=0, reverse=False):
        self.calls.append({"limit": limit, "min_id": min_id, "reverse": reverse})
        if self.failures:
            raise self.failures.pop(0)
        found = sorted((m for m in self.history if m.id > min_id), key=lambda m: m.id)
        return found[:limit] if reverse else found[::-1][:limit]


@pytest.fixture
def setup():
    chat = load_config(Path(__file__).parent.parent / "rules.example.yaml").chats["kpszsu"]
    client = FakeClient([tg_message(94907, "старе")])
    published = []
    poller = ChatPoller(
        client,
        "entity",
        ChatProcessor(chat),
        lambda chat, kind, payload: published.append((chat, kind, payload)) or True,
        now=lambda: T0 + timedelta(seconds=2),
    )
    asyncio.run(poller.baseline())
    return client, poller, published


def test_quote_of_a_reply_is_not_part_of_the_text():
    # Telethon keeps the replied-to message apart (reply_to); only the
    # message's own text reaches the rules.
    reply = tg_message(94910, "🛵 БпЛА курсом на Київ.")
    reply.reply_to = SimpleNamespace(reply_to_msg_id=94908, quote_text=THREAT)
    incoming = to_incoming(reply)
    assert incoming.text == "🛵 БпЛА курсом на Київ."
    assert incoming.reply_to == 94908
    assert to_incoming(tg_message(94911, "🛵 БпЛА")).reply_to is None


def test_service_message_is_skipped():
    assert to_incoming(tg_message(94910, None, action=object())) is None


def test_poll_publishes_only_messages_after_the_baseline(setup):
    client, poller, published = setup
    assert asyncio.run(poller.poll_once()) == 3.0
    assert published == []
    client.history.append(tg_message(94908, THREAT))
    asyncio.run(poller.poll_once())
    assert [(chat, kind) for chat, kind, _ in published] == [("kpszsu", "message"), ("kpszsu", "event")]
    assert client.calls[-1] == {"limit": 50, "min_id": 94907, "reverse": True}
    asyncio.run(poller.poll_once())
    assert client.calls[-1]["min_id"] == 94908
    assert len(published) == 2


def test_message_seen_by_poll_and_updates_is_published_once(setup):
    client, poller, published = setup
    message = tg_message(94908, THREAT)
    poller.handle(message, "updates")
    client.history.append(message)
    asyncio.run(poller.poll_once())
    assert len(published) == 2


def test_flood_wait_waits_and_doubles_the_interval_up_to_a_minute(setup):
    client, poller, _ = setup
    client.failures.append(errors.FloodWaitError(request=None, capture=30))
    assert asyncio.run(poller.poll_once()) == 30 + 6.0
    assert poller.interval == 6.0
    for _ in range(6):
        client.failures.append(errors.FloodWaitError(request=None, capture=1))
        asyncio.run(poller.poll_once())
    assert poller.interval == 60.0


def test_network_error_keeps_polling(setup):
    client, poller, _ = setup
    client.failures.append(ConnectionError("down"))
    assert asyncio.run(poller.poll_once()) == 3.0


@pytest.mark.parametrize(
    "error",
    [errors.AuthKeyUnregisteredError(request=None), errors.SessionRevokedError(request=None)],
)
def test_terminated_session_stops_polling(setup, error):
    client, poller, _ = setup
    client.failures.append(error)
    with pytest.raises(LoginLost):
        asyncio.run(poller.poll_once())
