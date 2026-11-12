"""Telegram side of the gateway: polling of each chat and the update stream.

Polling is the fast path (a channel's history answers within the interval);
the update stream arrives 10-20 s late for large channels, but it is the only
source of edits and it covers the time polling is slowed down.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone

from telethon import TelegramClient, errors, events, utils

from .processor import ChatProcessor, IncomingMessage

log = logging.getLogger(__name__)

MAX_POLL_INTERVAL = 60.0
BASELINE_MESSAGES = 20
POLL_BATCH = 50

# Errors that mean the session no longer gives access to the account.
LOGIN_LOST = (errors.UnauthorizedError, errors.AuthKeyError)


class LoginLost(Exception):
    """The session was terminated or is not authorised; a new login is needed."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def to_incoming(message) -> IncomingMessage | None:
    """Convert a Telethon message; service messages (pins, joins) give None.

    `message.message` is the plain text of the message itself: no formatting
    markup and no text of the message it replies to. The reply is kept as an
    id, so that a consumer can follow a chain of replies.
    """
    if getattr(message, "action", None) is not None or message.date is None:
        return None
    return IncomingMessage(
        id=message.id,
        date=message.date,
        text=message.message or "",
        edit_date=message.edit_date,
        reply_to=getattr(getattr(message, "reply_to", None), "reply_to_msg_id", None),
    )


class ChatPoller:
    """Polls one chat and feeds its processor."""

    def __init__(
        self,
        client: TelegramClient,
        entity,
        processor: ChatProcessor,
        publish: Callable[[str, str, dict], bool],
        now: Callable[[], datetime] = _now,
        observe: Callable[[str, list, datetime], None] | None = None,
    ):
        self._client = client
        self._entity = entity
        self._processor = processor
        self._publish = publish
        self._now = now
        self._observe = observe
        self.interval = processor.chat.poll_interval

    @property
    def name(self) -> str:
        return self._processor.chat.name

    async def baseline(self) -> None:
        messages = await self._client.get_messages(self._entity, limit=BASELINE_MESSAGES)
        self._processor.baseline(message.id for message in messages)
        log.info("%s: listening after message %s, every %g s", self.name, self._processor.last_id, self.interval)

    def handle(self, message, source: str) -> None:
        incoming = to_incoming(message)
        if incoming is None:
            return
        now = self._now()
        publications = self._processor.handle(incoming, now)
        for publication in publications:
            self._publish(self.name, publication.kind, publication.payload)
            log.info(
                "%s: %s id=%s%s via %s, %.1f s after it was posted",
                self.name,
                publication.payload.get("kind", "message"),
                incoming.id,
                " (edited)" if publication.payload["edited"] else "",
                source,
                (now - incoming.date).total_seconds(),
            )
        if publications and self._observe is not None:
            self._observe(self.name, publications, now)

    async def poll_once(self) -> float:
        """Fetch what is new and return the delay before the next poll."""
        try:
            if self._processor.last_id:
                messages = await self._client.get_messages(
                    self._entity, min_id=self._processor.last_id, limit=POLL_BATCH, reverse=True
                )
            else:
                # An empty chat at start: there is no id to continue from yet.
                messages = reversed(await self._client.get_messages(self._entity, limit=BASELINE_MESSAGES))
            for message in messages:
                self.handle(message, "poll")
        except errors.FloodWaitError as error:
            self.interval = min(self.interval * 2, MAX_POLL_INTERVAL)
            log.warning(
                "%s: Telegram asked to wait %s s (FLOOD_WAIT); polling every %g s from now on",
                self.name,
                error.seconds,
                self.interval,
            )
            return error.seconds + self.interval
        except LOGIN_LOST as error:
            raise LoginLost(str(error)) from error
        except (ConnectionError, OSError, asyncio.TimeoutError, errors.RPCError) as error:
            log.warning("%s: poll failed, will retry: %r", self.name, error)
        return self.interval

    async def run(self) -> None:
        while True:
            await asyncio.sleep(await self.poll_once())


async def resolve_chat(client: TelegramClient, name: str):
    """A chat is named by its public username or, for others, by its numeric id."""
    target = int(name) if name.lstrip("-").isdigit() else name
    try:
        return await client.get_input_entity(target)
    except LOGIN_LOST as error:
        raise LoginLost(str(error)) from error
    except (ValueError, errors.RPCError) as error:
        raise RuntimeError(f"chat '{name}' cannot be found by this account: {error}") from error


async def listen(
    client: TelegramClient,
    processors: dict[str, ChatProcessor],
    publish: Callable[[str, str, dict], bool],
    observe: Callable[[str, list, datetime], None] | None = None,
) -> None:
    """Run until the connection is closed for good; raises LoginLost when the session dies.

    `observe` gets everything published for one message, as a list.
    """
    pollers: dict[int, ChatPoller] = {}
    for name, processor in processors.items():
        entity = await resolve_chat(client, name)
        poller = ChatPoller(client, entity, processor, publish, observe=observe)
        try:
            await poller.baseline()
        except LOGIN_LOST as error:
            raise LoginLost(str(error)) from error
        pollers[utils.get_peer_id(entity)] = poller

    async def on_update(event) -> None:
        poller = pollers.get(event.chat_id)
        if poller is not None:
            poller.handle(event.message, "updates")

    chats = list(pollers)
    client.add_event_handler(on_update, events.NewMessage(chats=chats))
    client.add_event_handler(on_update, events.MessageEdited(chats=chats))

    async def until_disconnected() -> None:
        try:
            await client.disconnected
        except LOGIN_LOST as error:
            raise LoginLost(str(error)) from error

    tasks = [asyncio.create_task(poller.run(), name=f"poll-{poller.name}") for poller in pollers.values()]
    tasks.append(asyncio.create_task(until_disconnected(), name="connection"))
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        client.remove_event_handler(on_update)
