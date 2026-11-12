"""Command line: run the gateway, log in from a terminal, check a rules file, save a chat's history."""

import argparse
import asyncio
import getpass
import json
import logging
import platform
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .rules import ConfigError, load_config
from .settings import Settings, SettingsError

log = logging.getLogger("telegram_mqtt_gateway")

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_LOGIN_NEEDED = 2

SITUATION_TOPIC = "situation/ballistic"
SITUATION_TICK = 5  # seconds between checks of the decision module's timers


def _client(settings: Settings, flood_sleep_threshold: int = 0):
    from telethon import TelegramClient

    settings.session.parent.mkdir(parents=True, exist_ok=True)
    return TelegramClient(
        str(settings.session),
        settings.api_id,
        settings.api_hash,
        # While listening, every rate limit must reach the poller, which slows
        # down and logs it; a one-off command may let Telethon sit it out.
        flood_sleep_threshold=flood_sleep_threshold,
        # Shown in Telegram under Settings → Devices, to recognise the session.
        device_model="telegram-mqtt-gateway",
        system_version=platform.node() or platform.system(),
        app_version=__version__,
    )


async def run(settings: Settings, dry_run: bool) -> int:
    from .mqtt import DryRunPublisher, MqttPublisher
    from .processor import ChatProcessor
    from .situation import Situation
    from .telegram import LoginLost, listen

    config = load_config(settings.rules)
    processors = {
        name: ChatProcessor(chat, stale_after=timedelta(seconds=settings.stale_after))
        for name, chat in config.chats.items()
    }
    if dry_run:
        publisher = DryRunPublisher(settings.topic_prefix)
    else:
        publisher = MqttPublisher(
            settings.mqtt_host,
            settings.mqtt_port,
            settings.mqtt_username,
            settings.mqtt_password,
            settings.topic_prefix,
        )
    client = _client(settings)
    publisher.start()

    # The decision module, when the rules file describes the home.
    situation = Situation(config.situation) if config.situation is not None else None
    ticker = None

    def utcnow() -> datetime:
        return datetime.now(timezone.utc)

    def decide(decisions: list[dict]) -> None:
        for decision in decisions:
            publisher.set_state(SITUATION_TOPIC, decision)
            publisher.publish_event(f"{SITUATION_TOPIC}/event", decision)
            log.info(
                "situation: %s %s (%s%s)",
                decision["change"],
                decision["severity"],
                decision["reason"],
                f", {decision['source']} id={decision['id']}" if decision.get("source") else "",
            )

    def observe(chat: str, publications: list, now: datetime) -> None:
        decide(situation.feed(chat, publications, now))

    async def tick() -> None:
        while True:
            await asyncio.sleep(SITUATION_TICK)
            decide(situation.tick(utcnow()))

    if situation is not None:
        # Overwrites whatever a previous run left retained: after a restart
        # nothing is known about a threat in progress.
        publisher.set_state(SITUATION_TOPIC, situation.snapshot(utcnow()))
        if settings.alert_level_topic:
            loop = asyncio.get_running_loop()

            def on_level(payload: str) -> None:
                level = payload.strip().lower()
                log.info("air-alert level: %s", level)
                decisions = situation.set_alert_level(level, utcnow())
                decide(decisions)
                if not decisions:
                    # No change of severity, but the retained state shows the level.
                    publisher.set_state(SITUATION_TOPIC, situation.snapshot(utcnow()))

            publisher.subscribe(settings.alert_level_topic, lambda payload: loop.call_soon_threadsafe(on_level, payload))
        else:
            log.warning("TMG_ALERT_LEVEL_TOPIC is not set: every ballistic threat is treated as under an alert")

    try:
        await client.connect()
        if not await client.is_user_authorized():
            raise LoginLost("the session is missing or not authorised")
        publisher.set_login("ok")
        if situation is not None:
            ticker = asyncio.create_task(tick(), name="situation-tick")
        await listen(client, processors, publisher.publish, observe if situation is not None else None)
        log.warning("the Telegram connection was closed")
        return EXIT_OK
    except LoginLost as error:
        publisher.set_login("needed")
        log.error("login needed: %s", error)
        return EXIT_LOGIN_NEEDED
    finally:
        if ticker is not None:
            ticker.cancel()
        await client.disconnect()
        publisher.stop()


async def login(settings: Settings) -> int:
    """Create the session by QR code, for running outside Home Assistant."""
    import qrcode
    from telethon import errors

    client = _client(settings)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            qr = await client.qr_login()
            while True:
                code = qrcode.QRCode(border=2)
                code.add_data(qr.url)
                code.print_ascii(invert=True)
                print("Telegram → Settings → Devices → Link Desktop Device, then scan the code.", flush=True)
                try:
                    await qr.wait(timeout=25)
                    break
                except asyncio.TimeoutError:
                    await qr.recreate()
                except errors.SessionPasswordNeededError:
                    await client.sign_in(password=getpass.getpass("Two-step verification password: "))
                    break
        me = await client.get_me()
        print(f"Logged in as {me.first_name} (id {me.id}); session: {settings.session}.session")
        return EXIT_OK
    finally:
        await client.disconnect()


async def history(settings: Settings, chat: str, days: float, out: Path) -> int:
    """Save a chat's messages of the last days as JSON lines, oldest first.

    The text is saved raw, with emoji: the file is material for studying the
    chat's wordings and for tests, not something to publish.
    """
    from .telegram import LoginLost, resolve_chat, to_incoming

    client = _client(settings, flood_sleep_threshold=300)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            raise LoginLost("the session is missing or not authorised")
        entity = await resolve_chat(client, chat)
        since = datetime.now(timezone.utc) - timedelta(days=days)
        out.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with out.open("w", encoding="utf-8", newline="\n") as file:
            # One request gives 100 messages; a second between requests keeps
            # a month of a busy channel well under Telegram's limits.
            async for message in client.iter_messages(entity, offset_date=since, reverse=True, wait_time=1):
                incoming = to_incoming(message)
                if incoming is None:
                    continue
                record = {
                    "id": incoming.id,
                    "date": incoming.date.isoformat(),
                    "edit_date": incoming.edit_date.isoformat() if incoming.edit_date else None,
                    "reply_to": incoming.reply_to,
                    "text": incoming.text,
                }
                file.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
                if count % 1000 == 0:
                    log.info("%s: %s messages, up to %s", chat, count, incoming.date.isoformat())
        print(f"{chat}: {count} messages since {since:%Y-%m-%d %H:%M} UTC saved to {out}")
        return EXIT_OK
    except LoginLost as error:
        log.error("login needed: %s", error)
        return EXIT_LOGIN_NEEDED
    finally:
        await client.disconnect()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="telegram_mqtt_gateway", description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="log Telethon and MQTT details too")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run", help="listen to the chats and publish to MQTT")
    run_parser.add_argument("--dry-run", action="store_true", help="print publications instead of sending them")
    commands.add_parser("login", help="create the Telegram session by QR code in this terminal")
    check = commands.add_parser("check-rules", help="validate a rules file")
    check.add_argument("path")
    history_parser = commands.add_parser("history", help="save a chat's recent messages to a JSON lines file")
    history_parser.add_argument("chat", help="public username or numeric id")
    history_parser.add_argument("--days", type=float, default=30)
    history_parser.add_argument("--out", type=Path, help="default: data/history/<chat>.jsonl")
    review_parser = commands.add_parser("review", help="check a chat's rules against its saved history")
    review_parser.add_argument("chat")
    review_parser.add_argument("--rules", type=Path, default=Path("rules.example.yaml"))
    review_parser.add_argument("--file", type=Path, help="default: data/history/<chat>.jsonl")
    review_parser.add_argument("--limit", type=int, default=20, help="wordings shown per section")
    replay_parser = commands.add_parser("replay", help="show the decisions the saved histories would have caused")
    replay_parser.add_argument("--rules", type=Path, default=Path("rules.example.yaml"))
    replay_parser.add_argument("--dir", type=Path, default=Path("data/history"), help="folder with <chat>.jsonl files")
    replay_parser.add_argument(
        "--alert-level",
        choices=["unknown", "none", "yellow", "red"],
        default="unknown",
        help="air-alert level assumed for the whole period",
    )
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not args.verbose:
        logging.getLogger("telethon").setLevel(logging.WARNING)

    try:
        if args.command == "check-rules":
            config = load_config(args.path)
            for chat in config.chats.values():
                print(f"{chat.name}: every {chat.poll_interval:g} s, {len(chat.rules)} rules")
            return EXIT_OK
        if args.command == "review":
            from .review import format_review, read_history, review_messages

            config = load_config(args.rules)
            if args.chat not in config.chats:
                raise ConfigError(f"{args.rules}: no chat '{args.chat}'")
            messages = read_history(args.file or Path("data/history") / f"{args.chat}.jsonl")
            print(format_review(review_messages(messages, config.chats[args.chat]), args.limit), end="")
            return EXIT_OK
        if args.command == "replay":
            from .replay import format_replay, replay
            from .review import read_history

            config = load_config(args.rules)
            if config.situation is None:
                raise ConfigError(f"{args.rules}: no 'situation' section")
            histories = {
                name: read_history(args.dir / f"{name}.jsonl")
                for name in config.situation.sources
                if (args.dir / f"{name}.jsonl").exists()
            }
            level = None if args.alert_level == "unknown" else args.alert_level
            print(format_replay(replay(config, histories, level)), end="")
            return EXIT_OK
        settings = Settings.from_env()
        if args.command == "login":
            return asyncio.run(login(settings))
        if args.command == "history":
            out = args.out or Path("data/history") / f"{args.chat}.jsonl"
            return asyncio.run(history(settings, args.chat, args.days, out))
        return asyncio.run(run(settings, args.dry_run))
    except (ConfigError, SettingsError) as error:
        log.error("%s", error)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
