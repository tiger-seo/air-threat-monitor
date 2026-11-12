from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from air_threat_monitor.processor import ChatProcessor, IncomingMessage
from air_threat_monitor.rules import load_config

T0 = datetime(2026, 11, 10, 19, 23, 7, tzinfo=timezone.utc)
THREAT = "☄️ Загроза застосування балістичного озброєння з Брянська."
CLEAR = "📢 Відбій загрози застосування  балістичного озброєння."
UAV = "🛵 БпЛА курсом на Київ з півночі."


def seconds(value):
    return timedelta(seconds=value)


@pytest.fixture
def processor():
    chat = load_config(Path(__file__).parent.parent / "rules.example.yaml").chats["kpszsu"]
    processor = ChatProcessor(chat)
    processor.baseline([94900, 94905, 94907])
    return processor


def kinds(publications):
    return [(p.kind, p.payload.get("kind")) for p in publications]


def test_new_threat_gives_message_and_event(processor):
    publications = processor.handle(IncomingMessage(94908, T0, THREAT), T0 + seconds(2))
    assert [p.kind for p in publications] == ["message", "event"]
    assert publications[0].payload == {
        "chat": "kpszsu",
        "id": 94908,
        "date": "2026-11-10T19:23:07Z",
        "text": "Загроза застосування балістичного озброєння з Брянська.",
        "reply_to": None,
        "edited": False,
    }
    assert publications[1].payload == {
        "kind": "ballistic_threat",
        "chat": "kpszsu",
        "id": 94908,
        "date": "2026-11-10T19:23:07Z",
        "text": "Загроза застосування балістичного озброєння з Брянська.",
        "match": "Загроза застосування балістичного озброєння з Брянська",
        "fields": {"from": "Брянська"},
        "reply_to": None,
        "edited": False,
    }


def test_reply_carries_the_id_of_the_message_it_answers(processor):
    processor.handle(IncomingMessage(94908, T0, THREAT), T0)
    reply = IncomingMessage(94909, T0 + seconds(60), "🚀Київ!", reply_to=94908)
    publications = processor.handle(reply, T0 + seconds(61))
    assert [(p.kind, p.payload["text"], p.payload["reply_to"]) for p in publications] == [("message", "Київ!", 94908)]
    followup = IncomingMessage(94910, T0 + seconds(70), "🚀Балістика на Бровари/Київ!", reply_to=94909)
    event = processor.handle(followup, T0 + seconds(71))[1]
    assert (event.payload["kind"], event.payload["reply_to"]) == ("ballistic_missile", 94909)


def test_first_sight_of_a_message_with_an_edit_date_is_not_an_edit(processor):
    # All 9473 messages of the 30-day history carried an edit date.
    message = IncomingMessage(94908, T0, THREAT, edit_date=T0 + seconds(1))
    publications = processor.handle(message, T0 + seconds(2))
    assert [p.payload["edited"] for p in publications] == [False, False]


def test_message_without_match_gives_only_message(processor):
    assert kinds(processor.handle(IncomingMessage(94908, T0, UAV), T0)) == [("message", None)]


def test_media_only_message_is_published_with_empty_text(processor):
    publications = processor.handle(IncomingMessage(94908, T0, ""), T0)
    assert [p.payload["text"] for p in publications] == [""]


def test_baseline_tracks_the_newest_message(processor):
    assert processor.last_id == 94907
    processor.handle(IncomingMessage(94908, T0, UAV), T0)
    assert processor.last_id == 94908


def test_messages_from_before_the_start_give_nothing(processor):
    assert processor.handle(IncomingMessage(94907, T0, THREAT), T0) == []
    assert processor.handle(IncomingMessage(94901, T0, THREAT), T0) == []


def test_same_message_from_poll_and_updates_is_published_once(processor):
    message = IncomingMessage(94908, T0, THREAT)
    assert len(processor.handle(message, T0 + seconds(2))) == 2
    assert processor.handle(message, T0 + seconds(8)) == []


def test_stale_message_gives_no_event(processor):
    publications = processor.handle(IncomingMessage(94908, T0, THREAT), T0 + seconds(121))
    assert kinds(publications) == [("message", None)]


def test_message_at_the_stale_limit_still_gives_an_event(processor):
    publications = processor.handle(IncomingMessage(94908, T0, THREAT), T0 + seconds(120))
    assert kinds(publications) == [("message", None), ("event", "ballistic_threat")]


# --- Edits -------------------------------------------------------------------


def test_typo_fix_does_not_repeat_the_event(processor):
    processor.handle(IncomingMessage(94908, T0, "☄️ Загроза застосування балістичного озброєння з Брянска."), T0)
    edit = IncomingMessage(94908, T0, THREAT, edit_date=T0 + seconds(30))
    publications = processor.handle(edit, T0 + seconds(31))
    assert kinds(publications) == [("message", None)]
    assert publications[0].payload["edited"] is True
    assert publications[0].payload["text"].endswith("з Брянська.")


def test_edit_that_adds_a_match_gives_an_event(processor):
    processor.handle(IncomingMessage(94908, T0, UAV), T0)
    edit = IncomingMessage(94908, T0, UAV + "\n" + THREAT, edit_date=T0 + seconds(30))
    publications = processor.handle(edit, T0 + seconds(31))
    assert kinds(publications) == [("message", None), ("event", "ballistic_threat")]
    assert publications[1].payload["edited"] is True
    assert publications[1].payload["date"] == "2026-11-10T19:23:07Z"


def test_edit_that_adds_a_second_threat_gives_only_the_new_one(processor):
    processor.handle(IncomingMessage(94908, T0, THREAT), T0)
    second = "☄️ Загроза застосування балістичного озброєння з південного сходу."
    edit = IncomingMessage(94908, T0, THREAT + "\n" + second, edit_date=T0 + seconds(30))
    events = [p for p in processor.handle(edit, T0 + seconds(31)) if p.kind == "event"]
    assert [event.payload["fields"] for event in events] == [{"from": "південного сходу"}]


def test_edit_is_judged_stale_by_the_time_of_the_edit(processor):
    processor.handle(IncomingMessage(94908, T0, UAV), T0)
    edit = IncomingMessage(94908, T0, UAV + "\n" + THREAT, edit_date=T0 + seconds(600))
    assert kinds(processor.handle(edit, T0 + seconds(602))) == [("message", None), ("event", "ballistic_threat")]
    late = IncomingMessage(94908, T0, UAV + "\n" + THREAT + "\n" + CLEAR, edit_date=T0 + seconds(700))
    assert kinds(processor.handle(late, T0 + seconds(900))) == [("message", None)]


def test_match_missed_as_stale_is_not_sent_by_a_later_edit(processor):
    processor.handle(IncomingMessage(94908, T0, THREAT), T0 + seconds(300))
    edit = IncomingMessage(94908, T0, THREAT + " Уточнення.", edit_date=T0 + seconds(310))
    assert kinds(processor.handle(edit, T0 + seconds(311))) == [("message", None)]


def test_removed_and_restored_match_is_not_sent_again(processor):
    processor.handle(IncomingMessage(94908, T0, THREAT), T0)
    processor.handle(IncomingMessage(94908, T0, UAV, edit_date=T0 + seconds(10)), T0 + seconds(11))
    restored = IncomingMessage(94908, T0, THREAT, edit_date=T0 + seconds(20))
    assert kinds(processor.handle(restored, T0 + seconds(21))) == [("message", None)]


def test_reaction_update_with_unchanged_text_gives_nothing(processor):
    processor.handle(IncomingMessage(94908, T0, THREAT), T0)
    assert processor.handle(IncomingMessage(94908, T0, THREAT, edit_date=T0 + seconds(5)), T0 + seconds(6)) == []


def test_older_version_arriving_late_is_ignored(processor):
    processor.handle(IncomingMessage(94908, T0, UAV), T0)
    processor.handle(IncomingMessage(94908, T0, UAV + " Оновлено.", edit_date=T0 + seconds(20)), T0 + seconds(21))
    older = IncomingMessage(94908, T0, UAV + " Старе.", edit_date=T0 + seconds(10))
    assert processor.handle(older, T0 + seconds(22)) == []


def test_edit_of_a_message_from_before_the_start_gives_no_event(processor):
    edit = IncomingMessage(94905, T0 - seconds(600), THREAT, edit_date=T0)
    publications = processor.handle(edit, T0 + seconds(1))
    assert kinds(publications) == [("message", None)]
    assert publications[0].payload["edited"] is True
    assert processor.last_id == 94907


def test_forgotten_messages_are_treated_as_old():
    chat = load_config(Path(__file__).parent.parent / "rules.example.yaml").chats["kpszsu"]
    processor = ChatProcessor(chat, remember=2)
    for message_id in (1, 2, 3):
        processor.handle(IncomingMessage(message_id, T0, UAV), T0)
    assert processor.handle(IncomingMessage(1, T0, THREAT), T0) == []
    edit = IncomingMessage(1, T0, THREAT, edit_date=T0 + seconds(5))
    assert kinds(processor.handle(edit, T0 + seconds(6))) == [("message", None)]
