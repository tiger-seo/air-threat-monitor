"""The decision module, driven by the real wordings of both channels."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from air_threat_monitor.processor import ChatProcessor, IncomingMessage
from air_threat_monitor.rules import ConfigError, load_config, parse_config
from air_threat_monitor.situation import Interpreter, Situation

EXAMPLE = Path(__file__).parent.parent / "rules.example.yaml"
T0 = datetime(2026, 11, 11, 22, 53, 59, tzinfo=timezone.utc)
AF, MON = "kpszsu", "kyiv_m0nitoring"


class World:
    """Both channels, the gateway's processors and the decision module."""

    def __init__(self, alert_level="red"):
        config = load_config(EXAMPLE)
        self.situation = Situation(config.situation)
        self.processors = {name: ChatProcessor(chat) for name, chat in config.chats.items()}
        self.ids = {name: 1000 for name in config.chats}
        self.now = T0
        self.decisions = []
        self.decisions += self.situation.set_alert_level(alert_level, self.now)

    def post(self, chat, text, after=0, reply_to=None):
        """A message appears `after` seconds later; returns the decisions it caused."""
        self.now += timedelta(seconds=after)
        self.ids[chat] += 1
        message = IncomingMessage(self.ids[chat], self.now, text, reply_to=reply_to)
        publications = self.processors[chat].handle(message, self.now)
        new = self.situation.feed(chat, publications, self.now)
        self.decisions += new
        return new

    def wait(self, seconds):
        self.now += timedelta(seconds=seconds)
        new = self.situation.tick(self.now)
        self.decisions += new
        return new

    def last_id(self, chat):
        return self.ids[chat]


def brief(decisions):
    return [(d["change"], d["severity"], d["state"]) for d in decisions]


def test_threat_under_an_alert_is_attention():
    world = World(alert_level="red")
    decisions = world.post(AF, "☄️ Загроза застосування балістичного озброєння з Воронежа.")
    assert brief(decisions) == [("raised", "attention", "threat")]
    assert decisions[0]["reason"] == "ballistic_threat"
    assert decisions[0]["source"] == AF
    assert decisions[0]["text"] == "Загроза застосування балістичного озброєння з Воронежа."


def test_threat_without_an_alert_is_silent_until_kyiv_is_named():
    world = World(alert_level="none")
    assert world.post(AF, "☄️ Загроза застосування балістичного озброєння зі сходу.") == []
    assert world.post(AF, "🚀Балістика на Запоріжжя!", after=30) == []
    assert brief(world.post(AF, "🚀Балістика на Київ!", after=30)) == [("raised", "take_cover", "inbound_home")]


def test_unknown_alert_level_is_treated_as_an_alert():
    world = World(alert_level=None)
    assert brief(world.post(AF, "☄️ Загроза застосування балістичного озброєння")) == [
        ("raised", "attention", "threat")
    ]


def test_alert_starting_during_a_threat_raises_attention():
    world = World(alert_level="none")
    world.post(AF, "☄️ Загроза застосування балістичного озброєння з півночі.")
    decisions = world.situation.set_alert_level("red", world.now + timedelta(seconds=20))
    assert brief(decisions) == [("raised", "attention", "threat")]
    assert decisions[0]["reason"] == "alert_level"


def test_night_of_2026_11_12():
    """The chain that started this module, as both channels posted it."""
    world = World(alert_level="red")
    world.post(AF, "☄️ Загроза застосування балістичного озброєння з Воронежа.")
    world.post(MON, "Загроза з Воронежа.", after=50)
    world.post(AF, "🚀Балістична ракета через Сумщину!", after=69)
    world.post(AF, "🚀Балістика через Сумщину на Полтавщину!", after=22, reply_to=world.last_id(AF))
    world.post(AF, "🚀Балістика на Лубни!", after=14, reply_to=world.last_id(AF))
    world.post(AF, "🚀Пирятин!", after=52, reply_to=world.last_id(AF))
    assert brief(world.decisions) == [("raised", "attention", "threat")]

    region = world.post(AF, "🚀Балістична ракета через Полтавщину на південь Київщини!", after=57)
    assert brief(region) == []  # still "attention": the region is not the home
    assert world.situation.state(world.now) == "inbound_region"

    assert world.post(AF, "🚀Біла Церква!", after=31, reply_to=world.last_id(AF)) == []
    world.post(AF, "🚀Ще одна балістична ракета на Київщину!", after=40)

    kyiv = world.post(MON, "Балістика на Київ/передмістя.", after=8)
    assert brief(kyiv) == [("raised", "take_cover", "inbound_home")]
    assert kyiv[0]["source"] == MON

    # The official channel confirms 13 s later: no second announcement yet.
    assert world.post(AF, "🚀Балістика на Бровари/Київ!", after=13) == []
    # A bare place name counts because it answers a missile message.
    assert world.post(AF, "🚀Київ!", after=39, reply_to=world.last_id(AF)) == []

    withdrawn = world.post(MON, "Ні, Київ обходить все поки.", after=29)
    assert brief(withdrawn) == [("lowered", "attention", "threat")]

    again = world.post(AF, "🚀Балістика на Київ!", after=232)
    assert brief(again) == [("raised", "take_cover", "inbound_home")]

    descent = world.post(MON, "спуск на правий", after=42)
    assert brief(descent) == [("raised", "impact", "descent")]

    clean = world.post(MON, "чисто", after=52)
    assert brief(clean) == [("lowered", "attention", "threat")]


def test_official_all_clear_ends_the_threat_and_reports_the_peak():
    world = World()
    world.post(AF, "☄️ Загроза застосування балістичного озброєння з півночі.")
    world.post(AF, "🚀Балістичні ракети курсом на Київ.", after=85)
    decisions = world.post(AF, "📢 Відбій загрози застосування  балістичного озброєння.", after=1600)
    assert brief(decisions) == [("clear", "none", "idle")]
    assert decisions[0]["peak"] == "take_cover"
    assert decisions[0]["since"] == "2026-11-11T22:53:59Z"
    # The next threat starts from scratch.
    assert brief(world.post(AF, "☄️ Загроза застосування балістичного озброєння", after=600)) == [
        ("raised", "attention", "threat")
    ]


def test_clear_of_a_threat_that_was_never_announced_says_so():
    world = World(alert_level="none")
    world.post(AF, "☄️ Загроза застосування балістичного озброєння зі сходу.")
    decisions = world.post(AF, "📢 Відбій загрози застосування  балістичного озброєння.", after=900)
    assert brief(decisions) == [("clear", "none", "idle")]
    assert decisions[0]["peak"] == "none"


def test_unofficial_all_clear_only_withdraws_the_warning():
    world = World()
    world.post(AF, "☄️ Загроза застосування балістичного озброєння")
    world.post(MON, "Балістика на Київ/передмістя.", after=60)
    assert brief(world.wait(601)) == [("lowered", "attention", "threat")]  # the hold expired
    assert world.post(MON, "Відбій балістики.", after=10) == []
    assert world.situation.state(world.now) == "threat"
    world.post(MON, "Балістика на Київ/передмістя.", after=10)
    assert brief(world.post(MON, "відбій по балістиці", after=30)) == [("lowered", "attention", "threat")]


def test_take_cover_expires_without_new_messages():
    world = World()
    world.post(AF, "☄️ Загроза застосування балістичного озброєння")
    world.post(AF, "🚀Балістика на Київ", after=30)
    assert world.wait(599) == []
    assert brief(world.wait(2)) == [("lowered", "attention", "threat")]


def test_threat_without_all_clear_times_out():
    world = World()
    world.post(AF, "☄️ Загроза застосування балістичного озброєння")
    assert world.wait(3599) == []
    decisions = world.wait(2)
    assert brief(decisions) == [("clear", "none", "idle")]
    assert decisions[0]["reason"] == "timeout"


def test_more_missiles_at_kyiv_repeat_at_most_once_a_minute():
    world = World()
    world.post(AF, "☄️ Загроза застосування балістичного озброєння зі сходу.")
    world.post(AF, "🚀Балістична ракета на Київ!", after=50)
    assert world.post(MON, "2 ракети з брянська на київ", after=33) == []
    repeat = world.post(AF, "🚀Ще балістична ракета на Київ!", after=111)
    assert brief(repeat) == [("repeat", "take_cover", "inbound_home")]
    assert world.post(AF, "🚀Ще 2 ракети на Київ!", after=30) == []
    assert brief(world.post(AF, "🚀4 балістичні ракети на Київ!", after=35)) == [
        ("repeat", "take_cover", "inbound_home")
    ]


def test_count_only_message_of_the_kyiv_channel_means_kyiv():
    world = World()
    world.post(MON, "Загроза балістики з Брянська.")
    assert brief(world.post(MON, "2 ракети!", after=40)) == [("raised", "take_cover", "inbound_home")]


def test_missiles_elsewhere_keep_the_threat_but_not_the_severity():
    world = World()
    world.post(AF, "☄️ Загроза застосування балістичного озброєння")
    for text in ("🚀Балістика на Кам'янське/Дніпро.", "🚀Балістика на Запоріжжя!", "🚀 Ракета курсом на Кривий Ріг з півдня!"):
        assert world.post(AF, text, after=30) == []
    assert world.situation.state(world.now) == "threat"


def test_descent_outside_a_threat_is_ignored():
    world = World()
    assert world.post(MON, "спуск") == []
    assert world.post(MON, "чисто", after=10) == []
    assert world.situation.state(world.now) == "idle"


def test_unnamed_missile_outside_a_threat_is_ignored():
    world = World()
    assert world.post(AF, "🚀 Ракета на Запоріжжя з півночі.") == []
    assert world.post(AF, "🚀Ще ракети на Київ", after=10) == []
    assert world.situation.state(world.now) == "idle"


def test_missile_at_kyiv_with_no_threat_before_it_still_alarms():
    world = World(alert_level="none")
    assert brief(world.post(MON, "Балістика на Київ/передмістя.")) == [("raised", "take_cover", "inbound_home")]


def test_drone_reply_with_a_district_is_not_a_missile():
    # 2026-10-25: after a threat, replies in a drone thread named Kyiv districts.
    world = World()
    world.post(AF, "☄️ Загроза застосування балістичного озброєння з Курська")
    world.post(AF, "🏍 Реактивний БпЛА на Бровари", after=700)
    assert world.post(AF, "Нивки", after=60, reply_to=world.last_id(AF)) == []
    assert world.situation.state(world.now) == "threat"


def test_stale_message_changes_nothing():
    world = World()
    world.now += timedelta(seconds=300)
    old = IncomingMessage(5000, T0, "Балістика на Київ/передмістя.")
    publications = world.processors[MON].handle(old, world.now)
    assert world.situation.feed(MON, publications, world.now) == []
    assert world.situation.state(world.now) == "idle"


def test_snapshot_when_idle():
    world = World(alert_level="yellow")
    assert world.situation.snapshot(T0) == {
        "threat": "ballistic",
        "state": "idle",
        "severity": "none",
        "alert_level": "yellow",
        "since": None,
        "at": "2026-11-11T22:53:59Z",
    }


# --- Configuration ------------------------------------------------------------

CHATS = {"a": {"rules": [{"kind": "ballistic_threat", "pattern": "x"}]}}


def test_situation_is_optional():
    assert parse_config({"chats": CHATS}).situation is None


@pytest.mark.parametrize(
    ("situation", "message"),
    [
        ([], "situation: expected a mapping"),
        ({"home": "київ", "sources": {"a": {}}, "extra": 1}, "situation: unknown keys"),
        ({"sources": {"a": {}}}, "situation.home: expected a regular expression"),
        ({"home": "(", "sources": {"a": {}}}, "situation.home: invalid regular expression"),
        ({"home": "x*", "sources": {"a": {}}}, "situation.home: matches empty text"),
        ({"home": "київ"}, "situation.sources: expected a mapping"),
        ({"home": "київ", "sources": {"b": {}}}, "situation.sources.b: no such chat"),
        ({"home": "київ", "sources": {"a": {"trusted": True}}}, "situation.sources.a: expected only"),
        ({"home": "київ", "sources": {"a": {"official": "yes"}}}, "situation.sources.a.official"),
        ({"home": "київ", "sources": {"a": {}}, "inbound_hold": 0}, "situation.inbound_hold"),
    ],
)
def test_invalid_situation_names_the_place(situation, message):
    with pytest.raises(ConfigError) as error:
        parse_config({"chats": CHATS, "situation": situation})
    assert message in str(error.value)


def test_home_places_of_the_example():
    home = load_config(EXAMPLE).situation.home
    for text in ("на Київ", "над Києвом", "Ракета на КИїв!", "киів", "на Бровари/Київ", "Через Дарницю!", "на Бориспіль"):
        assert home.search(text), text
    for text in ("на Київщину", "південь Київщини", "на Харків", "Біла Церква!", "на Запоріжжя"):
        assert not home.search(text), text
    for text in ("Київського водосховища", "з Київської області", "на Подільськ", "Кам'янець-Подільського", "Мельницю-Подільську"):
        assert not home.search(text), text
    for text in ("на Поділ", "на Подолі"):
        assert home.search(text), text

    # The places the owner named on 2026-11-20: Obolon, the right bank, Vyshhorod, Minskyi massif.
    for text in ("на Оболонь", "Оболоні", "правий берег", "на правому березі", "Правобережжя", "над Вишгородом", "Мінський масив", "Мінського масиву", "на мінський"):
        assert home.search(text), text
    # Minsk in Belarus is not the Kyiv massif.
    for text in ("з Мінська", "Мінська область", "Мінськ"):
        assert not home.search(text), text


# --- Threats known by their course --------------------------------------------


class Courses(World):
    """The same channels, with the whole interpreter: ballistic and the courses."""

    def __init__(self, alert_level="red"):
        super().__init__(alert_level)
        self.situation = Interpreter(load_config(EXAMPLE).situation)
        self.situation.set_alert_level(alert_level, self.now)


def of(decisions, threat):
    return [(d["change"], d["severity"], d["state"]) for d in decisions if d["threat"] == threat]


def test_banderols_of_2026_11_13():
    """The Banderols that brought the red alert to Kyiv, as both channels posted them."""
    world = Courses()
    # Over other regions: nothing, however many.
    assert world.post(AF, "🚀 Полтавщина: Бандероль курсом на Нові Санжари.") == []
    region = world.post(AF, '🚀Баражуючі боєприпаси "Бандероль" в р-ні Ніжина курс південно-західний (Київщина)', after=60)
    assert of(region, "banderol") == [("raised", "attention", "inbound_region")]
    home = world.post(MON, "червона через бандеролі на вишгород/околиці", after=312)
    assert of(home, "banderol") == [("raised", "take_cover", "inbound_home")]
    assert home[0]["text"] == "червона через бандеролі на вишгород/околиці"
    # Another channel, six minutes later: one more "Ще бандероль на Київ".
    again = world.post(AF, '🚀Баражуючі боєприпаси "Бандероль" в р-ні Київського водосховища курсом на Київ з півночі.', after=345)
    assert of(again, "banderol") == [("repeat", "take_cover", "inbound_home")]
    # A region message neither lowers nor outlasts the warning for the home.
    assert world.post(AF, '🚀Баражуючі боєприпаси "Бандероль" в р-ні Куликівки (Чернігівщина) курс південно-західний (Київщина)', after=63) == []
    # Ten minutes after the last message about the home, the warning ends.
    assert of(world.wait(600 - 63 - 1), "banderol") == []
    assert of(world.wait(1), "banderol") == [("lowered", "none", "nearby")]
    westward = world.post(AF, '🚀Баражуючі боєприпаси "Бандероль" на заході Київщини на Житомирщину вектором руху Житомир.', after=420)
    assert of(westward, "banderol") == [("raised", "attention", "inbound_region")]
    world.wait(1800)
    clear = world.wait(1)
    assert of(clear, "banderol") == [("clear", "none", "idle")]
    assert clear[0]["peak"] == "take_cover"
    # The ballistic threat never moved.
    assert [d for d in world.decisions if d["threat"] == "ballistic"] == []


def test_a_reply_follows_the_same_weapon():
    world = Courses()
    world.post(AF, "🚀Київщина: «Бандероль» у напрямку Броварів.")
    first = world.last_id(AF)
    # "Вишгород!" answers the Banderol message: no rule knows it, the thread does.
    assert of(world.post(AF, "🚀Вишгород!", after=400, reply_to=first), "banderol") == []
    # A reply is the same Banderol: never "Ще бандероль".
    assert world.post(AF, "🚀Київщина: «Бандероль» у напрямку Броварів.", after=400, reply_to=first) == []
    # A reply in the thread saying nothing is tracked withdraws the warning.
    world.post(MON, "Бандероль на Бровари/Київ.", after=1)
    withdrawn = world.post(MON, "не фіксується", after=30, reply_to=world.last_id(MON))
    assert of(withdrawn, "banderol") == [("lowered", "none", "nearby")]


def test_nothing_tracked_outside_the_thread_is_not_about_the_course():
    world = Courses()
    world.post(MON, "Бандероль на Бровари/Київ.")
    assert of(world.post(MON, "чисто", after=30), "banderol") == []


def test_jet_drones_over_obolon_and_the_minskyi_massif_speak_without_the_city_name():
    # 2026-10-30, kpszsu: "Реактивний БпЛА на Мінський масив", no "Київ:" in front.
    assert of(Courses().post(AF, "🏍 Реактивний БпЛА на Мінський масив"), "jet_drone") == [
        ("raised", "take_cover", "inbound_home")
    ]
    assert of(Courses().post(AF, "🏍 Реактивний БпЛА на Оболонь"), "jet_drone") == [
        ("raised", "take_cover", "inbound_home")
    ]
    # Vyshhorod: a drone flying at it or through it toward the city keeps going south, over or
    # near the owner's home; one near it or leaving the city does not.
    for text in (
        "🏍 Реактивний БпЛА на Вишгород з півночі",
        "🏍 Київщина: реактивний БпЛА курсом на Вишгород",
        "🏍 Реактивний БпЛА над Київським водосховищем у напрямку Вишгорода",
        "🏍 Реактивний БпЛА через Вишгород у напрямку центру Києва.",
    ):
        assert of(Courses().post(AF, text), "jet_drone") == [("raised", "take_cover", "inbound_home")], text
    assert of(Courses().post(MON, "реактиви по морю в бік вишгорода/києва"), "jet_drone") == [
        ("raised", "take_cover", "inbound_home")
    ]
    for chat, text in (
        (AF, "🏍 Реактивний БпЛА з Києва через Вишгород на Димер"),
        (AF, "🏍 Реактивний БпЛА повз Вишгород на Димер"),
        (MON, "реактив біля вишгорода"),
    ):
        assert of(Courses().post(chat, text), "jet_drone") == [("raised", "attention", "inbound_region")], text


def test_jet_drones_speak_only_over_the_city():
    world = Courses()
    suburb = world.post(AF, "🏍 Реактивний БпЛА повз Вишневе курсом на Київ.")
    assert of(suburb, "jet_drone") == [("raised", "attention", "inbound_region")]
    city = world.post(AF, "🏍 Київ: реактивний БпЛА на Оболонь", after=120)
    assert of(city, "jet_drone") == [("raised", "take_cover", "inbound_home")]
    # Over another city, with the same words: nothing.
    assert world.post(AF, "🏍 Дніпро Реактивний БпЛА над містом!", after=10) == []
    assert of(world.post(AF, "🏍 Реактивний БпЛА над Києвом!", after=400), "jet_drone") == [
        ("repeat", "take_cover", "inbound_home")
    ]


def test_a_stale_message_is_ignored():
    world = Courses()
    world.now += timedelta(seconds=300)
    message = IncomingMessage(5000, world.now - timedelta(seconds=300), "🏍 Київ: реактивний БпЛА на Оболонь")
    publications = world.processors[AF].handle(message, world.now - timedelta(seconds=299))
    assert world.situation.feed(AF, publications, world.now) == []


def test_courses_are_validated():
    with pytest.raises(ConfigError, match="situation.courses.ballistic"):
        parse_config({"chats": CHATS, "situation": {"home": "київ", "sources": {"a": {}}, "courses": {"ballistic": None}}})
    with pytest.raises(ConfigError, match="situation.courses.x.home: matches empty text"):
        parse_config({"chats": CHATS, "situation": {"home": "київ", "sources": {"a": {}}, "courses": {"x": {"home": "y*"}}}})
    with pytest.raises(ConfigError, match="situation.courses.x: expected only"):
        parse_config({"chats": CHATS, "situation": {"home": "київ", "sources": {"a": {}}, "courses": {"x": {"loud": True}}}})
    config = parse_config(
        {"chats": CHATS, "situation": {"home": "київ", "sources": {"a": {}}, "courses": {"x": {"inbound_hold": 60}}}}
    )
    assert config.situation.courses["x"].inbound_hold == timedelta(seconds=60)
