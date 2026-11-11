from pathlib import Path

import pytest

from telegram_mqtt_gateway.rules import ConfigError, RuleMatch, load_config, match_rules, parse_config
from telegram_mqtt_gateway.text import clean_text

EXAMPLE = Path(__file__).parent.parent / "rules.example.yaml"


@pytest.fixture(scope="module")
def rules():
    return load_config(EXAMPLE).chats["kpszsu"].rules


def events(raw, rules):
    return match_rules(clean_text(raw), rules)


# --- Wordings recorded from the channel on 2026-11-09..10 -------------------


def test_threat_with_origin(rules):
    assert events("☄️ Загроза застосування балістичного озброєння з Брянська.", rules) == [
        RuleMatch(
            "ballistic_threat",
            "Загроза застосування балістичного озброєння з Брянська",
            {"from": "Брянська"},
        )
    ]


def test_threat_with_direction(rules):
    assert events("☄️ Загроза застосування балістичного озброєння з південного сходу.", rules) == [
        RuleMatch(
            "ballistic_threat",
            "Загроза застосування балістичного озброєння з південного сходу",
            {"from": "південного сходу"},
        )
    ]


@pytest.mark.parametrize(
    "raw",
    [
        "☄️ Загроза застосування балістичного озброєння.",
        "☄️ Загроза застосування балістичного озброєння!",
        "Загроза застосування балістичного озброєння",
    ],
)
def test_threat_without_origin(rules, raw):
    assert events(raw, rules) == [
        RuleMatch("ballistic_threat", "Загроза застосування балістичного озброєння", {})
    ]


@pytest.mark.parametrize(
    "raw",
    [
        "📢 Відбій загрози застосування  балістичного озброєння.",
        "📢 Відбій загрози застосування балістичного озброєння.",
    ],
)
def test_clear_is_not_a_threat(rules, raw):
    assert events(raw, rules) == [
        RuleMatch("ballistic_clear", "Відбій загрози застосування балістичного", {})
    ]


@pytest.mark.parametrize(
    "raw",
    [
        "🏍 Київ: реактивний БпЛА курсом на центр",
        "🛵 БпЛА курсом на Київ з півночі.",
        "🚀КАБи на Сумщину та Донеччину.",
        "🛫 Активність ворожої тактичної авіації на південно-східному напрямку!",
        "🚀Балістична ракета у напрямку Нової Водолаги (Харківщина)",
        "🚀Швидкісна ціль у Чорному морі, курсом на Одещину.",
        "+ у напрямку Сум",
        "🚀",
        "",
    ],
)
def test_other_messages_give_nothing(rules, raw):
    assert events(raw, rules) == []


def test_multiline_message_gives_events_in_text_order(rules):
    raw = (
        "☄️ Загроза застосування балістичного озброєння з Брянська.\n"
        "🛵 БпЛА курсом на Київ з півночі.\n"
        "📢 Відбій загрози застосування  балістичного озброєння.\n"
        "☄️ Загроза застосування балістичного озброєння з південного сходу!"
    )
    assert [(event.kind, event.fields) for event in events(raw, rules)] == [
        ("ballistic_threat", {"from": "Брянська"}),
        ("ballistic_clear", {}),
        ("ballistic_threat", {"from": "південного сходу"}),
    ]


def test_origin_does_not_run_into_the_next_line(rules):
    raw = "☄️ Загроза застосування балістичного озброєння з Курська\n🛵 БпЛА на Суми"
    assert events(raw, rules)[0].fields == {"from": "Курська"}


# --- Rules file --------------------------------------------------------------


def test_example_file_loads():
    config = load_config(EXAMPLE)
    chat = config.chats["kpszsu"]
    assert chat.poll_interval == 3.0
    assert [rule.kind for rule in chat.rules] == ["ballistic_clear", "ballistic_threat"]


def test_defaults():
    config = parse_config({"chats": {"news": None}})
    assert config.chats["news"].poll_interval == 3.0
    assert config.chats["news"].rules == ()


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (None, "top-level 'chats'"),
        ({"chats": []}, "top-level 'chats'"),
        ({"chats": {}}, "'chats' is empty"),
        ({"chats": {"a": {}}, "extra": 1}, "unknown top-level keys"),
        ({"chats": {"a/b": {}}}, "chats.a/b: chat name"),
        ({"chats": {"a": []}}, "chats.a: expected a mapping"),
        ({"chats": {"a": {"interval": 3}}}, "chats.a: unknown keys"),
        ({"chats": {"a": {"poll_interval": "3"}}}, "chats.a.poll_interval: expected a number"),
        ({"chats": {"a": {"poll_interval": True}}}, "chats.a.poll_interval: expected a number"),
        ({"chats": {"a": {"poll_interval": 0.5}}}, "chats.a.poll_interval: must be at least 1 s"),
        ({"chats": {"a": {"rules": {}}}}, "chats.a.rules: expected a list"),
        ({"chats": {"a": {"rules": ["x"]}}}, "chats.a.rules[0]: expected a mapping"),
        ({"chats": {"a": {"rules": [{"kind": "k", "pattern": "x", "flags": 1}]}}}, "rules[0]: unknown keys"),
        ({"chats": {"a": {"rules": [{"pattern": "x"}]}}}, "rules[0].kind"),
        ({"chats": {"a": {"rules": [{"kind": "Bad Kind", "pattern": "x"}]}}}, "rules[0].kind"),
        ({"chats": {"a": {"rules": [{"kind": "k"}]}}}, "rules[0].pattern: expected"),
        ({"chats": {"a": {"rules": [{"kind": "k", "pattern": "("}]}}}, "rules[0].pattern: invalid regular expression"),
        ({"chats": {"a": {"rules": [{"kind": "k", "pattern": "x*"}]}}}, "rules[0].pattern: matches empty text"),
    ],
)
def test_invalid_config_names_the_place(data, message):
    with pytest.raises(ConfigError) as error:
        parse_config(data)
    assert message in str(error.value)


def test_missing_file_and_bad_yaml_name_the_file(tmp_path):
    missing = tmp_path / "rules.yaml"
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(missing)
    missing.write_text("chats: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(missing)
    missing.write_text("chats: {a: {poll_interval: 0}}", encoding="utf-8")
    with pytest.raises(ConfigError) as error:
        load_config(missing)
    assert str(missing) in str(error.value)
