from pathlib import Path

import pytest

from air_threat_monitor.rules import ConfigError, RuleMatch, load_config, match_rules, parse_config
from air_threat_monitor.text import clean_text

EXAMPLE = Path(__file__).parent.parent / "rules.example.yaml"


@pytest.fixture(scope="module")
def rules():
    return load_config(EXAMPLE).chats["kpszsu"].rules


def events(raw, rules):
    return match_rules(clean_text(raw), rules)


def test_long_message_gives_no_events():
    chat = load_config(EXAMPLE).chats["kpszsu"]
    alert = "Балістика на Київ!"
    assert [match.kind for match in chat.match(alert)] == ["ballistic_missile"]
    summary = "У ніч на 17 жовтня противник атакував. " * 6 + "Збито 5 балістичних ракет Іскандер-М."
    assert len(summary) > chat.max_length
    assert chat.match(summary) == []


# --- Wordings recorded from the channel on 2026-11-09..10 -------------------


def test_threat_with_origin(rules):
    assert events("☄️ Загроза застосування балістичного озброєння з Брянська.", rules) == [
        RuleMatch(
            "ballistic_threat",
            "Загроза застосування балістичного озброєння з Брянська",
            {"from": "Брянська"},
        )
    ]


def test_threat_seen_on_2026_11_12(rules):
    assert events("🚀 Загроза застосування балістичного озброєння з Воронежа.", rules) == [
        RuleMatch(
            "ballistic_threat",
            "Загроза застосування балістичного озброєння з Воронежа",
            {"from": "Воронежа"},
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
    ("raw", "route"),
    [
        # Seen on 2026-11-12, in the order the channel posted them.
        ("🚀Балістична ракета через Сумщину!", "через Сумщину"),
        ("🚀Балістика через Сумщину на Полтавщину!", "через Сумщину на Полтавщину"),
        ("🚀Балістика на Лубни!", "на Лубни"),
        ("🚀Балістична ракета через Полтавщину на південь Київщини!", "через Полтавщину на південь Київщини"),
        ("🚀Ще одна балістична ракета на Київщину!", "на Київщину"),
        ("🚀Балістика на Бровари/Київ!", "на Бровари/Київ"),
        ("🚀Балістика на Київ!", "на Київ"),
        # Found by the review of 30 days of history, 2026-11-12.
        ("🚀Балістичні ракети курсом на Київ.", "курсом на Київ"),
        ("🚀4 балістичні ракети на Київ!", "на Київ"),
        ("🚀Декілька балістичних ракет на Київ!", "на Київ"),
        ("🚀Ще на Київ балістика", "на Київ"),
        ("🚀Повторний пуск балістики на  Київ", "на Київ"),
        # Seen on 2026-11-10.
        ("🚀Балістична ракета у напрямку Нової Водолаги (Харківщина)", "у напрямку Нової Водолаги (Харківщина)"),
    ],
)
def test_missile_follow_up_gives_its_route(rules, raw, route):
    found = events(raw, rules)
    assert [(event.kind, event.fields) for event in found] == [("ballistic_missile", {"route": route})]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("🚀Повторний пуск балістики", [("ballistic_missile", {})]),
        ("🚀Крилаті ракети на Київ з півночі.", [("cruise_missile", {"route": "на Київ з півночі"})]),
        ("🚀Крилата ракета на Харківщині курс західний", [("cruise_missile", {"route": "на Харківщині курс західний"})]),
        ("Ракета на КИїв!", [("missile", {"route": "на КИїв"})]),
        ("🚀Ще 2 ракети на Київ!", [("missile", {"route": "на Київ"})]),
        ("🚀Ракета з Черкащини на Київщину", [("missile", {"route": "з Черкащини на Київщину"})]),
        # The morning summary must stay silent.
        (
            "⚡️ ЗБИТО/ПОДАВЛЕНО 293 ЦІЛІ ПРОТИВНИКА\n➖➖➖\nУ ніч на 17 жовтня противник атакував балістичними ракетами"
            " Іскандер-М/KN-23 із Воронезької області, крилатими ракетами Іскандер-К та 300 ударними БпЛА.",
            [],
        ),
    ],
)
def test_other_missile_wordings(rules, raw, expected):
    assert [(event.kind, event.fields) for event in events(raw, rules)] == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Seen on 2026-11-13, the Banderols that brought the red alert to Kyiv.
        (
            '🚀Баражуючі боєприпаси "Бандероль" в р-ні Київського водосховища курсом на Київ з півночі.',
            [("banderol", 'Баражуючі боєприпаси "Бандероль" в р-ні Київського водосховища курсом на Київ з півночі.')],
        ),
        ("🚀Київщина: «Бандероль» у напрямку Броварів.", [("banderol", "Київщина: «Бандероль» у напрямку Броварів.")]),
        ('🚀 ББ "Бандероль" на н.п.Борзна та Парафіївку на Чернігівщині.', [("banderol", 'ББ "Бандероль" на н.п.Борзна та Парафіївку на Чернігівщині.')]),
        ("🏍 Київ: реактивний БпЛА курсом на центр", [("jet_drone", "Київ: реактивний БпЛА курсом на центр")]),
        ("🏍 Реактивні БпЛА на Запоріжжя з півночі.", [("jet_drone", "Реактивні БпЛА на Запоріжжя з півночі.")]),
        ("🏍 Реактивний курсом на Рівне з півночі.", [("jet_drone", "Реактивний курсом на Рівне з півночі.")]),
        # One line per weapon: each line is its own event, with its own places.
        (
            "🏍 Реактивний БпЛА на півдні Одещини.\n🏍 Реактивний БпЛА повз Згурівку на Київщині, курс на південний напрямок.",
            [
                ("jet_drone", "Реактивний БпЛА на півдні Одещини."),
                ("jet_drone", "Реактивний БпЛА повз Згурівку на Київщині, курс на південний напрямок."),
            ],
        ),
    ],
)
def test_threats_known_by_their_course(rules, raw, expected):
    assert [(event.kind, event.match) for event in events(raw, rules)] == expected


def test_threat_and_clear_are_not_missile_follow_ups(rules):
    raw = "☄️ Загроза застосування балістичного озброєння.\n📢 Відбій загрози застосування балістичного озброєння."
    assert [event.kind for event in events(raw, rules)] == ["ballistic_threat", "ballistic_clear"]


@pytest.mark.parametrize(
    "raw",
    [
        "🛵 БпЛА курсом на Київ з півночі.",
        "🚀КАБи на Сумщину та Донеччину.",
        "🛫 Активність ворожої тактичної авіації на південно-східному напрямку!",
        "🚀Швидкісна ціль у Чорному морі, курсом на Одещину.",
        "+ у напрямку Сум",
        # Follow-ups that are only a place name, seen on 2026-11-12.
        "🚀 Пирятин!",
        "🚀 Біла Церква!",
        "🚀Київ!",
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


# --- kyiv_m0nitoring, wordings of 2026-11-09..11 ------------------------------


@pytest.fixture(scope="module")
def monitoring_rules():
    return load_config(EXAMPLE).chats["kyiv_m0nitoring"].rules


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Загроза балістики з Брянська.", [("ballistic_threat", {"from": "Брянська"})]),
        ("Загроза з Воронежа.", [("ballistic_threat", {"from": "Воронежа"})]),
        ("Балістика на Київ/передмістя.", [("ballistic_missile", {"route": "Київ/передмістя"})]),
        (
            "Загроза балістики з Брянська.\n23:07 Робота засобів ППО ворога.",
            [("ballistic_threat", {"from": "Брянська"})],
        ),
        ("спуск", [("ballistic_descent", {})]),
        ("ще спуск !!!", [("ballistic_descent", {})]),
        ("спуск на правий", [("ballistic_descent", {"where": "правий"})]),
        ("4 ракети спуск", [("ballistic_descent", {})]),
        ("спуск іскандерів ‼️", [("ballistic_descent", {})]),
        # The threat is over; the joke about stairs is not a descent.
        ("Відбій загрози, тренування спуску на 1 поверх.", [("ballistic_clear", {})]),
        ("Балістика Воронеж.\nUPD: Без загроз.", [("ballistic_threat", {"from": "Воронеж"})]),
        ("Загроза балістики.", [("ballistic_threat", {})]),
        ("Повторна загроза балістики з Курська.", [("ballistic_threat", {"from": "Курська"})]),
        ("Повторно дали загрозу балістики.", [("ballistic_threat", {})]),
        ("знову загроза балістики", [("ballistic_threat", {})]),
        ("загроза з брянска", [("ballistic_threat", {"from": "брянска"})]),
        ("брянск", [("ballistic_threat", {"from": "брянск"})]),
        ("Брянск\nРакетная опасность", []),
        ("Брянск и близлежащие\nТревога по БПЛА", []),
        ("2 ракети!", [("ballistic_missile", {"count": "2"})]),
        ("Ще 2-4 ракети!", [("ballistic_missile", {"count": "2-4"})]),
        ("2-3 ракети!!!!", [("ballistic_missile", {"count": "2-3"})]),
        ("ні, грається висотою", []),
        (
            "Кількість готових до застосування ракет на потенційних «київських» точках:\n- 5 Іскандер-М.\n- 20 С-400+Онікси.",
            [],
        ),
        ("по 1 ракеті пускати, щоб вбити рятувальників це рівень росіян", []),
        ("Воронеж", [("ballistic_threat", {"from": "Воронеж"})]),
        ("бал", [("ballistic_threat", {})]),
        ("баллистика", [("ballistic_threat", {})]),
        ("Вихід балістики на Київ/передмістя.", [("ballistic_missile", {"route": "Київ/передмістя"})]),
        ("балістика на київ з брянська", [("ballistic_missile", {"route": "київ з брянська"})]),
        ("2 ракети з брянська на київ", [("ballistic_missile", {"route": "київ"})]),
        ("2-4 циркона на Київ.", [("ballistic_missile", {"route": "Київ"})]),
        ("6-8 цирконів на київщину/киів", [("ballistic_missile", {"route": "київщину/киів"})]),
        ("І тепер іскандери пішли на київ !!!!", [("ballistic_missile", {"route": "київ"})]),
        ("Відбій балістики.", [("ballistic_clear", {})]),
        ("Відбій по балістиці!", [("ballistic_clear", {})]),
        ("балістична загроза знята", [("ballistic_clear", {})]),
        ("Загрозу по ракетам зняли, дрони збивають на підступах до столиці.", [("ballistic_clear", {})]),
        ("ракетну зняли", [("ballistic_clear", {})]),
        ("чисто", [("nothing_tracked", {})]),
        ("чисто по ракетам", [("nothing_tracked", {})]),
        ("не фіксується", [("nothing_tracked", {})]),
        ("не фіксується ракет до нас", [("nothing_tracked", {})]),
        ("Без загроз.", [("nothing_tracked", {})]),
        ("Без фіксацій ракет.", [("nothing_tracked", {})]),
        ("Ні.", [("nothing_tracked", {})]),
        ("ні, поспішили", [("nothing_tracked", {})]),
        ("Ні, Київ обходить все поки.", [("nothing_tracked", {})]),
        ("все ж таки не балістика", [("nothing_tracked", {})]),
        # Threats known by their course: the whole line, no fields.
        ("3 реактива на київ, перший наближається до вишгорода/києва", [("jet_drone", {})]),
        ("реактив на трою, балістика не фіксується", [("jet_drone", {})]),
        ("реактив на бровари/вишгород", [("jet_drone", {})]),
        ("реактиви по морю в бік вишгорода/києва", [("jet_drone", {})]),
        ("Бандероль на Бровари/Київ.", [("banderol", {})]),
        ("червона через бандеролі на вишгород/околиці", [("banderol", {})]),
        ("реактив в районі Обухова і бандероль на Чернігівщині", [("banderol", {}), ("jet_drone", {})]),
        # Must stay silent.
        ("під києвом був реактив, не фікс вже", []),
        ("реактив збили над Броварами", []),
        ("загиблі внаслідок ракетного удару по києву", []),
        ("балістична відбій, лише дрон кружляє над києвом", [("ballistic_clear", {})]),
        ("ви все чуєте, загроза трипільська тес/чабани та наливайківка", []),
        ("уточнення: з брянска без загрози, тривожимось на Курськ", []),
        ("пролунав вибух, чисто", []),
        ("Дрони балістикою?Ви зараз серйозно?", []),
        (
            "Будьте уважні, бібізян лягає спати лише тоді, коли не очікує стратегічної авіації, а загроза балістики нижче середньої.",
            [],
        ),
        ("2 ракети на київ", [("ballistic_missile", {"route": "київ"})]),
        ("буде відбій", []),
        ("Відбій.", []),
        ("❌ жодних вагомих попереджень щодо балістичного удару по нашому регіону не надходило.", []),
    ],
)
def test_monitoring_channel(monitoring_rules, raw, expected):
    assert [(event.kind, event.fields) for event in events(raw, monitoring_rules)] == expected


# --- Rules file --------------------------------------------------------------


def test_example_file_loads():
    config = load_config(EXAMPLE)
    chat = config.chats["kpszsu"]
    assert chat.poll_interval == 3.0
    assert [rule.kind for rule in chat.rules] == [
        "ballistic_clear",
        "ballistic_threat",
        "ballistic_missile",
        "ballistic_missile",
        "ballistic_missile",
        "cruise_missile",
        "missile",
        "banderol",
        "jet_drone",
    ]
    assert list(config.situation.courses) == ["banderol", "jet_drone"]


def test_max_length_is_validated():
    assert parse_config({"chats": {"news": {"max_length": 100}}}).chats["news"].max_length == 100
    with pytest.raises(ConfigError, match="chats.news.max_length"):
        parse_config({"chats": {"news": {"max_length": 0}}})


def test_watch_is_optional_and_validated():
    config = parse_config({"chats": {"news": {"watch": "(?i)ракет"}}})
    assert config.chats["news"].watch.search("Ракета")
    assert parse_config({"chats": {"news": None}}).chats["news"].watch is None
    with pytest.raises(ConfigError, match="chats.news.watch"):
        parse_config({"chats": {"news": {"watch": "("}}})


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
