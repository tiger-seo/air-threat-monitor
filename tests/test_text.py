import pytest

from telegram_mqtt_gateway.text import clean_text


@pytest.mark.parametrize(
    ("raw", "cleaned"),
    [
        # Wordings of the kpszsu channel.
        (
            "☄️ Загроза застосування балістичного озброєння з Брянська.",
            "Загроза застосування балістичного озброєння з Брянська.",
        ),
        (
            "📢 Відбій загрози застосування  балістичного озброєння.",
            "Відбій загрози застосування балістичного озброєння.",
        ),
        ("🚀КАБи на Сумщину та Донеччину.", "КАБи на Сумщину та Донеччину."),
        ("🏍🛵 БпЛА курсом на Київ з півночі.", "БпЛА курсом на Київ з півночі."),
        # Raw text as Telethon gave it on 2026-11-11: the channel's custom emoji
        # arrives as an ordinary one, with no space after it.
        ("🚀Ще одна балістична ракета на Київщину!", "Ще одна балістична ракета на Київщину!"),
        ("🚀Київ!", "Київ!"),
        ("⚠ Увага!", "Увага!"),
        ("⚠️ Увага!", "Увага!"),
        # An emoji between words must not glue them together.
        ("Київ🏍БпЛА", "Київ БпЛА"),
        # Sequences: flag, family joined with ZWJ, skin tone, keycap, tag flag.
        ("Слава 🇺🇦 Україні", "Слава Україні"),
        ("родина 👨‍👩‍👧 тут", "родина тут"),
        ("добре 👍🏽", "добре"),
        ("1️⃣ Київ 2️⃣ Харків", "Київ Харків"),
        ("🏴\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f Англія", "Англія"),
        # Characters forced to emoji presentation.
        ("курс ↗️ на північ", "курс на північ"),
        ("©️ Повітряні сили", "Повітряні сили"),
        # Only emoji.
        ("🚀🚀🚀", ""),
        ("", ""),
    ],
)
def test_emoji_are_removed(raw, cleaned):
    assert clean_text(raw) == cleaned


@pytest.mark.parametrize(
    "text",
    [
        "Балістична ракета у напрямку Нової Водолаги (Харківщина)",
        "№ 5: +3 °C, «Київ» — п'ять БпЛА; 12:30, 50%?",
        "Суми → Полтава",
        "Ціль #2 * 3 = 6",
        "it's 100% © plain",
    ],
)
def test_plain_text_is_kept(text):
    assert clean_text(text) == text


def test_line_breaks_are_kept_and_lines_trimmed():
    raw = "🛵 БпЛА на Київ \r\n\r\n🏍  Реактивний БпЛА\tна Харків\n🚀\n\n\n+ у напрямку Сум"
    assert clean_text(raw) == "БпЛА на Київ\n\nРеактивний БпЛА на Харків\n\n+ у напрямку Сум"


def test_non_breaking_space_becomes_a_space():
    assert clean_text("Загроза застосування") == "Загроза застосування"
