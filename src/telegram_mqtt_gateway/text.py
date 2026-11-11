"""Cleaning of message text before it is matched and published.

Consumers of the MQTT topics read the text aloud or show it on small displays,
so emoji are noise there; rules are also simpler to write against plain text.
"""

import re

_EMOJI = re.compile(
    "(?:"
    # Keycaps (digit, optional variation selector, enclosing keycap) go as a
    # whole, otherwise the bare digit would stay behind as a false number.
    "[0-9#*]️?⃣"
    # Pictographs, flags, skin tones; technical, miscellaneous and dingbat
    # symbols; stars and heavy arrows.
    "|[\U0001f000-\U0001faff⌀-⏿☀-➿⬀-⯿]"
    # Any other character forced to emoji presentation, such as an arrow or
    # the copyright sign followed by U+FE0F.
    "|[^\\n]️"
    # Leftover joiners, variation selectors, keycap marks and tag characters.
    "|[‍︎️⃣\U000e0020-\U000e007f]"
    ")+"
)
_HORIZONTAL_SPACE = re.compile(r"[^\S\n]+")
_BLANK_LINES = re.compile(r"\n{3,}")


def clean_text(text: str) -> str:
    """Return text without emoji and with whitespace normalised.

    An emoji leaves a space behind so that the words around it stay apart.
    Line breaks are kept: one message can carry several announcements.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _EMOJI.sub(" ", text)
    lines = (_HORIZONTAL_SPACE.sub(" ", line).strip() for line in text.split("\n"))
    return _BLANK_LINES.sub("\n\n", "\n".join(lines)).strip()
