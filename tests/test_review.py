from air_threat_monitor.review import format_review, review_messages
from air_threat_monitor.rules import parse_config

CHAT = parse_config(
    {
        "chats": {
            "demo": {
                "watch": "(?i)ракет|баліст",
                "rules": [
                    {"kind": "threat", "pattern": "Загроза балістики"},
                    {"kind": "descent", "pattern": "(?i)спуск"},
                ],
            }
        }
    }
).chats["demo"]

MESSAGES = [
    {"date": "2026-11-01T10:00:00+00:00", "text": "☄️ Загроза балістики з Брянська."},
    {"date": "2026-11-02T10:00:00+00:00", "text": "☄️ Загроза балістики з Брянська."},
    {"date": "2026-11-03T10:00:00+00:00", "text": "🚀 Нова ракета\nна Київ"},
    {"date": "2026-11-04T10:00:00+00:00", "text": "добраніч"},
]


def test_review_counts_matches_and_lists_unmatched_watch_words():
    review = review_messages(MESSAGES, CHAT)
    assert review.total == 4
    assert (review.first_date[:10], review.last_date[:10]) == ("2026-11-01", "2026-11-04")
    assert dict(review.kinds["threat"]) == {"Загроза балістики з Брянська.": 2}
    assert dict(review.kinds["descent"]) == {}
    assert dict(review.suspects) == {"Нова ракета / на Київ": 1}


def test_report_flags_a_rule_that_matched_nothing():
    report = format_review(review_messages(MESSAGES, CHAT))
    assert "demo: 4 messages, 2026-11-01 .. 2026-11-04" in report
    assert "## threat: 2 messages, 1 wordings" in report
    assert "## descent: 0 messages" in report
    assert "has the wording changed?" in report
    assert "## watch words, no rule: 1 messages" in report
