# telegram-mqtt-gateway

Listens to configured Telegram channels and chats with a user-account session, matches each message against rules and publishes the results to MQTT. What to do with an event is decided by the consumer (Home Assistant).

State: under construction. It runs from a terminal; the login page and the Home Assistant app packaging do not exist yet. It has not published to a real broker yet.

## Rules

See [rules.example.yaml](rules.example.yaml). A rule is a Python regular expression with a `kind`; every match gives one event, and named groups become its `fields`. Before matching and publishing, emoji are removed from the message text and runs of spaces are collapsed, so rules are written for plain text.

## Decisions for the home

With a `situation` section in the rules file, the gateway also follows a ballistic threat across messages and sources and publishes what it means for the home. It needs the air-alert level from the consumer (`TMG_ALERT_LEVEL_TOPIC`, payload `red`, `yellow` or `none`); without it every threat is treated as under an alert.

| Topic | Payload |
|---|---|
| `telegram/situation/ballistic` | the current decision, retained |
| `telegram/situation/ballistic/event` | the same payload on every change, not retained: the trigger for an announcement |

```json
{"threat": "ballistic", "state": "inbound_home", "severity": "take_cover", "change": "raised", "peak": "take_cover",
 "reason": "ballistic_missile", "source": "kyiv_m0nitoring", "id": 34921, "text": "Балістика на Київ/передмістя.",
 "alert_level": "red", "since": "2026-11-11T22:53:59Z", "at": "2026-11-11T22:59:44Z"}
```

| Severity | When |
|---|---|
| `none` | no threat, or a threat while the home has no alert |
| `attention` | a threat while the home is under an alert, or a missile toward the region |
| `take_cover` | a missile toward a `home` place, from any source; lasts 10 minutes after the last such message |
| `impact` | "спуск": the missile is in its terminal phase; lasts 2 minutes |

`change` is `raised`, `lowered`, `repeat` (the same severity confirmed by a new message, at most once a minute) or `clear`. A `clear` carries `peak`, the highest severity of the threat, so the consumer can skip the all-clear of a threat it never announced. The threat ends with the official all-clear or after an hour without missile messages; "чисто" or an unofficial all-clear only withdraws the current warning.

`replay` runs the saved histories through the same code and prints every decision, which is how a change to the rules or the places is judged:

```sh
.venv/Scripts/python -m telegram_mqtt_gateway replay --alert-level none
```

Not covered: cruise missiles and drones give events but no decisions; after a restart a threat in progress is not known until its next message.

## Monthly review

The channels change their wordings, and a rule that stopped matching fails silently. Once a month, for every chat in the rules file:

```sh
.venv/Scripts/python -m telegram_mqtt_gateway history kpszsu --days 31
.venv/Scripts/python -m telegram_mqtt_gateway review kpszsu --limit 200 > data/history/kpszsu-review.txt
```

Read the report in this order:

1. **A kind with no matches, or far fewer than last month.** The wording has probably changed; find the new one under "watch words, no rule".
2. **"watch words, no rule".** Messages that contain the chat's `watch` words and matched nothing. Most are commentary; an alert among them needs a rule.
3. **The wordings under each kind.** Anything that is not that kind is a false match; tighten the rule.

Every change to a rule gets a test with the real message in `tests/test_rules.py`. Record the date and the counts per kind where the previous review is recorded, so the next one has something to compare with. `history` cannot run while the gateway uses the same session file: stop the gateway or use another session.

## MQTT topics

The prefix `telegram` is configurable. Messages and events are not retained and are dropped while the broker is unreachable: a late event is worse than none.

| Topic | Payload |
|---|---|
| `telegram/status` | `online` / `offline` (retained, last will) |
| `telegram/login` | `ok` / `needed` (retained) |
| `telegram/<chat>/message` | `{chat, id, date, text, reply_to, edited}` for every new or edited message |
| `telegram/<chat>/event` | `{kind, chat, id, date, text, match, fields, reply_to, edited}` for every rule match |

`reply_to` is the id of the message being replied to, or `null`; with it a consumer can follow a chain of replies whose members no rule can recognise by text.

A message older than `TMG_STALE_AFTER` seconds when it is received gives no events. An edit gives events only for matches the earlier versions of the message did not have.

## Running from a terminal

Settings come from environment variables; keep them in `local.env` (ignored by Git).

| Variable | Default | |
|---|---|---|
| `TMG_API_ID`, `TMG_API_HASH` | required | from my.telegram.org/apps |
| `TMG_SESSION` | `data/session/gateway` | session file, without `.session`; it gives full access to the account |
| `TMG_RULES` | `rules.yaml` | |
| `TMG_MQTT_HOST`, `TMG_MQTT_PORT` | `localhost`, `1883` | |
| `TMG_MQTT_USERNAME`, `TMG_MQTT_PASSWORD` | none | |
| `TMG_TOPIC_PREFIX` | `telegram` | |
| `TMG_STALE_AFTER` | `120` | seconds |
| `TMG_ALERT_LEVEL_TOPIC` | none | topic with the air-alert level of the home: `red`, `yellow`, `none` |

```sh
set -a; . ./local.env; set +a
.venv/Scripts/python -m telegram_mqtt_gateway check-rules rules.example.yaml
.venv/Scripts/python -m telegram_mqtt_gateway login            # QR code in the terminal
.venv/Scripts/python -m telegram_mqtt_gateway run --dry-run    # print instead of publishing
.venv/Scripts/python -m telegram_mqtt_gateway run
.venv/Scripts/python -m telegram_mqtt_gateway history kpszsu --days 30   # raw messages to data/history/kpszsu.jsonl
.venv/Scripts/python -m telegram_mqtt_gateway review kpszsu               # what each rule caught in that history
```

## Development

```sh
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # bin/ instead of Scripts/ outside Windows
.venv/Scripts/python -m pytest
```
