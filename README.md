# air-threat-monitor

Follows air threats to a home in Ukraine. It listens to configured Telegram channels with a user-account session, matches each message against rules, follows a ballistic threat across messages and channels, and publishes messages, rule matches and decisions to MQTT. What to do with a decision (announce it or not, where, how loud) is left to the consumer (Home Assistant).

It was called `telegram-mqtt-gateway` until 2026-11-12; "the gateway" in the code and below means the part that listens to Telegram. Sources other than Telegram are meant to be added as modules that feed the same decisions.

State: under construction. It runs from a terminal and has a login page; the Home Assistant app packaging is written and has not been deployed yet.

## Rules

See [rules.example.yaml](rules.example.yaml). A rule is a Python regular expression with a `kind`; every match gives one event, and named groups become its `fields`. Before matching and publishing, emoji are removed from the message text and runs of spaces are collapsed, so rules are written for plain text.

## Decisions for the home

With a `situation` section in the rules file, the gateway also follows a ballistic threat across messages and sources and publishes what it means for the home. It needs the air-alert level from the consumer (`AIR_THREAT_ALERT_LEVEL_TOPIC`, payload `red`, `yellow` or `none`); without it every threat is treated as under an alert.

| Topic | Payload |
|---|---|
| `air_threat/ballistic` | the current decision, retained |
| `air_threat/ballistic/event` | the same payload on every change, not retained: the trigger for an announcement |

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
.venv/Scripts/python -m air_threat_monitor replay --alert-level none
```

Not covered: cruise missiles and drones give events but no decisions; after a restart a threat in progress is not known until its next message.

## Monthly review

The channels change their wordings, and a rule that stopped matching fails silently. Once a month, for every chat in the rules file:

```sh
.venv/Scripts/python -m air_threat_monitor history kpszsu --days 31
.venv/Scripts/python -m air_threat_monitor review kpszsu --limit 200 > data/history/kpszsu-review.txt
```

Read the report in this order:

1. **A kind with no matches, or far fewer than last month.** The wording has probably changed; find the new one under "watch words, no rule".
2. **"watch words, no rule".** Messages that contain the chat's `watch` words and matched nothing. Most are commentary; an alert among them needs a rule.
3. **The wordings under each kind.** Anything that is not that kind is a false match; tighten the rule.

Every change to a rule gets a test with the real message in `tests/test_rules.py`. Record the date and the counts per kind where the previous review is recorded, so the next one has something to compare with. `history` cannot run while the gateway uses the same session file: stop the gateway or use another session.

## MQTT topics

The prefix `air_threat` is configurable (`AIR_THREAT_TOPIC_PREFIX`); everything a source publishes is under `source/<source>/`. Messages and events are not retained and are dropped while the broker is unreachable: a late event is worse than none.

| Topic | Payload |
|---|---|
| `air_threat/status` | `online` / `offline` (retained, last will) |
| `air_threat/source/telegram/login` | `ok` / `needed` (retained) |
| `air_threat/source/telegram/<chat>/message` | `{chat, id, date, text, reply_to, edited}` for every new or edited message |
| `air_threat/source/telegram/<chat>/event` | `{kind, chat, id, date, text, match, fields, reply_to, edited}` for every rule match |

`reply_to` is the id of the message being replied to, or `null`; with it a consumer can follow a chain of replies whose members no rule can recognise by text.

A message older than `AIR_THREAT_STALE_AFTER` seconds when it is received gives no events. An edit gives events only for matches the earlier versions of the message did not have.

## Login and status page

While `run` is going, `http://127.0.0.1:8099/` shows who the gateway is logged in as, the broker connection and the last message of every chat. Without a session, or after the session was terminated in Telegram (Settings → Devices), the gateway keeps running, publishes `air_threat/source/telegram/login` = `needed` and the page shows a QR code to scan in Telegram; an account with two-step verification is then asked for its password. After the login the gateway starts listening without a restart; messages posted in between count as old.

- A QR code is requested from Telegram only while the page is open, a new one about every 30 seconds.
- The page has no authentication of its own. It listens on `127.0.0.1`; as a Home Assistant app it is reached through ingress only.
- All its addresses are relative, so it works under any path a proxy serves it at.
- `AIR_THREAT_WEB_PORT=0` turns the page off: a missing session then ends `run` with exit code 2, and `login` creates the session from a terminal.

## Running from a terminal

Settings come from environment variables; keep them in `local.env` (ignored by Git).

| Variable | Default | |
|---|---|---|
| `AIR_THREAT_API_ID`, `AIR_THREAT_API_HASH` | required | from my.telegram.org/apps |
| `AIR_THREAT_SESSION` | `data/session/telegram` | session file, without `.session`; it gives full access to the account |
| `AIR_THREAT_RULES` | `rules.yaml` | |
| `AIR_THREAT_MQTT_HOST`, `AIR_THREAT_MQTT_PORT` | `localhost`, `1883` | |
| `AIR_THREAT_MQTT_USERNAME`, `AIR_THREAT_MQTT_PASSWORD` | none | |
| `AIR_THREAT_TOPIC_PREFIX` | `air_threat` | |
| `AIR_THREAT_STALE_AFTER` | `120` | seconds |
| `AIR_THREAT_ALERT_LEVEL_TOPIC` | none | topic with the air-alert level of the home: `red`, `yellow`, `none` |
| `AIR_THREAT_WEB_HOST`, `AIR_THREAT_WEB_PORT` | `127.0.0.1`, `8099` | login and status page; port `0` turns it off |

```sh
set -a; . ./local.env; set +a
.venv/Scripts/python -m air_threat_monitor check-rules rules.example.yaml
.venv/Scripts/python -m air_threat_monitor login            # QR code in the terminal, instead of the page
.venv/Scripts/python -m air_threat_monitor run --dry-run    # print instead of publishing
.venv/Scripts/python -m air_threat_monitor run
.venv/Scripts/python -m air_threat_monitor history kpszsu --days 30   # raw messages to data/history/kpszsu.jsonl
.venv/Scripts/python -m air_threat_monitor review kpszsu               # what each rule caught in that history
```

## As a Home Assistant app

`config.yaml` and `Dockerfile` make the repository a local Home Assistant app (add-on), built on the device. `./deploy.sh` copies the committed code to `/local_apps/air_threat_monitor` over `ssh hassio` and installs, updates (new `version` in `config.yaml`) or rebuilds (same version) the app `local_air_threat_monitor`. State: written, not deployed yet.

- **Settings** come from the app's Configuration tab (`api_id`, `api_hash`, the rules file, the topic prefix, the alert-level topic); the broker's address and login come from the Supervisor (`services: mqtt:need`). The command `app` reads both and then runs like `run`.
- **Rules** are read from `/homeassistant/air_threat_monitor/rules.yaml`, which is mounted read-only; restart the app after changing them.
- **Login**: the page opens from the Home Assistant sidebar (ingress) and answers the ingress proxy only. The session is kept in the app's `/data/session/` and is excluded from backups, so a restored system asks for a new login.
- **Version**: `version` in `config.yaml` and `__version__` change together; a test compares them.

## Development

```sh
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # bin/ instead of Scripts/ outside Windows
.venv/Scripts/python -m pytest
```
