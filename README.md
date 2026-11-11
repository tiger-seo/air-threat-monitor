# telegram-mqtt-gateway

Listens to configured Telegram channels and chats with a user-account session, matches each message against rules and publishes the results to MQTT. What to do with an event is decided by the consumer (Home Assistant).

State: under construction. Rule matching and text cleaning exist; the Telegram client, the MQTT publisher, the login page and the Home Assistant app packaging do not yet.

## Rules

See [rules.example.yaml](rules.example.yaml). A rule is a Python regular expression with a `kind`; every match gives one event, and named groups become its `fields`. Before matching and publishing, emoji are removed from the message text and runs of spaces are collapsed, so rules are written for plain text.

## Development

```sh
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # bin/ instead of Scripts/ outside Windows
.venv/Scripts/python -m pytest
```
