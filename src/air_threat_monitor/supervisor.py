"""Settings when the monitor runs as a Home Assistant app.

The Supervisor writes the app's options to /data/options.json and tells where
the MQTT broker is; both are turned into the same variables a terminal run
reads from the environment, so the rest of the program does not know the
difference.
"""

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from .settings import SettingsError

OPTIONS = Path("/data/options.json")
MQTT_SERVICE = "http://supervisor/services/mqtt"
# The only address Home Assistant's ingress reaches the page from.
INGRESS_PROXY = "172.30.32.2"
SESSION = "/data/session/telegram"
WEB_PORT = 8099


def read_options(path: Path = OPTIONS) -> dict:
    try:
        options = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SettingsError(f"{path}: cannot read the app's options: {error}") from None
    if not isinstance(options, dict):
        raise SettingsError(f"{path}: expected a mapping of options")
    return options


def fetch_mqtt(token: str | None = None, url: str = MQTT_SERVICE) -> dict:
    """Ask the Supervisor for the broker; the app must list `mqtt` under `services`."""
    token = token or os.environ.get("SUPERVISOR_TOKEN", "")
    if not token:
        raise SettingsError("SUPERVISOR_TOKEN is not set: this command runs only as a Home Assistant app")
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.load(response)
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise SettingsError(f"the Supervisor gave no MQTT broker ({url}): {error}") from None
    # The answer is wrapped as {"result": "ok", "data": {...}}.
    data = body.get("data", body) if isinstance(body, dict) else None
    if not isinstance(data, dict) or not data.get("host"):
        raise SettingsError("the Supervisor knows no MQTT broker: install and start the Mosquitto app")
    return data


def environment(options: dict, mqtt: dict) -> dict[str, str]:
    """The variables `Settings.from_env` reads, for a run inside the app's container."""
    if mqtt.get("ssl"):
        raise SettingsError("the MQTT broker asks for TLS, which the monitor does not speak yet")
    values = {
        "AIR_THREAT_API_ID": options.get("api_id"),
        "AIR_THREAT_API_HASH": options.get("api_hash"),
        "AIR_THREAT_RULES": options.get("rules"),
        "AIR_THREAT_TOPIC_PREFIX": options.get("topic_prefix"),
        "AIR_THREAT_ALERT_LEVEL_TOPIC": options.get("alert_level_topic"),
        "AIR_THREAT_SESSION": SESSION,
        "AIR_THREAT_MQTT_HOST": mqtt.get("host"),
        "AIR_THREAT_MQTT_PORT": mqtt.get("port"),
        "AIR_THREAT_MQTT_USERNAME": mqtt.get("username"),
        "AIR_THREAT_MQTT_PASSWORD": mqtt.get("password"),
        # The container has no loopback visitor: the page is reached through
        # ingress only, and nobody else may see the QR code.
        "AIR_THREAT_WEB_HOST": "0.0.0.0",
        "AIR_THREAT_WEB_PORT": WEB_PORT,
        "AIR_THREAT_WEB_ALLOW": INGRESS_PROXY,
    }
    return {name: str(value) for name, value in values.items() if value not in (None, "")}
