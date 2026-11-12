"""Settings of the process, read from environment variables.

The rules file says what to listen to; these say how to reach Telegram and
the broker, and they differ between the laptop and the Home Assistant app.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class SettingsError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    api_id: int
    api_hash: str
    session: Path  # Telethon adds ".session" to it
    rules: Path
    mqtt_host: str
    mqtt_port: int
    mqtt_username: str | None
    mqtt_password: str | None
    topic_prefix: str
    stale_after: float
    # Topic where the consumer publishes the air-alert level: red, yellow or none.
    alert_level_topic: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env

        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise SettingsError(f"{name} is not set")
            return value

        def number(name: str, default: str, kind=int):
            raw = env.get(name, "").strip() or default
            try:
                return kind(raw)
            except ValueError:
                raise SettingsError(f"{name}: expected a number, got '{raw}'") from None

        api_id = number("AIR_THREAT_API_ID", required("AIR_THREAT_API_ID"))
        prefix = (env.get("AIR_THREAT_TOPIC_PREFIX", "").strip() or "air_threat").strip("/")
        if not prefix or any(char in prefix for char in "+#"):
            raise SettingsError("AIR_THREAT_TOPIC_PREFIX: must be a topic without wildcards")
        return cls(
            api_id=api_id,
            api_hash=required("AIR_THREAT_API_HASH"),
            session=Path(env.get("AIR_THREAT_SESSION", "").strip() or "data/session/telegram"),
            rules=Path(env.get("AIR_THREAT_RULES", "").strip() or "rules.yaml"),
            mqtt_host=env.get("AIR_THREAT_MQTT_HOST", "").strip() or "localhost",
            mqtt_port=number("AIR_THREAT_MQTT_PORT", "1883"),
            mqtt_username=env.get("AIR_THREAT_MQTT_USERNAME", "").strip() or None,
            mqtt_password=env.get("AIR_THREAT_MQTT_PASSWORD", "") or None,
            topic_prefix=prefix,
            stale_after=number("AIR_THREAT_STALE_AFTER", "120", float),
            alert_level_topic=env.get("AIR_THREAT_ALERT_LEVEL_TOPIC", "").strip() or None,
        )
