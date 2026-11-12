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

        api_id = number("TMG_API_ID", required("TMG_API_ID"))
        prefix = (env.get("TMG_TOPIC_PREFIX", "").strip() or "telegram").strip("/")
        if not prefix or any(char in prefix for char in "+#"):
            raise SettingsError("TMG_TOPIC_PREFIX: must be a topic without wildcards")
        return cls(
            api_id=api_id,
            api_hash=required("TMG_API_HASH"),
            session=Path(env.get("TMG_SESSION", "").strip() or "data/session/gateway"),
            rules=Path(env.get("TMG_RULES", "").strip() or "rules.yaml"),
            mqtt_host=env.get("TMG_MQTT_HOST", "").strip() or "localhost",
            mqtt_port=number("TMG_MQTT_PORT", "1883"),
            mqtt_username=env.get("TMG_MQTT_USERNAME", "").strip() or None,
            mqtt_password=env.get("TMG_MQTT_PASSWORD", "") or None,
            topic_prefix=prefix,
            stale_after=number("TMG_STALE_AFTER", "120", float),
        )
