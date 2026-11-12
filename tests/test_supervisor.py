import asyncio
import json
import re
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from air_threat_monitor import __version__, supervisor
from air_threat_monitor.settings import Settings, SettingsError
from air_threat_monitor.web import Login, create_app

ROOT = Path(__file__).parent.parent
OPTIONS = {
    "api_id": 12345,
    "api_hash": "hash",
    "rules": "/homeassistant/air_threat_monitor/rules.yaml",
    "topic_prefix": "air_threat",
    "alert_level_topic": "air_alert/kyiv/level",
}
MQTT = {"host": "core-mosquitto", "port": 1883, "username": "addons", "password": "secret", "ssl": False}


def test_options_and_broker_become_settings():
    settings = Settings.from_env(supervisor.environment(OPTIONS, MQTT))
    assert (settings.api_id, settings.api_hash) == (12345, "hash")
    assert (settings.mqtt_host, settings.mqtt_port) == ("core-mosquitto", 1883)
    assert (settings.mqtt_username, settings.mqtt_password) == ("addons", "secret")
    assert settings.rules == Path("/homeassistant/air_threat_monitor/rules.yaml")
    assert settings.alert_level_topic == "air_alert/kyiv/level"
    assert settings.session == Path("/data/session/telegram")
    # The page listens on the container's address, for the ingress proxy only.
    assert (settings.web_host, settings.web_port, settings.web_allow) == ("0.0.0.0", 8099, ("172.30.32.2",))


def test_unset_options_fall_back_to_the_defaults_or_are_reported():
    env = supervisor.environment({**OPTIONS, "alert_level_topic": "", "api_hash": None}, MQTT)
    assert "AIR_THREAT_ALERT_LEVEL_TOPIC" not in env
    with pytest.raises(SettingsError, match="AIR_THREAT_API_HASH"):
        Settings.from_env(env)


def test_broker_with_tls_is_refused():
    with pytest.raises(SettingsError, match="TLS"):
        supervisor.environment(OPTIONS, {**MQTT, "ssl": True})


def test_options_file_is_read(tmp_path):
    path = tmp_path / "options.json"
    path.write_text(json.dumps(OPTIONS), encoding="utf-8")
    assert supervisor.read_options(path) == OPTIONS
    with pytest.raises(SettingsError):
        supervisor.read_options(tmp_path / "missing.json")


def test_broker_is_asked_from_the_supervisor_with_the_app_token():
    seen = {}

    async def service(request: web.Request) -> web.Response:
        seen["authorization"] = request.headers.get("Authorization")
        return web.json_response({"result": "ok", "data": MQTT})

    async def empty(request: web.Request) -> web.Response:
        return web.json_response({"result": "ok", "data": {}})

    async def scenario():
        app = web.Application()
        app.add_routes([web.get("/services/mqtt", service), web.get("/none", empty)])
        async with TestServer(app) as server:
            fetch = lambda path: asyncio.to_thread(supervisor.fetch_mqtt, "token", str(server.make_url(path)))
            assert await fetch("/services/mqtt") == MQTT
            assert seen["authorization"] == "Bearer token"
            with pytest.raises(SettingsError, match="Mosquitto"):
                await fetch("/none")
            with pytest.raises(SettingsError):
                await fetch("/missing")

    asyncio.run(scenario())


def test_page_answers_only_the_allowed_address():
    async def scenario():
        async with TestClient(TestServer(create_app(Login(), list, allow=("172.30.32.2",)))) as client:
            assert (await client.get("/")).status == 403
            assert (await client.get("/api/state")).status == 403
        async with TestClient(TestServer(create_app(Login(), list, allow=("127.0.0.1",)))) as client:
            assert (await client.get("/")).status == 200

    asyncio.run(scenario())


def test_app_definition_matches_the_code():
    config = (ROOT / "config.yaml").read_text(encoding="utf-8")
    assert re.search(r'^version: "(.+?)"', config, re.M).group(1) == __version__
    assert f"ingress_port: {supervisor.WEB_PORT}" in config
    assert "mqtt:need" in config
    # Every option the code reads has a schema entry, and the other way round.
    schema = set(re.findall(r"^  (\w+):", config.split("schema:")[1], re.M))
    assert schema == set(OPTIONS)
