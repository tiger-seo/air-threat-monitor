"""MQTT side of the gateway: retained state topics, message/event publishing, inputs."""

import json
import logging
import threading
from collections.abc import Callable

import paho.mqtt.client as paho

log = logging.getLogger(__name__)

QOS = 1
# Where the Telegram source publishes under the prefix: its login state and its chats.
TELEGRAM = "source/telegram"


def _encode(payload) -> str:
    return payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)


class MqttPublisher:
    """Publishes under one topic prefix; reconnects on its own.

    Messages and events are dropped while the broker is unreachable instead of
    being queued: an event delivered minutes late would announce a threat that
    is over. Retained state is kept and published again on every connect.
    """

    def __init__(
        self,
        host: str,
        port: int = 1883,
        username: str | None = None,
        password: str | None = None,
        prefix: str = "air_threat",
        client_id: str = "air-threat-monitor",
    ):
        self._host = host
        self._port = port
        self._prefix = prefix.strip("/")
        self._retained: dict[str, str] = {}
        self._subscriptions: dict[str, Callable[[str], None]] = {}
        self._lock = threading.Lock()
        self._client = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id=client_id)
        if username:
            self._client.username_pw_set(username, password)
        self._client.will_set(self._topic("status"), "offline", qos=QOS, retain=True)
        self._client.reconnect_delay_set(min_delay=1, max_delay=30)
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message

    def start(self) -> None:
        self._client.connect_async(self._host, self._port, keepalive=30)
        self._client.loop_start()

    def stop(self) -> None:
        if self._client.is_connected():
            self._client.publish(self._topic("status"), "offline", qos=QOS, retain=True).wait_for_publish(5)
        self._client.disconnect()
        self._client.loop_stop()

    def set_login(self, state: str) -> None:
        """Remember and publish the login state: "ok" or "needed"."""
        self.set_state(f"{TELEGRAM}/login", state)

    def set_state(self, suffix: str, payload) -> None:
        """Publish a retained value under the prefix and keep it for reconnects."""
        encoded = _encode(payload)
        with self._lock:
            self._retained[suffix] = encoded
        if self._client.is_connected():
            self._client.publish(self._topic(suffix), encoded, qos=QOS, retain=True)

    def publish(self, chat: str, kind: str, payload: dict) -> bool:
        """Publish a message or an event of a chat; False when it was dropped."""
        return self.publish_event(f"{TELEGRAM}/{chat}/{kind}", payload)

    def publish_event(self, suffix: str, payload: dict) -> bool:
        topic = self._topic(suffix)
        if not self._client.is_connected():
            log.warning("broker is not connected, dropped %s id=%s", topic, payload.get("id"))
            return False
        self._client.publish(topic, _encode(payload), qos=QOS, retain=False)
        return True

    def subscribe(self, topic: str, callback: Callable[[str], None]) -> None:
        """Listen to a topic outside the prefix; the callback runs on the MQTT thread."""
        with self._lock:
            self._subscriptions[topic] = callback
        if self._client.is_connected():
            self._client.subscribe(topic, qos=QOS)

    def _topic(self, suffix: str) -> str:
        return f"{self._prefix}/{suffix}"

    def _on_connect(self, client, userdata, flags, reason_code, properties) -> None:
        if reason_code.is_failure:
            log.error("broker refused the connection: %s", reason_code)
            return
        log.info("connected to the broker at %s:%s", self._host, self._port)
        client.publish(self._topic("status"), "online", qos=QOS, retain=True)
        with self._lock:
            retained = dict(self._retained)
            topics = list(self._subscriptions)
        for suffix, payload in retained.items():
            client.publish(self._topic(suffix), payload, qos=QOS, retain=True)
        for topic in topics:
            client.subscribe(topic, qos=QOS)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties) -> None:
        if reason_code.is_failure:
            log.warning("lost the broker connection: %s", reason_code)

    def _on_message(self, client, userdata, message) -> None:
        with self._lock:
            callback = self._subscriptions.get(message.topic)
        if callback is not None:
            callback(message.payload.decode("utf-8", errors="replace"))


class DryRunPublisher:
    """Stands in for the broker: prints what would be published."""

    def __init__(self, prefix: str = "air_threat"):
        self._prefix = prefix.strip("/")

    def start(self) -> None:
        print(f"{self._prefix}/status online", flush=True)

    def stop(self) -> None:
        print(f"{self._prefix}/status offline", flush=True)

    def set_login(self, state: str) -> None:
        self.set_state(f"{TELEGRAM}/login", state)

    def set_state(self, suffix: str, payload) -> None:
        print(f"{self._prefix}/{suffix} (retained) {_encode(payload)}", flush=True)

    def publish(self, chat: str, kind: str, payload: dict) -> bool:
        return self.publish_event(f"{TELEGRAM}/{chat}/{kind}", payload)

    def publish_event(self, suffix: str, payload: dict) -> bool:
        print(f"{self._prefix}/{suffix} {_encode(payload)}", flush=True)
        return True

    def subscribe(self, topic: str, callback: Callable[[str], None]) -> None:
        print(f"(would subscribe to {topic})", flush=True)
