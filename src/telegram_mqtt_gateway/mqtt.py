"""MQTT side of the gateway: retained state topics and message/event publishing."""

import json
import logging
import threading

import paho.mqtt.client as paho

log = logging.getLogger(__name__)

QOS = 1


class MqttPublisher:
    """Publishes under one topic prefix; reconnects on its own.

    Messages and events are dropped while the broker is unreachable instead of
    being queued: an event delivered minutes late would announce a threat that
    is over.
    """

    def __init__(
        self,
        host: str,
        port: int = 1883,
        username: str | None = None,
        password: str | None = None,
        prefix: str = "telegram",
        client_id: str = "telegram-mqtt-gateway",
    ):
        self._host = host
        self._port = port
        self._prefix = prefix.strip("/")
        self._login: str | None = None
        self._lock = threading.Lock()
        self._client = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id=client_id)
        if username:
            self._client.username_pw_set(username, password)
        self._client.will_set(self._topic("status"), "offline", qos=QOS, retain=True)
        self._client.reconnect_delay_set(min_delay=1, max_delay=30)
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect

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
        with self._lock:
            self._login = state
        if self._client.is_connected():
            self._client.publish(self._topic("login"), state, qos=QOS, retain=True)

    def publish(self, chat: str, kind: str, payload: dict) -> bool:
        """Publish a message or an event of a chat; False when it was dropped."""
        topic = self._topic(f"{chat}/{kind}")
        if not self._client.is_connected():
            log.warning("broker is not connected, dropped %s id=%s", topic, payload.get("id"))
            return False
        self._client.publish(topic, json.dumps(payload, ensure_ascii=False), qos=QOS, retain=False)
        return True

    def _topic(self, suffix: str) -> str:
        return f"{self._prefix}/{suffix}"

    def _on_connect(self, client, userdata, flags, reason_code, properties) -> None:
        if reason_code.is_failure:
            log.error("broker refused the connection: %s", reason_code)
            return
        log.info("connected to the broker at %s:%s", self._host, self._port)
        client.publish(self._topic("status"), "online", qos=QOS, retain=True)
        with self._lock:
            login = self._login
        if login is not None:
            client.publish(self._topic("login"), login, qos=QOS, retain=True)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties) -> None:
        if reason_code.is_failure:
            log.warning("lost the broker connection: %s", reason_code)


class DryRunPublisher:
    """Stands in for the broker: prints what would be published."""

    def __init__(self, prefix: str = "telegram"):
        self._prefix = prefix.strip("/")

    def start(self) -> None:
        print(f"{self._prefix}/status online", flush=True)

    def stop(self) -> None:
        print(f"{self._prefix}/status offline", flush=True)

    def set_login(self, state: str) -> None:
        print(f"{self._prefix}/login {state}", flush=True)

    def publish(self, chat: str, kind: str, payload: dict) -> bool:
        print(f"{self._prefix}/{chat}/{kind} {json.dumps(payload, ensure_ascii=False)}", flush=True)
        return True
