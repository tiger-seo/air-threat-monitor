import asyncio
from datetime import datetime, timedelta, timezone

from aiohttp.test_utils import TestClient, TestServer
from telethon import errors

from air_threat_monitor import web
from air_threat_monitor.web import Login, create_app


class FakeQr:
    """A QR login whose waits end as queued: an exception is raised, anything else means scanned."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.tokens = 1
        self.timeouts = []

    @property
    def url(self):
        return f"tg://login?token=token{self.tokens}"

    @property
    def expires(self):
        return datetime.now(timezone.utc) + timedelta(seconds=30)

    async def recreate(self):
        self.tokens += 1

    async def wait(self, timeout=None):
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, asyncio.Event):
            await outcome.wait()
        elif isinstance(outcome, BaseException):
            raise outcome


class FakeClient:
    def __init__(self, outcomes, password="secret"):
        self.qr = FakeQr(outcomes)
        self.qr_logins = 0
        self.password = password
        self.attempts = []

    async def qr_login(self):
        self.qr_logins += 1
        return self.qr

    async def sign_in(self, password):
        self.attempts.append(password)
        if password != self.password:
            raise errors.PasswordHashInvalidError(request=None)


async def settle():
    for _ in range(5):
        await asyncio.sleep(0)


def test_no_code_is_requested_until_somebody_opens_the_page():
    async def scenario():
        login = Login()
        client = FakeClient([None])
        task = asyncio.create_task(login.run(client))
        await settle()
        assert (login.state, client.qr_logins) == ("needed", 0)
        login.touch()
        await task
        assert client.qr_logins == 1

    asyncio.run(scenario())


def test_expired_code_is_replaced_while_the_page_is_watched():
    async def scenario():
        login = Login()
        scanned = asyncio.Event()
        client = FakeClient([asyncio.TimeoutError(), scanned])
        login.touch()
        task = asyncio.create_task(login.run(client))
        await settle()
        assert login.state == "qr"
        assert login.qr_url == "tg://login?token=token2"
        assert all(10 <= timeout <= 60 for timeout in client.qr.timeouts)
        scanned.set()
        await task

    asyncio.run(scenario())


def test_codes_stop_when_the_page_is_closed():
    async def scenario():
        clock = [0.0]
        login = Login(clock=lambda: clock[0])
        client = FakeClient([asyncio.TimeoutError(), asyncio.TimeoutError(), None])
        login.touch()

        async def expire(timeout=None):
            # The code runs out long after the page was last asked for.
            clock[0] += web.WATCH_SECONDS + 1
            raise asyncio.TimeoutError()

        client.qr.wait = expire
        task = asyncio.create_task(login.run(client))
        await settle()
        assert (login.state, login.qr_url, client.qr.tokens) == ("needed", None, 1)
        task.cancel()

    asyncio.run(scenario())


def test_two_step_verification_asks_for_the_password_until_it_is_right():
    async def scenario():
        login = Login()
        client = FakeClient([errors.SessionPasswordNeededError(request=None)])
        login.touch()
        task = asyncio.create_task(login.run(client))
        await settle()
        assert (login.state, login.qr_url) == ("password", None)
        assert login.submit_password("wrong")
        await settle()
        assert (login.state, login.error) == ("password", "Неправильний пароль")
        assert not task.done()
        assert login.submit_password("secret")
        await task
        assert client.attempts == ["wrong", "secret"]
        assert login.error is None

    asyncio.run(scenario())


def test_password_is_refused_when_none_is_awaited():
    assert Login().submit_password("secret") is False


def test_network_error_starts_over_with_a_new_code(monkeypatch):
    async def scenario():
        monkeypatch.setattr(web, "RETRY_SECONDS", 0)
        login = Login()
        client = FakeClient([ConnectionError("down"), None])
        login.touch()
        await login.run(client)
        assert client.qr_logins == 2

    asyncio.run(scenario())


def with_page(login, scenario, status=lambda: [("Версія", "0.1.0")]):
    async def run():
        async with TestClient(TestServer(create_app(login, status))) as client:
            await scenario(client)

    asyncio.run(run())


def test_state_shows_the_user_and_the_gateway():
    login = Login()
    login.logged_in("Тест")

    async def scenario(client):
        data = await (await client.get("/api/state")).json()
        assert data == {"login": "ok", "user": "Тест", "qr": None, "error": None, "gateway": [["Версія", "0.1.0"]]}

    with_page(login, scenario)


def test_state_carries_the_code_as_svg_and_marks_the_page_watched():
    login = Login()
    login.state, login.qr_url = "qr", "tg://login?token=abc"

    async def scenario(client):
        data = await (await client.get("/api/state")).json()
        assert data["qr"].startswith("<svg")
        assert login._watched()

    with_page(login, scenario)


def test_page_uses_relative_addresses_only():
    # Behind Home Assistant's ingress the page lives under a path it does not know.
    async def scenario(client):
        response = await client.get("/")
        text = await response.text()
        assert response.content_type == "text/html"
        assert 'fetch("api/state"' in text and 'fetch("api/password"' in text
        assert 'fetch("/' not in text and 'src="' not in text and 'href="' not in text

    with_page(Login(), scenario)


def test_password_reaches_the_login_only_as_json_and_only_when_awaited():
    login = Login()

    async def scenario(client):
        assert (await client.post("/api/password", json={"password": "x"})).status == 409
        login._password = asyncio.get_running_loop().create_future()
        assert (await client.post("/api/password", data={"password": "x"})).status == 415
        assert (await client.post("/api/password", json={"password": ""})).status == 400
        assert (await client.post("/api/password", json=["x"])).status == 400
        assert not login._password.done()
        assert (await client.post("/api/password", json={"password": "secret"})).status == 204
        assert login._password.result() == "secret"

    with_page(login, scenario)
