"""Login and status page.

The page is the only way to create the session where the gateway runs as an
app: it shows a QR code to scan in Telegram and asks for the two-step
verification password. It uses relative addresses only, so it works behind
Home Assistant's ingress, whatever path that serves it under.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timezone

import qrcode
import qrcode.image.svg
from aiohttp import web
from telethon import errors

log = logging.getLogger(__name__)

# A QR code is requested from Telegram only while somebody looks at the page:
# a gateway left for days without a session must not ask for a token every 30 s.
WATCH_SECONDS = 15
RETRY_SECONDS = 5


class Login:
    """The login state the page shows, and the QR login it drives.

    States: "starting" (not known yet), "ok", "needed" (no session, nobody is
    looking at the page), "qr" (a code is shown), "password" (the code was
    scanned, the account has two-step verification).
    """

    def __init__(self, clock: Callable[[], float] | None = None):
        self.state = "starting"
        self.user: str | None = None
        self.qr_url: str | None = None
        self.error: str | None = None
        self._clock = clock
        self._watched_at: float | None = None
        self._wake = asyncio.Event()
        self._password: asyncio.Future | None = None

    def _now(self) -> float:
        return self._clock() if self._clock is not None else asyncio.get_running_loop().time()

    def touch(self) -> None:
        """The page was asked for: somebody is looking at it."""
        self._watched_at = self._now()
        self._wake.set()

    def _watched(self) -> bool:
        return self._watched_at is not None and self._now() - self._watched_at <= WATCH_SECONDS

    def logged_in(self, user: str) -> None:
        self.state, self.user, self.qr_url, self.error = "ok", user, None, None

    def lost(self, reason: str) -> None:
        self.state, self.user, self.qr_url, self.error = "needed", None, None, reason

    def submit_password(self, password: str) -> bool:
        """Hand over the password typed on the page; False when none is awaited."""
        if self._password is None or self._password.done():
            return False
        self._password.set_result(password)
        return True

    async def run(self, client) -> None:
        """Log the client in by QR code; returns once the session is authorised."""
        qr = None
        while True:
            if not self._watched():
                self.state, self.qr_url = "needed", None
                self._wake.clear()
                await self._wake.wait()
                continue
            try:
                if qr is None:
                    qr = await client.qr_login()
                else:
                    await qr.recreate()
                self.state, self.qr_url = "qr", qr.url
                # The code lives about 30 s. The bounds keep a wrong clock from
                # asking for codes in a tight loop or showing a dead one for long.
                remaining = (qr.expires - datetime.now(timezone.utc)).total_seconds()
                await qr.wait(timeout=min(max(remaining, 10), 60))
                return
            except asyncio.TimeoutError:
                continue
            except errors.SessionPasswordNeededError:
                await self._sign_in_with_password(client)
                return
            except errors.FloodWaitError as error:
                log.warning("login: Telegram asked to wait %s s", error.seconds)
                self.state, self.qr_url = "needed", None
                self.error = f"Telegram просить зачекати {error.seconds} с"
                await asyncio.sleep(error.seconds)
                self.error = None
            except (ConnectionError, OSError, errors.RPCError) as error:
                log.warning("login: failed, will retry: %r", error)
                self.error = f"Помилка: {error}"
                qr = None
                await asyncio.sleep(RETRY_SECONDS)

    async def _sign_in_with_password(self, client) -> None:
        self.state, self.qr_url, self.error = "password", None, None
        while True:
            self._password = asyncio.get_running_loop().create_future()
            try:
                password = await self._password
            finally:
                self._password = None
            try:
                await client.sign_in(password=password)
                self.error = None
                return
            except errors.PasswordHashInvalidError:
                self.error = "Неправильний пароль"
            except errors.FloodWaitError as error:
                log.warning("login: Telegram asked to wait %s s", error.seconds)
                self.error = f"Забагато спроб; Telegram просить зачекати {error.seconds} с"


def qr_svg(url: str) -> str:
    image = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, border=2, box_size=10)
    return image.to_string(encoding="unicode")


def create_app(login: Login, status: Callable[[], dict]) -> web.Application:
    """`status` gives what the page shows about the gateway besides the login."""
    cached: tuple[str, str] | None = None

    async def page(request: web.Request) -> web.Response:
        return web.Response(text=PAGE, content_type="text/html", headers={"Cache-Control": "no-store"})

    async def state(request: web.Request) -> web.Response:
        nonlocal cached
        login.touch()
        svg = None
        if login.qr_url:
            if cached is None or cached[0] != login.qr_url:
                cached = (login.qr_url, qr_svg(login.qr_url))
            svg = cached[1]
        return web.json_response(
            {"login": login.state, "user": login.user, "qr": svg, "error": login.error, "gateway": status()},
            headers={"Cache-Control": "no-store"},
        )

    async def password(request: web.Request) -> web.Response:
        # Only JSON: a form on another site cannot send it without the
        # browser asking this server first, and it gets no permission.
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        try:
            value = (await request.json())["password"]
        except (ValueError, KeyError, TypeError):
            raise web.HTTPBadRequest() from None
        if not isinstance(value, str) or not value:
            raise web.HTTPBadRequest()
        if not login.submit_password(value):
            raise web.HTTPConflict()
        return web.Response(status=204)

    app = web.Application(client_max_size=4096)
    app.add_routes([web.get("/", page), web.get("/api/state", state), web.post("/api/password", password)])
    return app


async def serve(app: web.Application, host: str, port: int) -> web.AppRunner:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    try:
        await web.TCPSite(runner, host, port).start()
    except BaseException:
        await runner.cleanup()
        raise
    log.info("login and status page: http://%s:%s/", host, port)
    return runner


PAGE = """<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Монітор повітряних загроз</title>
<style>
  :root { color-scheme: light dark; --bg: #f6f7f9; --card: #fff; --text: #1c1e21; --muted: #667085;
          --line: #e3e6ea; --ok: #1a7f37; --warn: #b54708; --accent: #2481cc; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #111418; --card: #1b1f24; --text: #e6e8eb; --muted: #98a2b3;
            --line: #2c323a; --ok: #4ac26b; --warn: #f79009; --accent: #5aa9e6; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--text);
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 420px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 0 0 16px; }
  section { background: var(--card); border: 1px solid var(--line); border-radius: 12px;
            padding: 20px; margin-bottom: 16px; }
  .state { font-weight: 600; margin: 0 0 4px; }
  .ok { color: var(--ok); } .warn { color: var(--warn); }
  p { margin: 0 0 12px; } p:last-child { margin-bottom: 0; }
  .muted { color: var(--muted); font-size: 14px; }
  #qr { background: #fff; border-radius: 8px; padding: 8px; margin: 12px auto; max-width: 280px; }
  #qr svg { display: block; width: 100%; height: auto; }
  form { display: flex; gap: 8px; margin-top: 12px; }
  input { flex: 1; min-width: 0; padding: 10px 12px; font: inherit; color: inherit; background: var(--bg);
          border: 1px solid var(--line); border-radius: 8px; }
  button { padding: 10px 16px; font: inherit; font-weight: 600; color: #fff; background: var(--accent);
           border: 0; border-radius: 8px; cursor: pointer; }
  button:disabled { opacity: .6; cursor: default; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; margin: 0; font-size: 14px; }
  dt { color: var(--muted); } dd { margin: 0; text-align: right; overflow-wrap: anywhere; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
<main>
  <h1>Монітор повітряних загроз</h1>
  <section>
    <p class="state" id="state">Завантаження…</p>
    <p class="muted" id="hint" hidden></p>
    <div id="qr" hidden></div>
    <form id="password" hidden>
      <input type="password" id="value" autocomplete="current-password" placeholder="Пароль" required>
      <button id="send">Увійти</button>
    </form>
    <p class="warn" id="error" hidden></p>
  </section>
  <section id="gateway" hidden><dl id="facts"></dl></section>
</main>
<script>
const el = id => document.getElementById(id);
const show = (node, text) => { node.hidden = !text; if (text) node.textContent = text; };
const HINTS = {
  needed: "Готую QR-код…",
  qr: "Telegram на телефоні → Налаштування → Пристрої → Підключити пристрій, і наведіть камеру на код.",
  password: "Код прийнято. Введіть пароль двоетапної перевірки Telegram.",
};
let shownQr = null;

function render(data) {
  const ok = data.login === "ok";
  const state = el("state");
  state.textContent = ok ? "Увійшов як " + data.user
    : data.login === "starting" ? "Запуск…" : "Потрібен вхід у Telegram";
  state.className = "state " + (ok ? "ok" : data.login === "starting" ? "" : "warn");
  show(el("hint"), HINTS[data.login]);
  if (data.qr !== shownQr) { el("qr").innerHTML = data.qr || ""; shownQr = data.qr; }
  el("qr").hidden = !data.qr;
  el("password").hidden = data.login !== "password";
  show(el("error"), data.error);
  const facts = el("facts");
  facts.replaceChildren();
  for (const [name, value] of data.gateway || []) {
    const dt = document.createElement("dt"), dd = document.createElement("dd");
    dt.textContent = name; dd.textContent = value;
    facts.append(dt, dd);
  }
  el("gateway").hidden = !facts.children.length;
}

async function refresh() {
  try {
    const response = await fetch("api/state", {cache: "no-store"});
    if (!response.ok) throw new Error(response.status);
    render(await response.json());
  } catch (error) {
    el("state").textContent = "Монітор не відповідає";
    el("state").className = "state warn";
    for (const id of ["hint", "qr", "password", "error", "gateway"]) el(id).hidden = true;
    shownQr = null;
  }
}

el("password").addEventListener("submit", async event => {
  event.preventDefault();
  el("send").disabled = true;
  try {
    await fetch("api/password", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({password: el("value").value}),
    });
    el("value").value = "";
    await new Promise(resolve => setTimeout(resolve, 1500));
    await refresh();
  } finally {
    el("send").disabled = false;
  }
});

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
