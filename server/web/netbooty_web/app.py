"""NetBooty web app: pairing, approving PCs and choosing what they boot.

Standard library only. Configure with environment variables:

    NETBOOTY_DATA       data directory shared with the responder (default /var/lib/netbooty)
    NETBOOTY_PASSWORD   login password (a random one is generated and logged if unset)
    NETBOOTY_API_TOKEN  bearer token for the JSON API (optional; the API also accepts a login session)
    NETBOOTY_WEB_BIND   listen address (default 0.0.0.0)
    NETBOOTY_WEB_PORT   listen port (default 8470)
    NETBOOTY_PING_SECS  how often to ping each PC for its power status (default 15)
    NETBOOTY_WOL_ADDR   where to send Wake-on-LAN packets (default 255.255.255.255:9)
"""

from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import sys
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .power import WOL_PORT, Monitor, make_pinger
from .store import StateError, Store

SESSION_SECS = 12 * 3600
COOKIE = "netbooty_session"


class Config:
    def __init__(self, data: str, password: str, api_token: str | None, monitor: Monitor | None = None):
        self.store = Store(data)
        self.password = password
        self.api_token = api_token
        self.secret = secrets.token_bytes(32)  # sessions end when the app restarts
        # Pings only once started (in main()).
        self.monitor = monitor or Monitor(self.store)

    def pcs(self) -> list[dict]:
        """`Store.pcs()` plus each PC's power status."""
        out = []
        for pc in self.store.pcs():
            power = self.monitor.snapshot(pc)
            power["summary"] = power_summary(power, pc)
            out.append({**pc, "power": power})
        return out

    def session(self) -> str:
        expiry = str(int(time.time()) + SESSION_SECS)
        sig = hmac.new(self.secret, expiry.encode(), hashlib.sha256).hexdigest()
        return f"{expiry}.{sig}"

    def valid_session(self, value: str) -> bool:
        expiry, _, sig = value.partition(".")
        good = hmac.new(self.secret, expiry.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good) and expiry.isdigit() and int(expiry) > time.time()


def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def ago(ts) -> str:
    if not ts:
        return "never"
    d = int(time.time() - ts)
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


def power_summary(p: dict, pc: dict) -> str:
    match p["state"]:
        case "unavailable":
            return f"Power status unavailable: {p.get('error')}"
        case "waking":
            return f"◌ Waking… (sent {ago(p['since'])})"
        case "off":
            text = f"○ Off since {ago(p['since'])}"
            if p["wake_failed"]:
                text += (" · did not wake: check Wake-on-LAN in the BIOS (ErP off) and the OS's "
                         "network card settings")
            return text
        case "on":
            parts = ["● On"]
            if p["running"] is None:
                parts.append("running: unknown (did not ask the server this boot)")
            elif p["running"]:
                parts.append(f"probably running {p['running']} (asked at boot {ago(p['asked_at'])})")
            else:
                parts.append(f"probably running its own default (asked at boot {ago(p['asked_at'])})")
            if p["os_hint"]:
                parts.append(f"replies like {p['os_hint']} (TTL {p['ttl']})")
            return " · ".join(parts)
    if not pc.get("from"):
        return "Power: unknown until the PC has asked the server once"
    return "Power: checking…"


# Refreshes the power lines and wake forms without reloading the page.
POWER_SCRIPT = """<script>
setInterval(async () => {
  try {
    const r = await fetch('/api/state');
    if (!r.ok) return;
    for (const pc of (await r.json()).pcs) {
      const line = document.getElementById('power-' + pc.id);
      if (line) line.textContent = pc.power.summary;
      const wake = document.getElementById('wake-' + pc.id);
      if (wake) wake.hidden = pc.power.state === 'on';
    }
  } catch (e) {}
}, 10000);
</script>"""


STYLE = """
:root { --bg:#fff; --fg:#1b1b1b; --muted:#666; --line:#ddd; --accent:#2457c5; --card:#f7f7f8; }
@media (prefers-color-scheme: dark) { :root { --bg:#141416; --fg:#e8e8ea; --muted:#9a9aa2; --line:#2c2c31;
  --accent:#7aa2ff; --card:#1c1c20; } }
* { box-sizing:border-box } body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.45 system-ui, sans-serif } main { max-width:900px; margin:0 auto; padding:16px }
h1 { font-size:20px } h2 { font-size:16px; margin-top:28px } .muted { color:var(--muted) }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin:10px 0 }
.row { display:flex; flex-wrap:wrap; gap:8px; align-items:center }
input, select, button { font:inherit; padding:5px 8px; border:1px solid var(--line); border-radius:6px;
  background:var(--bg); color:var(--fg) } button { cursor:pointer } button.primary { background:var(--accent);
  color:#fff; border-color:var(--accent) } code, .code { font-family:ui-monospace, monospace; font-size:13px;
  word-break:break-all } .err { color:#c0392b } form { display:inline } header { display:flex;
  justify-content:space-between; align-items:center } [hidden] { display:none !important }
"""


def page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>"
    ).encode()


def login_page(error: str = "") -> bytes:
    err = f"<p class=err>{esc(error)}</p>" if error else ""
    return page("NetBooty", f"""<h1>NetBooty</h1>{err}
<form method=post action=/login class=row><input type=password name=password placeholder=Password autofocus>
<button class=primary>Log in</button></form>""")


def pairing_code(pub: dict, host: str | None) -> str | None:
    """The responder's pairing code, pointing at the address this page was
    reached at when the responder only auto-detected its own address (which
    can be a container-internal one). An explicitly configured address wins."""
    code = pub.get("pairing_code")
    if not code or pub.get("server_ip_configured"):
        return code
    hostname = (host or "").rsplit(":", 1)[0]
    try:
        ip = ipaddress.IPv4Address(hostname)
    except ValueError:
        return code
    if ip.is_loopback or ip.is_unspecified:
        return code
    parts = code.split(":")
    return ":".join(parts[:4] + [str(ip)])


def dashboard(cfg: Config, error: str = "", host: str | None = None) -> bytes:
    st = cfg.store
    pub = st.public()
    parts = ["<header><h1>NetBooty</h1><form method=post action=/logout><button>Log out</button></form></header>"]
    if error:
        parts.append(f"<p class=err>{esc(error)}</p>")

    parts.append("<h2>PCs</h2>")
    pcs = cfg.pcs()
    if not pcs:
        parts.append("<p class=muted>No PCs approved yet. Pair a PC (below), then approve it under New PCs.</p>")
    for pc in pcs:
        opts = "".join(
            f"<option value='{esc(t)}' {'selected' if t == pc['choice'] else ''}>{esc(t)}</option>"
            for t in pc["targets"]
        )
        none_sel = "selected" if pc["choice"] is None else ""
        once_buttons = "".join(
            f"<form method=post action='/pc/{pc['id']}/once'><input type=hidden name=target value='{esc(t)}'>"
            f"<button>{esc(t)} once</button></form>"
            for t in pc["targets"]
        )
        once = (f"<span>next boot: <b>{esc(pc['once'])}</b></span>"
                f"<form method=post action='/pc/{pc['id']}/once'><button>cancel</button></form>") if pc["once"] else ""
        wake_opts = "".join(f"<option value='{esc(t)}'>{esc(t)}</option>" for t in pc["targets"])
        hidden = "hidden" if pc["power"]["state"] == "on" else ""
        answer = pc["last_answer"] or "no preference"
        seen = (f"last asked {ago(pc['last_seen'])} from {esc(pc['from'])}, answered {esc(answer)}"
                if pc["last_seen"] else "has not asked yet")
        parts.append(f"""<div class=card><div class=row><b>{esc(pc['name'])}</b>
<span class=muted>{esc(', '.join(pc['targets']) or 'no targets')}</span></div>
<div class=row style='margin-top:6px'>
<form method=post action='/pc/{pc['id']}/choice' class=row>Boots <select name=target>
<option value='' {none_sel}>its own default</option>{opts}</select><button>Save</button></form></div>
<div class=row style='margin-top:6px'>{once_buttons} {once}</div>
<div class=row style='margin-top:6px'><span id='power-{pc['id']}'>{esc(pc['power']['summary'])}</span></div>
<div class=row style='margin-top:6px'>
<form method=post action='/pc/{pc['id']}/wake' class=row id='wake-{pc['id']}' {hidden}>Wake into
<select name=target><option value=''>its usual choice</option>{wake_opts}</select><button>Wake</button></form>
<form method=post action='/pc/{pc['id']}/mac' class=row>MAC <input name=mac value='{esc(pc['mac'] or '')}'
placeholder='learned when seen on' size=17><button>Save</button></form></div>
<div class='row muted' style='margin-top:6px'>{seen}
<form method=post action='/pc/{pc['id']}/remove' onsubmit="return confirm('Remove this PC?')">
<button>Remove</button></form></div></div>""")

    reqs = st.pending_requests()
    parts.append("<h2>New PCs</h2>")
    if not reqs:
        parts.append("<p class=muted>None. A paired PC appears here when it boots NetBooty or runs "
                     "<code>netbooty-setup announce</code>.</p>")
    for r in reqs:
        name = r.get("hostname") or ""
        targets = ",".join(r.get("targets") or [])
        parts.append(f"""<div class=card><div class=muted>client {esc(r['id'][:12])}… from {esc(r.get('from'))},
{ago(r.get('last_seen'))}</div>
<form method=post action='/request/{r['id']}/approve' class=row style='margin-top:6px'>
<input name=name value='{esc(name)}' placeholder='PC name' required>
<input name=targets value='{esc(targets)}' placeholder='targets, e.g. windows,linux' size=28>
<button class=primary>Approve</button></form>
<form method=post action='/request/{r['id']}/dismiss'><button>Dismiss</button></form></div>""")

    parts.append("<h2>Pair a PC</h2>")
    code = pairing_code(pub, host)
    if code:
        fps = " / ".join(pub.get("fingerprints", []))
        parts.append(f"""<div class=card><p>On the PC, run (or paste the code into <code>sudo netbooty-setup</code>):</p>
<div class=row><input id=cmd readonly size=60 class=code value="sudo netbooty-setup pair '{esc(code)}'">
<button onclick="navigator.clipboard.writeText(document.getElementById('cmd').value)">Copy</button>
<a href=/pairing.txt download=netbooty-pairing.txt>Download</a></div>
<p class=muted>Key fingerprint: <code>{esc(fps)}</code> — the PC shows the same when pairing.</p>
<p class=muted>Or let the PC find this server itself: <code>sudo netbooty-setup pair --discover</code>,
then check that it shows this fingerprint.</p></div>""")
    else:
        parts.append("<p class=err>The responder has not published a key yet. Is it running?</p>")
    if pcs:
        parts.append(POWER_SCRIPT)
    return page("NetBooty", "".join(parts))


class Handler(BaseHTTPRequestHandler):
    cfg: Config
    server_version = "netbooty-web"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    # --- helpers -------------------------------------------------------------

    def send(self, status: int, body: bytes, ctype="text/html; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, to: str, headers=None):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def json(self, status: int, value):
        self.send(status, (json.dumps(value) + "\n").encode(), "application/json")

    def logged_in(self) -> bool:
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return COOKIE in c and self.cfg.valid_session(c[COOKIE].value)

    def api_authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if self.cfg.api_token and auth.startswith("Bearer "):
            return hmac.compare_digest(auth[7:].strip(), self.cfg.api_token)
        return self.logged_in()

    def same_origin(self) -> bool:
        """Form posts must come from this site (cookies are also SameSite=Strict)."""
        origin = self.headers.get("Origin")
        return origin is None or urlsplit(origin).netloc == self.headers.get("Host")

    def body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(min(n, 65536))

    def form(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.body().decode(errors="replace")).items()}

    # --- routes --------------------------------------------------------------

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            return self.send(200, b"ok\n", "text/plain")
        if path.startswith("/api/"):
            return self.api("GET", path)
        if not self.logged_in():
            return self.send(200, login_page()) if path == "/login" else self.redirect("/login")
        if path == "/":
            return self.send(200, dashboard(self.cfg, host=self.headers.get("Host")))
        if path == "/pairing.txt":
            code = pairing_code(self.cfg.store.public(), self.headers.get("Host")) or ""
            return self.send(200, (code + "\n").encode(), "text/plain; charset=utf-8")
        return self.send(404, page("Not found", "<p>Not found</p>"))

    def do_DELETE(self):
        return self.api("DELETE", urlsplit(self.path).path)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path.startswith("/api/"):
            return self.api("POST", path)
        if not self.same_origin():
            return self.send(403, page("Forbidden", "<p>Cross-site request refused.</p>"))
        if path == "/login":
            given = self.form().get("password", "")
            if hmac.compare_digest(given.encode(), self.cfg.password.encode()):
                cookie = f"{COOKIE}={self.cfg.session()}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECS}"
                return self.redirect("/", {"Set-Cookie": cookie})
            time.sleep(1)
            return self.send(401, login_page("Wrong password."))
        if path == "/logout":
            return self.redirect("/login", {"Set-Cookie": f"{COOKIE}=; Max-Age=0; Path=/"})
        if not self.logged_in():
            return self.redirect("/login")
        parts = path.strip("/").split("/")
        f = self.form()
        st = self.cfg.store
        try:
            match parts:
                case ["pc", cid, "choice"]:
                    st.set_choice(cid, f.get("target") or None)
                case ["pc", cid, "once"]:
                    st.set_once(cid, f.get("target") or None)
                case ["pc", cid, "remove"]:
                    st.remove(cid)
                case ["pc", cid, "wake"]:
                    self.cfg.monitor.wake(cid, f.get("target") or None)
                case ["pc", cid, "mac"]:
                    st.set_mac(cid, f.get("mac", "").strip() or None)
                case ["request", cid, "approve"]:
                    targets = [t.strip() for t in f.get("targets", "").split(",") if t.strip()]
                    st.approve(cid, f.get("name", "").strip(), targets)
                case ["request", cid, "dismiss"]:
                    st.dismiss(cid)
                case _:
                    return self.send(404, page("Not found", "<p>Not found</p>"))
        except StateError as e:
            return self.send(400, dashboard(self.cfg, str(e), self.headers.get("Host")))
        return self.redirect("/")

    def api(self, method: str, path: str):
        if not self.api_authorized():
            return self.json(401, {"error": "unauthorized"})
        st = self.cfg.store
        parts = path.strip("/").split("/")[1:]
        try:
            data = json.loads(self.body() or b"{}") if method == "POST" else {}
            match (method, parts):
                case ("GET", ["state"]):
                    pub = st.public()
                    return self.json(200, {
                        "pcs": self.cfg.pcs(),
                        "requests": st.pending_requests(),
                        "pairing": {"code": pairing_code(pub, self.headers.get("Host")),
                                    "fingerprints": pub.get("fingerprints", [])},
                    })
                case ("POST", ["pcs", key, "choice"]):
                    st.set_choice(st.find_pc(key), data.get("target"))
                case ("POST", ["pcs", key, "once"]):
                    st.set_once(st.find_pc(key), data.get("target"))
                case ("POST", ["pcs", key, "wake"]):
                    self.cfg.monitor.wake(st.find_pc(key), data.get("target"))
                case ("POST", ["pcs", key, "mac"]):
                    st.set_mac(st.find_pc(key), data.get("mac"))
                case ("DELETE", ["pcs", key]):
                    st.remove(st.find_pc(key))
                case ("POST", ["requests", cid, "approve"]):
                    st.approve(cid, str(data.get("name", "")).strip(), list(data.get("targets") or []))
                case ("POST", ["requests", cid, "dismiss"]):
                    st.dismiss(cid)
                case _:
                    return self.json(404, {"error": "not found"})
        except (StateError, ValueError, TypeError, AttributeError) as e:
            return self.json(400, {"error": str(e)})
        return self.json(200, {"ok": True})


def make_server(cfg: Config, bind: str, port: int) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"cfg": cfg})
    return ThreadingHTTPServer((bind, port), handler)


def main() -> None:
    data = os.environ.get("NETBOOTY_DATA", "/var/lib/netbooty")
    password = os.environ.get("NETBOOTY_PASSWORD") or ""
    if not password:
        password = secrets.token_urlsafe(12)
        print(f"NETBOOTY_PASSWORD is not set; generated password for this run: {password}", flush=True)
    cfg = Config(data, password, os.environ.get("NETBOOTY_API_TOKEN") or None)
    wol = os.environ.get("NETBOOTY_WOL_ADDR", "255.255.255.255")
    wol_host, _, wol_port = wol.partition(":")
    cfg.monitor.wol_addr = (wol_host, int(wol_port or WOL_PORT))
    cfg.monitor.interval = float(os.environ.get("NETBOOTY_PING_SECS", "15"))
    cfg.monitor.pinger = make_pinger()
    cfg.monitor.start()
    bind = os.environ.get("NETBOOTY_WEB_BIND", "0.0.0.0")
    port = int(os.environ.get("NETBOOTY_WEB_PORT", "8470"))
    srv = make_server(cfg, bind, port)
    print(f"NetBooty web app on http://{bind}:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
