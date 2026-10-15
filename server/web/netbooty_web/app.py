"""NetBooty web app: pairing, approving PCs and choosing what they boot.

A Flask app served by waitress (one process: the power monitor runs in it).
The page itself is static (static/index.html + app.js) and works through the
JSON API. Configure with environment variables:

    NETBOOTY_DATA       data directory shared with the responder (default /var/lib/netbooty)
    NETBOOTY_PASSWORD   login password (a random one is generated and logged if unset)
    NETBOOTY_API_TOKEN  bearer token for the JSON API (optional; the API also accepts a login session)
    NETBOOTY_WEB_BIND   listen address (default 0.0.0.0)
    NETBOOTY_WEB_PORT   listen port (default 8470)
    NETBOOTY_PING_SECS  how often to ping each PC for its power status (default 15)
    NETBOOTY_WOL_ADDR   where to send Wake-on-LAN packets (default 255.255.255.255:9)
"""

from __future__ import annotations

import hmac
import html
import ipaddress
import json
import os
import secrets
import sys
import time
from datetime import timedelta
from urllib.parse import urlsplit

from flask import Flask, jsonify, redirect, request, send_from_directory, session
from waitress import create_server

from .power import WOL_PORT, Monitor, make_pinger
from .store import StateError, Store

SESSION_SECS = 12 * 3600
COOKIE = "netbooty_session"
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
CSP = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"


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
    """One line of text for API users; the page renders the fields itself."""
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


def login_page(error: str = "") -> str:
    err = f"<p class=err role=alert>{html.escape(error)}</p>" if error else ""
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>NetBooty</title>
<link rel=icon href=/static/favicon.svg><link rel=stylesheet href=/static/app.css></head><body><main class=login>
<h1>NetBooty</h1>{err}<form method=post action=/login class=stack>
<input type=password name=password placeholder=Password aria-label=Password autocomplete=current-password autofocus required>
<button class=primary>Log in</button></form></main></body></html>"""


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


def create_app(cfg: Config) -> Flask:
    app = Flask(__name__, static_folder=STATIC, static_url_path="/static")
    app.secret_key = cfg.secret
    app.config.update(
        SESSION_COOKIE_NAME=COOKIE,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_HTTPONLY=True,
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=SESSION_SECS),
        MAX_CONTENT_LENGTH=65536,
    )

    def bearer() -> bool | None:
        """True/False for a Bearer token when one is configured, None without one."""
        auth = request.headers.get("Authorization", "")
        if cfg.api_token and auth.startswith("Bearer "):
            return hmac.compare_digest(auth[7:].strip().encode(), cfg.api_token.encode())
        return None

    def logged_in() -> bool:
        return session.get("user") is not None

    @app.before_request
    def same_origin():
        """Cookie-authenticated changes must come from this site (cookies are
        also SameSite=Strict). Bearer-token clients are not browsers."""
        if request.method in ("GET", "HEAD", "OPTIONS") or bearer():
            return None
        origin = request.headers.get("Origin")
        if origin is not None and urlsplit(origin).netloc != request.host:
            if request.path.startswith("/api/"):
                return jsonify(error="cross-site request refused"), 403
            return "Cross-site request refused.\n", 403, {"Content-Type": "text/plain"}
        return None

    @app.after_request
    def headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = CSP
        if request.method != "GET" or resp.status_code >= 400:
            sys.stderr.write(f"{request.remote_addr} {request.method} {request.path} {resp.status_code}\n")
        return resp

    @app.get("/healthz")
    def healthz():
        return "ok\n", 200, {"Content-Type": "text/plain"}

    @app.get("/login")
    def login_form():
        return login_page()

    @app.post("/login")
    def login():
        given = request.form.get("password", "")
        if hmac.compare_digest(given.encode(), cfg.password.encode()):
            session.clear()
            session.permanent = True
            session["user"] = "admin"
            return redirect("/", 303)
        time.sleep(1)
        return login_page("Wrong password."), 401

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect("/login", 303)

    @app.get("/")
    def index():
        if not logged_in():
            return redirect("/login", 303)
        return send_from_directory(STATIC, "index.html")

    @app.get("/pairing.txt")
    def pairing_txt():
        if not logged_in():
            return redirect("/login", 303)
        code = pairing_code(cfg.store.public(), request.host) or ""
        return code + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/<path:path>", methods=["GET", "POST", "DELETE"])
    def api(path: str):
        token = bearer()
        if not (token or (token is None and logged_in())):
            return jsonify(error="unauthorized"), 401
        st = cfg.store
        parts = path.strip("/").split("/")
        try:
            data = json.loads(request.get_data() or b"{}") if request.method == "POST" else {}
            match (request.method, parts):
                case ("GET", ["state"]):
                    pub = st.public()
                    return jsonify({
                        "now": time.time(),
                        "pcs": cfg.pcs(),
                        "requests": st.pending_requests(),
                        "pairing": {"code": pairing_code(pub, request.host),
                                    "fingerprints": pub.get("fingerprints", [])},
                    })
                case ("POST", ["pcs", key]):
                    name, targets = data.get("name"), data.get("targets")
                    if targets is not None and not isinstance(targets, list):
                        raise StateError("targets must be a list")
                    st.edit(st.find_pc(key),
                            None if name is None else str(name).strip(),
                            None if targets is None else [str(t).strip() for t in targets if str(t).strip()])
                case ("POST", ["pcs", key, "choice"]):
                    st.set_choice(st.find_pc(key), data.get("target"))
                case ("POST", ["pcs", key, "once"]):
                    st.set_once(st.find_pc(key), data.get("target"))
                case ("POST", ["pcs", key, "wake"]):
                    cfg.monitor.wake(st.find_pc(key), data.get("target"))
                case ("POST", ["pcs", key, "mac"]):
                    st.set_mac(st.find_pc(key), data.get("mac"))
                case ("DELETE", ["pcs", key]):
                    st.remove(st.find_pc(key))
                case ("POST", ["requests", cid, "approve"]):
                    st.approve(cid, str(data.get("name", "")).strip(), list(data.get("targets") or []))
                case ("POST", ["requests", cid, "dismiss"]):
                    st.dismiss(cid)
                case _:
                    return jsonify(error="not found"), 404
        except (StateError, ValueError, TypeError, AttributeError) as e:
            return jsonify(error=str(e)), 400
        return jsonify(ok=True)

    return app


def make_server(cfg: Config, bind: str, port: int):
    """A waitress server (`.run()`, `.close()`, `.effective_port`)."""
    return create_server(create_app(cfg), host=bind, port=port, threads=8, channel_timeout=30,
                         ident="netbooty-web")


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
    print(f"NetBooty web app on http://{bind}:{srv.effective_port}", flush=True)
    try:
        srv.run()
    except KeyboardInterrupt:
        pass
