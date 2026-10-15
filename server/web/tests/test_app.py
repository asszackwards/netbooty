"""Web app tests against a temporary data directory (no responder needed)."""

import http.cookiejar
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netbooty_web.app import Config, make_server  # noqa: E402

CID = "ab" * 16
PASSWORD = "hunter2"
TOKEN = "tok-123"

OPENED: list[str] = []
sys.addaudithook(lambda event, args: OPENED.append(str(args[0])) if event == "open" and args else None)


@pytest.fixture
def app(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (tmp_path / "key").mkdir()
    (tmp_path / "key" / "current.seed").write_text("00" * 32)
    (state / "public.json").write_text(json.dumps({
        "version": 1, "port": 47000, "server_ip": "10.0.0.5", "keys": ["k"],
        "fingerprints": ["aaaa-bbbb-cccc-dddd"], "pairing_code": "netbooty-pair:1:47000:KEY:10.0.0.5"}))
    (state / "requests.json").write_text(json.dumps({"version": 1, "requests": {
        CID: {"first_seen": 9e9, "last_seen": 9e9, "from": "10.0.0.9", "hostname": "zaqbox",
              "targets": ["windows", "linux"]}}}))
    srv, base = serve(Config(str(tmp_path), PASSWORD, TOKEN))
    OPENED.clear()
    yield base, tmp_path
    srv.close()


def serve(cfg):
    """Start the real (waitress) server on a free port."""
    srv = make_server(cfg, "127.0.0.1", 0)
    threading.Thread(target=srv.run, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.effective_port}"


class Browser:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(self, path):
        with self.opener.open(self.base + path) as r:
            return r.status, r.read().decode()

    def response(self, path):
        with self.opener.open(self.base + path) as r:
            return r.status, r.headers, r.read().decode()

    def api(self, method, path, body=None, headers=None):
        """The JSON API with this browser's login session (no bearer token)."""
        req = urllib.request.Request(self.base + path, method=method, headers=headers or {},
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with self.opener.open(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def post(self, path, **fields):
        data = urllib.parse.urlencode(fields).encode()
        try:
            with self.opener.open(urllib.request.Request(self.base + path, data=data)) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()


def api(base, method, path, body=None, token=TOKEN):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def state(tmp):
    return json.loads((tmp / "state" / "state.json").read_text())


def test_login_required_and_wrong_password(app):
    base, _ = app
    b = Browser(base)
    status, body = b.get("/")
    assert "Password" in body  # redirected to the login page
    status, body = b.post("/login", password="nope")
    assert status == 401 and "Wrong password" in body


def login(base):
    b = Browser(base)
    status, body = b.post("/login", password=PASSWORD)
    assert status == 200 and "/static/app.js" in body  # landed on the page
    return b


def test_page_and_static_files(app):
    base, _ = app
    b = Browser(base)
    status, body = b.get("/")
    assert "Password" in body and "app.js" not in body  # login page, not the app
    assert b.api("GET", "/api/state")[0] == 401
    status, _ = b.get("/static/app.js")  # no data in it: served without login
    assert status == 200

    b = login(base)
    status, headers, body = b.response("/")
    assert status == 200 and "<title>NetBooty</title>" in body
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY" and headers["Cache-Control"] == "no-store"
    status, headers, _ = b.response("/static/app.js")
    assert "javascript" in headers["Content-Type"]
    with pytest.raises(urllib.error.HTTPError) as e:
        b.get("/static/../store.py")
    assert e.value.code == 404

    b.post("/logout")
    assert b.api("GET", "/api/state")[0] == 401


def test_pair_approve_choose_once(app):
    base, tmp = app
    b = login(base)
    _, st = b.api("GET", "/api/state")
    assert st["pairing"] == {"code": "netbooty-pair:1:47000:KEY:10.0.0.5", "fingerprints": ["aaaa-bbbb-cccc-dddd"]}
    assert st["requests"][0]["hostname"] == "zaqbox"  # pending request with announced hostname
    assert abs(st["now"] - time.time()) < 60

    assert b.api("POST", f"/api/requests/{CID}/approve", {"name": "zaqbox", "targets": ["windows", "linux"]})[0] == 200
    s = state(tmp)
    assert s["clients"][CID] == {"name": "zaqbox", "targets": ["windows", "linux"], "choice": None, "once": None}

    b.api("POST", f"/api/pcs/{CID}/choice", {"target": "windows"})
    assert state(tmp)["clients"][CID]["choice"] == "windows"
    status, err = b.api("POST", f"/api/pcs/{CID}/choice", {"target": "macos"})
    assert status == 400 and "no target" in err["error"]

    b.api("POST", f"/api/pcs/{CID}/once", {"target": "linux"})
    once = state(tmp)["clients"][CID]["once"]
    assert once["target"] == "linux" and len(once["id"]) == 16
    assert b.api("GET", "/api/state")[1]["pcs"][0]["once"] == "linux"
    b.api("POST", f"/api/pcs/{CID}/once", {"target": None})  # cancel
    assert state(tmp)["clients"][CID]["once"] is None

    _, txt = b.get("/pairing.txt")
    assert txt.strip() == "netbooty-pair:1:47000:KEY:10.0.0.5"


def test_edit_pc(app):
    base, tmp = app
    api(base, "POST", f"/api/requests/{CID}/approve", {"name": "zaqbox", "targets": ["windows", "linux"]})
    api(base, "POST", "/api/pcs/zaqbox/choice", {"target": "linux"})
    api(base, "POST", "/api/pcs/zaqbox/once", {"target": "windows"})

    assert api(base, "POST", "/api/pcs/zaqbox", {"name": " gamingpc "})[0] == 200
    c = state(tmp)["clients"][CID]
    assert c["name"] == "gamingpc" and c["targets"] == ["windows", "linux"] and c["choice"] == "linux"

    # Dropping a target clears the choice / one-shot that used it.
    assert api(base, "POST", "/api/pcs/gamingpc", {"targets": ["windows", "fedora"]})[0] == 200
    c = state(tmp)["clients"][CID]
    assert c["targets"] == ["windows", "fedora"] and c["choice"] is None and c["once"]["target"] == "windows"
    api(base, "POST", "/api/pcs/gamingpc", {"targets": ["fedora"]})
    assert state(tmp)["clients"][CID]["once"] is None

    status, err = api(base, "POST", "/api/pcs/gamingpc", {"targets": ["bad name"]})
    assert status == 400 and "invalid target" in err["error"]
    assert api(base, "POST", "/api/pcs/gamingpc", {"targets": "fedora"})[0] == 400  # not a list
    assert api(base, "POST", "/api/pcs/gamingpc", {"name": ""})[0] == 400
    assert api(base, "POST", "/api/pcs/nosuch", {"name": "x"})[0] == 400

    s = json.loads((tmp / "state" / "state.json").read_text())
    s["clients"]["cd" * 16] = {"name": "other", "targets": [], "choice": None, "once": None}
    (tmp / "state" / "state.json").write_text(json.dumps(s))
    status, err = api(base, "POST", "/api/pcs/gamingpc", {"name": "OTHER"})
    assert status == 400 and "already exists" in err["error"]


def test_once_shown_as_used_after_responder_serves_it(app):
    base, tmp = app
    api(base, "POST", f"/api/requests/{CID}/approve", {"name": "pc", "targets": ["windows"]})
    api(base, "POST", "/api/pcs/pc/once", {"target": "windows"})
    once_id = state(tmp)["clients"][CID]["once"]["id"]
    _, st = api(base, "GET", "/api/state")
    assert st["pcs"][0]["once"] == "windows"
    (tmp / "state" / "status.json").write_text(json.dumps({"version": 1, "clients": {CID: {
        "last_seen": 1, "from": "10.0.0.9", "last_answer": "windows", "once_served": {"id": once_id, "at": 1}}}}))
    _, st = api(base, "GET", "/api/state")
    assert st["pcs"][0]["once"] is None
    assert st["pcs"][0]["last_answer"] == "windows"


def test_api(app):
    base, tmp = app
    assert api(base, "GET", "/api/state", token="wrong")[0] == 401
    status, st = api(base, "GET", "/api/state")
    assert status == 200 and st["requests"][0]["hostname"] == "zaqbox"
    assert st["pairing"]["code"].startswith("netbooty-pair:1:")
    assert api(base, "POST", f"/api/requests/{CID}/approve", {"name": "gamingpc", "targets": ["windows", "linux"]})[0] == 200
    assert api(base, "POST", "/api/pcs/gamingpc/choice", {"target": "linux"})[0] == 200
    assert state(tmp)["clients"][CID]["choice"] == "linux"
    assert api(base, "POST", "/api/pcs/gamingpc/choice", {"target": None})[0] == 200
    assert state(tmp)["clients"][CID]["choice"] is None
    assert api(base, "POST", "/api/pcs/nosuch/choice", {"target": "linux"})[0] == 400
    assert api(base, "POST", f"/api/requests/{CID}/approve", {"name": "x", "targets": ["bad name"]})[0] == 400
    assert api(base, "DELETE", "/api/pcs/gamingpc")[0] == 200
    assert CID not in state(tmp)["clients"]


def test_dismiss_hides_request(app):
    base, tmp = app
    b = login(base)
    assert b.api("POST", f"/api/requests/{CID}/dismiss")[0] == 200
    assert CID in state(tmp)["dismissed"]
    assert b.api("GET", "/api/state")[1]["requests"] == []


def test_cross_site_post_refused(app):
    base, tmp = app
    b = login(base)
    evil = {"Origin": "http://evil.example", "Content-Type": "application/json"}
    status, err = b.api("POST", f"/api/requests/{CID}/dismiss", {}, headers=evil)
    assert status == 403 and "cross-site" in err["error"]
    assert b.api("DELETE", "/api/pcs/x", headers=evil)[0] == 403
    assert not (tmp / "state" / "state.json").exists()
    status, _ = b.post("/logout")  # not refused without an Origin
    req = urllib.request.Request(f"{base}/login", data=b"password=" + PASSWORD.encode(), headers=evil)
    with pytest.raises(urllib.error.HTTPError) as e:
        b.opener.open(req)
    assert e.value.code == 403

    # Same origin is fine; so is a bearer token (not a browser) from anywhere.
    b = login(base)
    same = {"Origin": base}
    assert b.api("POST", f"/api/requests/{CID}/dismiss", {}, headers=same)[0] == 200
    req = urllib.request.Request(f"{base}/api/requests/{CID}/dismiss", data=b"{}", method="POST",
                                 headers={**evil, "Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req) as r:
        assert r.status == 200


def test_never_touches_the_key(app):
    base, tmp = app
    b = login(base)
    b.get("/")
    b.get("/static/app.js")
    b.api("POST", f"/api/requests/{CID}/approve", {"name": "pc", "targets": ["windows"]})
    api(base, "GET", "/api/state")
    key_dir = str(tmp / "key")
    assert not [p for p in OPENED if p.startswith(key_dir)]


def test_pairing_code_uses_the_address_the_page_was_reached_at():
    from netbooty_web.app import pairing_code
    detected = {"pairing_code": "netbooty-pair:1:47000:KEY:172.17.0.2", "server_ip_configured": False}
    assert pairing_code(detected, "10.10.0.5:8470") == "netbooty-pair:1:47000:KEY:10.10.0.5"
    assert pairing_code(detected, "server.lan:8470") == detected["pairing_code"]   # a name: keep
    assert pairing_code(detected, "127.0.0.1:8470") == detected["pairing_code"]    # loopback: keep
    configured = {**detected, "server_ip_configured": True}
    assert pairing_code(configured, "10.10.0.5:8470") == detected["pairing_code"]
    none = {"pairing_code": "netbooty-pair:1:47000:KEY", "server_ip_configured": False}
    assert pairing_code(none, "10.10.0.5") == "netbooty-pair:1:47000:KEY:10.10.0.5"
