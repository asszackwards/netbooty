"""Web app tests against a temporary data directory (no responder needed)."""

import http.cookiejar
import json
import sys
import threading
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
    srv = make_server(Config(str(tmp_path), PASSWORD, TOKEN), "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    OPENED.clear()
    yield f"http://127.0.0.1:{srv.server_address[1]}", tmp_path
    srv.shutdown()


class Browser:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def get(self, path):
        with self.opener.open(self.base + path) as r:
            return r.status, r.read().decode()

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


def test_pair_approve_choose_once(app):
    base, tmp = app
    b = Browser(base)
    _, body = b.post("/login", password=PASSWORD)
    assert "netbooty-pair:1:47000:KEY:10.0.0.5" in body
    assert "aaaa-bbbb-cccc-dddd" in body
    assert "zaqbox" in body  # pending request with announced hostname

    b.post(f"/request/{CID}/approve", name="zaqbox", targets="windows,linux")
    s = state(tmp)
    assert s["clients"][CID] == {"name": "zaqbox", "targets": ["windows", "linux"], "choice": None, "once": None}

    b.post(f"/pc/{CID}/choice", target="windows")
    assert state(tmp)["clients"][CID]["choice"] == "windows"
    status, body = b.post(f"/pc/{CID}/choice", target="macos")
    assert status == 400 and "no target" in body

    b.post(f"/pc/{CID}/once", target="linux")
    once = state(tmp)["clients"][CID]["once"]
    assert once["target"] == "linux" and len(once["id"]) == 16
    _, body = b.get("/")
    assert "next boot: <b>linux</b>" in body
    b.post(f"/pc/{CID}/once")  # cancel
    assert state(tmp)["clients"][CID]["once"] is None

    _, txt = b.get("/pairing.txt")
    assert txt.strip() == "netbooty-pair:1:47000:KEY:10.0.0.5"


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
    b = Browser(base)
    b.post("/login", password=PASSWORD)
    b.post(f"/request/{CID}/dismiss")
    assert CID in state(tmp)["dismissed"]
    _, body = b.get("/")
    assert "zaqbox" not in body


def test_cross_site_post_refused(app):
    base, tmp = app
    b = Browser(base)
    b.post("/login", password=PASSWORD)
    req = urllib.request.Request(f"{base}/request/{CID}/dismiss", data=b"", headers={"Origin": "http://evil.example"})
    with pytest.raises(urllib.error.HTTPError) as e:
        b.opener.open(req)
    assert e.value.code == 403
    assert not (tmp / "state" / "state.json").exists()


def test_never_touches_the_key(app):
    base, tmp = app
    b = Browser(base)
    b.post("/login", password=PASSWORD)
    b.get("/")
    b.post(f"/request/{CID}/approve", name="pc", targets="windows")
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
