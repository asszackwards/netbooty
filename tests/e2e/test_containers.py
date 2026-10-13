"""The boot server against the real container from server/compose.yaml.

Skipped unless Docker is usable by this user. Runs a separate compose project
(own volumes, free ports) and tears it down afterwards.
"""

import json
import os
import socket
import subprocess
import time
import urllib.request
import uuid

import pytest

import harness
from test_server import NB, boot, client_id

COMPOSE = harness.ROOT / "server" / "compose.yaml"
TOKEN = "test-token"


def docker_ok() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not docker_ok(), reason="docker not usable by this user")


def free_port(kind) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


class Stack:
    def __init__(self):
        self.project = f"nbtest{uuid.uuid4().hex[:8]}"
        self.udp = free_port(socket.SOCK_DGRAM)
        self.web = free_port(socket.SOCK_STREAM)
        self.env = dict(os.environ, NETBOOTY_PASSWORD="pw", NETBOOTY_API_TOKEN=TOKEN,
                        NETBOOTY_PORT=str(self.udp), NETBOOTY_WEB_PORT=str(self.web))

    def compose(self, *args, check=True) -> subprocess.CompletedProcess:
        return subprocess.run(["docker", "compose", "-p", self.project, "-f", str(COMPOSE), *args],
                              env=self.env, capture_output=True, text=True, check=check)

    def responder(self, *args) -> str:
        return self.compose("exec", "-T", "netbooty", "netbooty-server", *args).stdout

    def api(self, method, path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.web}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {TOKEN}"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())


@pytest.fixture(scope="module")
def stack():
    s = Stack()
    s.compose("up", "-d", "--build")
    try:
        for _ in range(100):
            try:
                if s.api("GET", "/api/state")["pairing"]["code"]:
                    break
            except OSError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError(s.compose("logs", check=False).stdout)
        yield s
    finally:
        s.compose("down", "-v", check=False)


def test_image_is_small_and_services_run_unprivileged(stack):
    info = json.loads(subprocess.run(["docker", "image", "inspect", "netbooty-server"], capture_output=True,
                                     text=True, check=True).stdout)[0]
    assert info["Size"] < 130e6, info["Size"]
    # Only the launcher runs as root. (busybox ps cuts user names at 8 characters.)
    ps = stack.compose("exec", "-T", "netbooty", "ps", "-o", "user,args").stdout
    user = {line.split()[-1]: line.split()[0] for line in ps.splitlines()}
    assert user["serve"] == "responde" and user["netbooty_web"] == "web", ps


def test_only_the_responder_can_read_the_key(stack):
    r = stack.compose("exec", "-T", "-u", "web", "netbooty", "cat", "/data/key/current.seed", check=False)
    assert r.returncode != 0
    r = stack.compose("exec", "-T", "-u", "web", "netbooty", "ls", "/data/state")
    assert "state.json" in r.stdout or "public.json" in r.stdout
    # The CLI runs as the responder (through the wrapper), so it can.
    code = stack.responder("pair", "--port", str(stack.udp), "--advertise-ip", "none")
    assert code.startswith("netbooty-pair:")


def test_pair_approve_choose_through_the_containers(scenario, stack):
    # Pairing code as the web page shows it (address left out: QEMU reaches the
    # host by broadcast through its user-mode network).
    code = stack.responder("pair", "--port", str(stack.udp), "--advertise-ip", "none").strip()
    # The web page shows the same code, plus the auto-detected server address.
    assert stack.api("GET", "/api/state")["pairing"]["code"].startswith(code)
    s = scenario.prepare("--default", "beta", "--pair", code)
    cid = client_id(s.a.files[NB])

    # First boot: unknown PC -> pairing request in the web app, default boot.
    r = boot(s)
    assert r.has("network: no reply") and r.target() == "beta"
    reqs = stack.api("GET", "/api/state")["requests"]
    assert [x["id"] for x in reqs] == [cid]

    # Approve and choose through the web API; the responder picks it up.
    stack.api("POST", f"/api/requests/{cid}/approve", {"name": "pc", "targets": ["alpha", "beta"]})
    stack.api("POST", "/api/pcs/pc/choice", {"target": "alpha"})
    time.sleep(21)  # NetBooty's reset-loop guard
    r = boot(s)
    assert r.has("decision=network target=alpha")
    pc = stack.api("GET", "/api/state")["pcs"][0]
    assert pc["last_answer"] == "alpha"
    assert pc["power"]["state"] in ("unknown", "on", "off", "unavailable")
