"""Milestone 4: NetBooty in QEMU paired with the real netbooty-server.

The responder runs on this host; QEMU's user-mode network delivers the
guest's broadcast to it and its unicast reply back. The server's own CLI is
used to approve the PC and choose what it boots, exactly as `docker compose
exec netbooty netbooty-server ...` would.
"""

import re
import socket
import subprocess
import time
from pathlib import Path

import pytest

import harness

NIC = "user,model=virtio-net-pci"
RNG = ["-device", "virtio-rng-pci"]
NB = "\\EFI\\netbooty\\netbooty.efi"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, data: Path):
        self.data = data
        data.mkdir(parents=True, exist_ok=True)
        self.port = free_port()
        self.log = data / "server.log"

    def cli(self, *args: str) -> str:
        return harness.run(harness.SERVER_BIN, "--data", self.data, *args).stdout

    def start(self):
        data_log = open(self.log, "w")
        self.proc = subprocess.Popen(
            [str(harness.SERVER_BIN), "--data", str(self.data), "serve", "--port", str(self.port),
             "--advertise-ip", "none"], stdout=data_log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if "listening" in self.log.read_text():
                return self
            time.sleep(0.05)
        raise RuntimeError("responder did not start: " + self.log.read_text())

    def code(self) -> str:
        return self.cli("pair", "--port", str(self.port), "--advertise-ip", "none").strip()

    def stop(self):
        self.proc.terminate()
        self.proc.wait()


@pytest.fixture
def server(tmp_path):
    s = Server(tmp_path / "server").start()
    yield s
    s.stop()


def client_id(efi) -> str:
    out = harness.run(harness.SETUP_BIN, "show", efi).stdout
    return re.search(r"client id:\s+([0-9a-f]{32})", out).group(1)


def paired(scenario, server, *extra, code=None, script_extra=""):
    """Install NetBooty paired with `server`; returns (scenario, client id)."""
    s = scenario.prepare("--default", "beta", "--pair", code or server.code(), *extra, script_extra=script_extra)
    return s, client_id(s.a.files[NB])


def approve(server, cid, name="pc"):
    server.cli("client", "add", cid, "--name", name, "--targets", "alpha,beta")


def boot(s, **kw):
    return s.boot(nic=NIC, extra=RNG, **kw)


def test_server_chooses_the_target(scenario, server):
    s, cid = paired(scenario, server)
    approve(server, cid)
    server.cli("set", "pc", "alpha")
    r = boot(s)
    assert r.has("network: server")
    assert r.has("decision=network target=alpha")
    assert r.target() == "alpha"
    assert r.has("NetBootyNetStatus=server")
    assert "answered pc" in server.log.read_text()
    assert "answered alpha" in server.cli("status")


def test_no_preference_boots_default(scenario, server):
    s, cid = paired(scenario, server)
    approve(server, cid)
    r = boot(s)
    assert r.has(": no preference")
    assert r.has("decision=default target=beta")


def test_unapproved_pc_becomes_pairing_request(scenario, server):
    s, cid = paired(scenario, server)
    r = boot(s)
    assert r.has("network: no reply")
    assert r.target() == "beta"
    assert cid[:12] in server.cli("client", "list")
    # Approve the request; the next boot follows the server.
    server.cli("client", "approve", cid, "--name", "pc", "--targets", "alpha,beta")
    server.cli("set", "pc", "alpha")
    time.sleep(21)  # NetBooty's reset-loop guard; any real OS boot takes longer
    assert boot(s).has("decision=network target=alpha")


def test_reply_signed_by_another_server_is_rejected(scenario, server, tmp_path):
    other = Server(tmp_path / "other")
    other.cli("keygen")
    wrong_code = other.cli("pair", "--port", str(server.port), "--advertise-ip", "none").strip()
    s, cid = paired(scenario, server, code=wrong_code)
    approve(server, cid)
    server.cli("set", "pc", "alpha")
    r = boot(s)
    assert r.has("network: no valid reply (")
    assert r.has("decision=default target=beta")


def test_key_rotation(scenario, server):
    server.cli("keygen", "--next")
    both = server.code()
    assert "," in both.split(":")[3]  # current and next key
    s, cid = paired(scenario, server, code=both)
    approve(server, cid)
    server.cli("set", "pc", "alpha")
    server.cli("keygen", "--promote")  # now signing with the former next key
    assert boot(s).has("decision=network target=alpha")


def test_os_request_beats_server(scenario, server):
    s, cid = paired(scenario, server, script_extra="nbnext beta\n")
    approve(server, cid)
    server.cli("set", "pc", "alpha")
    r = boot(s)
    assert r.has("decision=os-request target=beta")


def test_menu_shows_server_choice(scenario, server):
    s, cid = paired(scenario, server, "--menu", "always", "--menu-timeout", "5")
    approve(server, cid)
    server.cli("set", "pc", "alpha")
    r = boot(s)
    assert r.has("Automatic (server: alpha)")
    assert r.has("decision=network target=alpha")


def test_menu_pick_beats_server(scenario, server):
    s, cid = paired(scenario, server, "--menu", "always", "--menu-timeout", "10")
    approve(server, cid)
    server.cli("set", "pc", "alpha")
    r = boot(s, keys=[("Automatic (server: alpha)", "2")])
    assert r.has("decision=menu target=beta")


def test_once_is_used_once(scenario, server):
    s, cid = paired(scenario, server)
    approve(server, cid)
    server.cli("set", "pc", "beta")
    server.cli("next", "pc", "alpha")
    assert boot(s).has("decision=network target=alpha")
    time.sleep(61)  # past the one-shot's grace period for retries of the same boot
    assert boot(s).has("decision=network target=beta")


def test_discovery_offer(server):
    """`netbooty-setup pair --discover` sends DISCOVER; the responder answers
    with its pairing code (only public data)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(2)
    for dest in ("127.0.0.1", "255.255.255.255"):
        sock.sendto(b"NBTYD1", (dest, server.port))
        data, _ = sock.recvfrom(1024)
        assert data.startswith(b"NBTYP1")
        code = data[6:].decode()
        assert code.startswith(f"netbooty-pair:1:{server.port}:")
        assert code == server.code()
    assert "discovery request" in server.log.read_text()
