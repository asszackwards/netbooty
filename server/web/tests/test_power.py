"""Power status and Wake-on-LAN, with a fake pinger and ARP table."""

import json
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netbooty_web.app import Config  # noqa: E402
from netbooty_web.power import Monitor, arp_mac, magic_packet, os_hint  # noqa: E402
from netbooty_web.store import StateError, Store, normalize_mac  # noqa: E402
from test_app import CID, PASSWORD, TOKEN, Browser, api, serve, state  # noqa: E402

MAC = "aa:bb:cc:dd:ee:01"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Pinger:
    """Replies with `ttl` (None = no reply); fails like a missing permission when `denied`."""
    def __init__(self):
        self.ttl = None
        self.denied = False

    def __call__(self, ip, timeout):
        if self.denied:
            raise PermissionError(13, "Permission denied")
        return self.ttl


@pytest.fixture
def setup(tmp_path):
    st = tmp_path / "state"
    st.mkdir()
    (st / "state.json").write_text(json.dumps({"version": 1, "dismissed": [], "clients": {
        CID: {"name": "pc", "targets": ["windows", "linux"], "choice": None, "once": None}}}))
    store = Store(tmp_path)
    clock, pinger = Clock(), Pinger()
    arp = {"10.0.0.9": MAC}
    mon = Monitor(store, pinger=pinger, arp=arp.get, clock=clock)
    return store, mon, clock, pinger, tmp_path


def asked(tmp, at, answer="windows"):
    (tmp / "state" / "status.json").write_text(json.dumps({"version": 1, "clients": {
        CID: {"last_seen": at, "from": "10.0.0.9", "last_answer": answer}}}))


def snap(store, mon):
    return mon.snapshot(store.pcs()[0])


def test_unknown_until_the_pc_has_asked(setup):
    store, mon, _, pinger, _ = setup
    pinger.ttl = 128
    mon.poll()  # no address yet: nothing to ping
    assert snap(store, mon)["state"] == "unknown"


def test_on_off_and_two_miss_rule(setup):
    store, mon, clock, pinger, tmp = setup
    asked(tmp, 900)
    pinger.ttl = 128
    mon.poll()
    p = snap(store, mon)
    assert p["state"] == "on" and p["ttl"] == 128 and p["os_hint"] == "Windows"
    assert p["running"] == "windows" and p["asked_at"] == 900

    pinger.ttl = None
    clock.t += 15
    mon.poll()
    assert snap(store, mon)["state"] == "on"  # one miss is not enough
    clock.t += 15
    mon.poll()
    p = snap(store, mon)
    assert p["state"] == "off" and p["since"] == 1030


def test_running_belongs_to_this_power_on_only(setup):
    store, mon, clock, pinger, tmp = setup
    asked(tmp, 900)
    pinger.ttl = 64
    mon.poll()                    # on at 1000
    pinger.ttl = None
    for _ in range(2):
        clock.t += 15
        mon.poll()                # off; last reply was at 1000
    # Back on without having asked the server (e.g. its network step failed).
    clock.t += 60
    pinger.ttl = 64
    mon.poll()
    p = snap(store, mon)
    assert p["state"] == "on" and p["running"] is None and p["os_hint"] == "Linux"
    # A boot that asked after the PC went off counts, including "no preference".
    asked(tmp, 1050, answer="")
    assert snap(store, mon)["running"] == ""


def test_mac_learned_once_and_manual_kept(setup):
    store, mon, _, pinger, tmp = setup
    asked(tmp, 900)
    pinger.ttl = 128
    mon.poll()
    assert state(tmp)["clients"][CID]["mac"] == MAC
    store.set_mac(CID, "AA-BB-CC-DD-EE-02")
    mon.poll()
    assert state(tmp)["clients"][CID]["mac"] == "aa:bb:cc:dd:ee:02"
    store.set_mac(CID, None)
    assert "mac" not in state(tmp)["clients"][CID]


def test_ping_not_permitted(setup):
    store, mon, _, pinger, tmp = setup
    asked(tmp, 900)
    pinger.denied = True
    mon.poll()
    p = snap(store, mon)
    assert p["state"] == "unavailable" and "ping_group_range" in p["error"]


def udp_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(2)
    return s


def test_wake_sets_once_sends_packet_and_times_out(setup):
    store, mon, clock, _, tmp = setup
    with pytest.raises(StateError, match="no MAC"):
        mon.wake(CID, "linux")
    assert state(tmp)["clients"][CID]["once"] is None  # nothing changed without a MAC

    store.set_mac(CID, MAC)
    with udp_listener() as rx:
        mon.wol_addr = rx.getsockname()
        mon.wake(CID, "linux")
        packet = rx.recv(200)
    assert len(packet) == 102 and packet == magic_packet(MAC)
    assert packet[:6] == b"\xff" * 6 and packet[6:12] == bytes.fromhex("aabbccddee01")
    assert state(tmp)["clients"][CID]["once"]["target"] == "linux"

    asked(tmp, 900)
    p = snap(store, mon)
    assert p["state"] == "waking"
    clock.t += 200
    p = snap(store, mon)
    assert p["wake_failed"] and p["state"] != "waking"

    with pytest.raises(StateError, match="no target"):
        mon.wake(CID, "macos")


def test_helpers(tmp_path):
    assert normalize_mac("AABB.CCDD.EEFF") == "aa:bb:cc:dd:ee:ff"
    for bad in ("aa:bb:cc", "00:00:00:00:00:00", "zz:bb:cc:dd:ee:ff"):
        with pytest.raises(StateError):
            normalize_mac(bad)
    assert (os_hint(128), os_hint(117), os_hint(64), os_hint(255), os_hint(None)) == \
        ("Windows", "Windows", "Linux", None, None)
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "10.0.0.9         0x1         0x2         AA:BB:CC:DD:EE:01     *        eth0\n"
        "10.0.0.10        0x1         0x0         00:00:00:00:00:00     *        eth0\n")
    assert arp_mac("10.0.0.9", str(arp)) == MAC
    assert arp_mac("10.0.0.10", str(arp)) is None
    assert arp_mac("10.0.0.11", str(arp)) is None


@pytest.fixture
def app(setup):
    store, mon, clock, pinger, tmp = setup
    cfg = Config(str(tmp), PASSWORD, TOKEN, monitor=mon)
    mon.store = cfg.store
    srv, base = serve(cfg)
    yield base, tmp, mon, pinger
    srv.close()


def test_web_and_api(app):
    base, tmp, mon, pinger = app
    asked(tmp, 900)
    pinger.ttl = 128
    mon.poll()
    _, st = api(base, "GET", "/api/state")
    pc = st["pcs"][0]
    assert pc["mac"] == MAC and pc["power"]["state"] == "on"
    assert pc["power"]["summary"].startswith("● On · probably running windows")

    b = Browser(base)
    b.post("/login", password=PASSWORD)
    b.api("POST", f"/api/pcs/{CID}/mac", {"mac": "aa-bb-cc-dd-ee-03"})
    assert state(tmp)["clients"][CID]["mac"] == "aa:bb:cc:dd:ee:03"
    status, err = b.api("POST", f"/api/pcs/{CID}/mac", {"mac": "nope"})
    assert status == 400 and "invalid MAC" in err["error"]

    with udp_listener() as rx:
        mon.wol_addr = rx.getsockname()
        b.api("POST", f"/api/pcs/{CID}/wake", {"target": None})  # its usual choice: no one-shot
        assert rx.recv(200) == magic_packet("aa:bb:cc:dd:ee:03")
        assert state(tmp)["clients"][CID]["once"] is None
        assert api(base, "POST", "/api/pcs/pc/wake", {"target": "linux"})[0] == 200
        assert rx.recv(200) == magic_packet("aa:bb:cc:dd:ee:03")
    assert state(tmp)["clients"][CID]["once"]["target"] == "linux"

    assert api(base, "POST", "/api/pcs/pc/mac", {"mac": None})[0] == 200
    status, err = api(base, "POST", "/api/pcs/pc/wake", {"target": None})
    assert status == 400 and "no MAC" in err["error"]
    assert api(base, "POST", "/api/pcs/pc/wake", {}, token="wrong")[0] == 401


def test_real_ping_of_localhost():
    from netbooty_web.power import ping
    try:
        ttl = ping("127.0.0.1")
    except OSError as e:
        pytest.skip(f"unprivileged ping not permitted here: {e}")
    assert ttl == 64
    assert ping("192.0.2.1", 0.3) is None  # TEST-NET-1: never answers


def ip_packet(src: str, ttl: int, icmp: bytes) -> bytes:
    return bytes([0x45, 0, 0, 20 + len(icmp), 0, 0, 0, 0, ttl, 1, 0, 0]) + socket.inet_aton(src) + \
        socket.inet_aton("10.0.0.5") + icmp


def test_raw_echo_packets():
    from netbooty_web.power import checksum, echo_request, parse_reply
    req = echo_request(0x1234, 7)
    assert req[0] == 8 and checksum(req) == 0  # a valid checksum sums to zero
    reply = b"\0" + req[1:]
    assert parse_reply(ip_packet("10.0.0.9", 128, reply), "10.0.0.9", 0x1234, 7) == 128
    assert parse_reply(ip_packet("10.0.0.8", 128, reply), "10.0.0.9", 0x1234, 7) is None   # other host
    assert parse_reply(ip_packet("10.0.0.9", 128, reply), "10.0.0.9", 0x1234, 8) is None   # older request
    assert parse_reply(ip_packet("10.0.0.9", 64, req), "10.0.0.9", 0x1234, 7) is None      # a request, not a reply
    assert parse_reply(b"short", "10.0.0.9", 0x1234, 7) is None


def test_raw_pinger_skips_other_icmp():
    from netbooty_web.power import RawPinger

    class FakeSock:
        def __init__(self):
            self.inbox = []

        def sendto(self, data, addr):
            reply = b"\0" + data[1:]
            self.inbox = [ip_packet(addr[0], 64, data),                  # our own request, looped back
                          ip_packet("10.0.0.7", 128, reply),            # someone else's reply
                          ip_packet(addr[0], 128, reply)]

        def settimeout(self, t):
            pass

        def recv(self, n):
            if not self.inbox:
                raise TimeoutError
            return self.inbox.pop(0)

    p = RawPinger(FakeSock())
    assert p("10.0.0.9") == 128
    assert p("10.0.0.9") == 128  # next sequence number still matches its own reply
