"""Power status by ICMP ping, and Wake-on-LAN.

Each approved PC is pinged at the address it last asked the server from.
What it is running is inferred, not reported: the server's answer at its
last boot (if it asked during this power-on), plus a TTL hint (Windows
answers with 128, Linux with 64).

Needs host networking (to reach the LAN with broadcasts and read the host's
ARP table) and `net.ipv4.ping_group_range` covering this process's group
(the default on systemd distributions).
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass

from .store import StateError, Store, normalize_mac

MISSES_FOR_OFF = 2
WAKE_WINDOW_SECS = 180
WOL_PORT = 9

_IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
_IP_TTL = getattr(socket, "IP_TTL", 2)


def ping(ip: str, timeout: float = 1.0) -> int | None:
    """One ICMP echo; the reply's TTL, or None without a reply. Raises
    OSError when unprivileged ICMP sockets are not allowed."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as s:
        s.setsockopt(socket.IPPROTO_IP, _IP_RECVTTL, 1)
        s.settimeout(timeout)
        # The kernel fills in the identifier and checksum.
        s.sendto(struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"netbooty", (ip, 0))
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            try:
                data, anc, _, addr = s.recvmsg(256, socket.CMSG_SPACE(4))
            except (TimeoutError, socket.timeout):
                return None
            if addr[0] != ip or not data or data[0] != 0:  # 0 = echo reply
                continue
            for level, kind, value in anc:
                if level == socket.IPPROTO_IP and kind == _IP_TTL and len(value) >= 4:
                    return int.from_bytes(value[:4], sys.byteorder)
            return 0
    return None


def arp_mac(ip: str, path: str = "/proc/net/arp") -> str | None:
    """The host's ARP entry for `ip`, if complete."""
    try:
        lines = open(path).read().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        f = line.split()
        if len(f) >= 4 and f[0] == ip and int(f[2], 16) & 0x2 and f[3] != "00:00:00:00:00:00":
            return f[3].lower()
    return None


def magic_packet(mac: str) -> bytes:
    return b"\xff" * 6 + bytes.fromhex(normalize_mac(mac).replace(":", "")) * 16


def send_wol(mac: str, addr: tuple[str, int] = ("255.255.255.255", WOL_PORT)) -> None:
    packet = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(3):
            s.sendto(packet, addr)


def os_hint(ttl: int | None) -> str | None:
    if not ttl or ttl > 128:
        return None
    return "Windows" if ttl > 64 else "Linux"


@dataclass
class Power:
    state: str = "unknown"  # unknown / on / off
    since: float | None = None
    ttl: int | None = None
    misses: int = 0
    last_reply: float = 0.0
    # Last reply before the PC was last seen off: an answer the server gave
    # after this belongs to the current power-on.
    down_after: float = 0.0
    wake_at: float | None = None


class Monitor:
    def __init__(self, store: Store, interval: float = 15, pinger=ping, arp=arp_mac,
                 wol_addr: tuple[str, int] = ("255.255.255.255", WOL_PORT), clock=time.time):
        self.store = store
        self.interval = interval
        self.pinger = pinger
        self.arp = arp
        self.wol_addr = wol_addr
        self.clock = clock
        self.error: str | None = None
        self._power: dict[str, Power] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._run, name="power-monitor", daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                self.poll()
            except StateError as e:
                print(f"power monitor: {e}", file=sys.stderr, flush=True)
            time.sleep(self.interval)

    def poll(self) -> None:
        """Ping every approved PC once."""
        clients = self.store.state()["clients"]
        status = self.store.status()
        for cid, c in clients.items():
            ip = (status.get(cid) or {}).get("from")
            if not ip:
                continue
            try:
                ttl = self.pinger(ip, 1.0)
            except OSError as e:
                if self.error is None:
                    self.error = f"ping not permitted ({e}); check net.ipv4.ping_group_range"
                    print(f"power monitor: {self.error}", file=sys.stderr, flush=True)
                return
            self.error = None
            self._record(cid, ttl)
            if ttl is not None and not c.get("mac"):
                mac = self.arp(ip)
                if mac:
                    self.store.set_mac(cid, mac, only_if_unset=True)
        with self._lock:
            for cid in set(self._power) - set(clients):
                del self._power[cid]

    def _record(self, cid: str, ttl: int | None) -> None:
        now = self.clock()
        with self._lock:
            p = self._power.setdefault(cid, Power())
            if ttl is not None:
                if p.state != "on":
                    p.state, p.since = "on", now
                p.misses, p.ttl, p.last_reply, p.wake_at = 0, ttl, now, None
            else:
                p.misses += 1
                if p.misses >= MISSES_FOR_OFF and p.state != "off":
                    p.state, p.since, p.down_after = "off", now, p.last_reply

    def snapshot(self, pc: dict) -> dict:
        """Power view of one entry of `Store.pcs()`."""
        now = self.clock()
        with self._lock:
            p = self._power.get(pc["id"]) or Power()
            state, wake_at = p.state, p.wake_at
            out = {"state": state, "since": p.since, "ttl": p.ttl, "os_hint": os_hint(p.ttl),
                   "running": None, "asked_at": None, "wake_failed": False}
            if self.error:
                out["state"] = "unavailable"
                out["error"] = self.error
            elif not pc.get("from"):
                out["state"] = "unknown"
            elif state == "on":
                seen = pc.get("last_seen") or 0
                if seen > p.down_after:
                    # "" = no preference: the PC booted its own default.
                    out["running"] = pc.get("last_answer") or ""
                    out["asked_at"] = seen
            if wake_at is not None and state != "on":
                if now - wake_at < WAKE_WINDOW_SECS:
                    out["state"] = "waking"
                    out["since"] = wake_at
                else:
                    out["wake_failed"] = True
            return out

    def wake(self, cid: str, target: str | None) -> None:
        """Boot `target` once (None: its usual choice) and send the magic packet."""
        c = self.store.state()["clients"].get(cid)
        if c is None:
            raise StateError("no such PC")
        if not c.get("mac"):
            raise StateError(f"no MAC address known for {c.get('name')}: enter it, or let the server "
                             "see the PC switched on once")
        if target is not None:
            self.store.set_once(cid, target)
        try:
            send_wol(c["mac"], self.wol_addr)
        except OSError as e:
            raise StateError(f"could not send the wake-up packet: {e}") from e
        with self._lock:
            self._power.setdefault(cid, Power()).wake_at = self.clock()
