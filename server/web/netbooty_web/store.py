"""The state files shared with the Rust responder (version 1).

    <data>/state/public.json    written by the responder (public keys, pairing code)
    <data>/state/state.json     written by this app / the CLI (PCs, choices, one-shots)
    <data>/state/requests.json  written by the responder (pairing requests)
    <data>/state/status.json    written by the responder (last seen / answered)

The web app never opens <data>/key; it cannot sign anything. In the container
it runs as a different user from the responder, so it could not read it either.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

VERSION = 1
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,15}$")
MAC_RE = re.compile(r"^[0-9a-f]{12}$")
ONCE_GRACE_SECS = 60


class StateError(ValueError):
    pass


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


def normalize_mac(mac: str) -> str:
    """`AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff` etc. -> `aa:bb:cc:dd:ee:ff`."""
    digits = re.sub(r"[\s:.-]", "", str(mac)).lower()
    if not MAC_RE.match(digits) or digits in ("0" * 12, "f" * 12):
        raise StateError(f"invalid MAC address {mac!r}")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


class Store:
    def __init__(self, data: str | os.PathLike):
        self.dir = Path(data) / "state"
        self._lock = threading.Lock()

    def _read(self, name: str, default: dict) -> dict:
        try:
            return json.loads((self.dir / name).read_text())
        except FileNotFoundError:
            return default
        except (OSError, ValueError) as e:
            raise StateError(f"cannot read {name}: {e}") from e

    def _write(self, name: str, value: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / f".{name}.web.tmp"
        tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.dir / name)

    def public(self) -> dict:
        return self._read("public.json", {})

    def state(self) -> dict:
        s = self._read("state.json", {"version": VERSION, "clients": {}, "dismissed": []})
        s.setdefault("clients", {})
        s.setdefault("dismissed", [])
        return s

    def requests(self) -> dict:
        return self._read("requests.json", {"version": VERSION, "requests": {}}).get("requests", {})

    def status(self) -> dict:
        return self._read("status.json", {"version": VERSION, "clients": {}}).get("clients", {})

    def update(self, fn) -> dict:
        """Read-modify-write state.json under a lock; `fn(state)` mutates it."""
        with self._lock:
            s = self.state()
            fn(s)
            s["version"] = VERSION
            self._write("state.json", s)
            return s

    # --- views -------------------------------------------------------------

    def pcs(self) -> list[dict]:
        status = self.status()
        out = []
        for cid, c in sorted(self.state()["clients"].items(), key=lambda kv: kv[1].get("name", "")):
            st = status.get(cid, {})
            once = c.get("once")
            served = st.get("once_served") or {}
            pending_once = once if once and served.get("id") != once.get("id") else None
            out.append({
                "id": cid,
                "name": c.get("name", ""),
                "targets": c.get("targets", []),
                "choice": c.get("choice"),
                "once": pending_once["target"] if pending_once else None,
                "last_seen": st.get("last_seen"),
                "from": st.get("from"),
                "last_answer": st.get("last_answer"),
                "mac": c.get("mac"),
            })
        return out

    def pending_requests(self) -> list[dict]:
        s = self.state()
        now = time.time()
        out = []
        for cid, r in self.requests().items():
            if cid in s["clients"] or cid in s["dismissed"] or now - r.get("last_seen", 0) > 24 * 3600:
                continue
            out.append({"id": cid, **r})
        return sorted(out, key=lambda r: -r.get("last_seen", 0))

    def find_pc(self, key: str) -> str:
        key = key.lower()
        clients = self.state()["clients"]
        hits = [cid for cid, c in clients.items() if cid == key or c.get("name", "").lower() == key]
        if len(hits) != 1:
            raise StateError(f"no PC {key!r}")
        return hits[0]

    # --- changes -----------------------------------------------------------

    def _check_target(self, client: dict, target: str) -> None:
        if not valid_name(target):
            raise StateError(f"invalid target name {target!r}")
        targets = client.get("targets") or []
        if targets and target.lower() not in (t.lower() for t in targets):
            raise StateError(f"{client.get('name')} has no target {target!r}")

    def set_choice(self, cid: str, target: str | None) -> None:
        def fn(s):
            c = s["clients"].get(cid)
            if c is None:
                raise StateError("no such PC")
            if target is not None:
                self._check_target(c, target)
            c["choice"] = target
        self.update(fn)

    def set_once(self, cid: str, target: str | None) -> None:
        def fn(s):
            c = s["clients"].get(cid)
            if c is None:
                raise StateError("no such PC")
            if target is None:
                c["once"] = None
            else:
                self._check_target(c, target)
                c["once"] = {"id": secrets.token_hex(8), "target": target}
        self.update(fn)

    def set_mac(self, cid: str, mac: str | None, only_if_unset: bool = False) -> None:
        mac = normalize_mac(mac) if mac else None

        def fn(s):
            c = s["clients"].get(cid)
            if c is None:
                raise StateError("no such PC")
            if only_if_unset and c.get("mac"):
                return
            if mac:
                c["mac"] = mac
            else:
                c.pop("mac", None)
        self.update(fn)

    def approve(self, cid: str, name: str, targets: list[str]) -> None:
        if not re.fullmatch(r"[0-9a-f]{32}", cid):
            raise StateError("bad client id")
        if not name or len(name) > 63:
            raise StateError("give the PC a name")
        bad = [t for t in targets if not valid_name(t)]
        if bad:
            raise StateError(f"invalid target names: {', '.join(bad)}")

        def fn(s):
            if any(c.get("name", "").lower() == name.lower() for k, c in s["clients"].items() if k != cid):
                raise StateError(f"a PC named {name!r} already exists")
            s["clients"][cid] = {"name": name, "targets": targets, "choice": None, "once": None}
            if cid in s["dismissed"]:
                s["dismissed"].remove(cid)
        self.update(fn)

    def dismiss(self, cid: str) -> None:
        self.update(lambda s: cid in s["dismissed"] or s["dismissed"].append(cid))

    def remove(self, cid: str) -> None:
        self.update(lambda s: s["clients"].pop(cid, None))
