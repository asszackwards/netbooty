"""Container entrypoint: run the responder and the web app as two users.

Started as root only to fix up the data directories, then:

    responder (uid 10001)  netbooty-server serve; the only user that can read <data>/key
    web       (uid 10002)  this web app; shares <data>/state through the netbooty group

If either exits, the other is stopped and the container exits, so the
restart policy restarts both.
"""

from __future__ import annotations

import os
import pwd
import grp
import signal
import subprocess
import sys

RESPONDER = "/usr/local/libexec/netbooty-server"
GROUP = "netbooty"


def fix_permissions(data: str, responder: int, group: int) -> None:
    """Key: responder only. State: shared, group-writable (setgid dir).
    Also migrates volumes from the two-container layout."""
    key, state = os.path.join(data, "key"), os.path.join(data, "state")
    for d in (key, state):
        os.makedirs(d, exist_ok=True)
    for root, dirs, files in os.walk(key):
        os.chown(root, responder, group)
        os.chmod(root, 0o700)
        for f in files:
            os.chown(os.path.join(root, f), responder, group)
            os.chmod(os.path.join(root, f), 0o600)
    os.chown(state, responder, group)
    os.chmod(state, 0o2775)
    for f in os.listdir(state):
        p = os.path.join(state, f)
        if os.path.isfile(p):
            os.chown(p, responder, group)
            os.chmod(p, 0o664)


def main() -> None:
    data = os.environ.get("NETBOOTY_DATA", "/data")
    gid = grp.getgrnam(GROUP).gr_gid
    fix_permissions(data, pwd.getpwnam("responder").pw_uid, gid)

    def start(user: str, cmd: list[str]) -> subprocess.Popen:
        return subprocess.Popen(cmd, user=user, group=GROUP, extra_groups=[], umask=0o002,
                                env={**os.environ, "HOME": "/tmp"})

    procs = [
        start("responder", [RESPONDER, "serve"]),
        start("web", [sys.executable, "-m", "netbooty_web"]),
    ]

    stopping = False

    def forward(sig, _frame):
        nonlocal stopping
        stopping = True
        for p in procs:
            if p.poll() is None:
                p.send_signal(sig)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)

    pid, status = os.wait()
    code = os.waitstatus_to_exitcode(status)
    if not stopping:
        name = "responder" if pid == procs[0].pid else "web app"
        print(f"{name} exited ({code}); stopping", file=sys.stderr, flush=True)
    for p in procs:
        if p.pid != pid and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    sys.exit(0 if stopping else code or 1)


if __name__ == "__main__":
    main()
