#!/usr/bin/env python3
"""Stand-in NetBooty responder for milestone 3 (stdlib only).

Answers every well-formed 37-byte NetBooty request with 80 placeholder bytes
(the size of a real reply) and logs who asked. NetBooty only reports replies
in milestone 3, so the content does not matter yet.

    python3 echo_responder.py [--port 47000]

Run it on any machine on the same LAN as the PC to check that NetBooty's
firmware networking works there.
"""

import argparse
import socket
import sys

MAGIC = b"NBTY1"
REQUEST_LEN = 37
REPLY = b"echo".ljust(16, b"\0") + bytes(64)


def serve(port: int, once: bool = False, out=sys.stdout) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    print(f"listening on udp/{port}", file=out, flush=True)
    while True:
        data, addr = sock.recvfrom(2048)
        if len(data) != REQUEST_LEN or not data.startswith(MAGIC):
            print(f"ignored {len(data)} bytes from {addr[0]}:{addr[1]}", file=out, flush=True)
            continue
        client_id, nonce = data[5:21].hex(), data[21:37].hex()
        print(f"request from {addr[0]}:{addr[1]} client {client_id} nonce {nonce}", file=out, flush=True)
        sock.sendto(REPLY, addr)
        if once:
            return


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=47000)
    args = ap.parse_args()
    try:
        serve(args.port)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
