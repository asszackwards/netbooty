"""QEMU/OVMF harness for NetBooty end-to-end tests.

Each scenario builds GPT disk images with an ESP, runs `testsetup.efi` once to
create Boot#### entries in a fresh OVMF variable store, then boots again and
captures the serial console until the stand-in target powers the VM off.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Test builds include `test-hooks` (simulated firmware faults), so they go to
# their own target dir and can never be mistaken for an installable build.
BUILD_DIR = ROOT / "target" / "e2e"
EFI_DIR = BUILD_DIR / "x86_64-unknown-uefi" / "release"
SETUP_BIN = BUILD_DIR / "debug" / "netbooty-setup"
OVMF_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
OVMF_VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
# Secure Boot build (SMM) and a variable store with Microsoft's keys enrolled,
# so Microsoft-signed shims boot as on real hardware.
OVMF_CODE_SB = Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
OVMF_VARS_MS = Path("/usr/share/OVMF/OVMF_VARS_4M.ms.fd")

DISK_MB = 64
PART_OFFSET = 1024 * 1024


def run(*cmd: str | os.PathLike, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], check=True, capture_output=True, text=True, **kw)


def build_all() -> None:
    env = dict(os.environ, PATH=f"{Path.home()}/.cargo/bin:{os.environ['PATH']}", CARGO_TARGET_DIR=str(BUILD_DIR))
    run("cargo", "build", "--release", "--target", "x86_64-unknown-uefi", "-p", "netbooty", "-p", "testbed",
        "--features", "netbooty/test-hooks",
        cwd=ROOT, env=env)
    run("cargo", "build", "-p", "netbooty-setup", cwd=ROOT, env=env)


@dataclass
class Disk:
    """A GPT disk with a single FAT ESP partition."""

    path: Path
    part_guid: str
    files: dict[str, Path] = field(default_factory=dict)  # ESP path -> local file

    def _img(self) -> str:
        return f"{self.path}@@{PART_OFFSET}"

    def create(self) -> None:
        with open(self.path, "wb") as f:
            f.truncate(DISK_MB * 1024 * 1024)
        run("sgdisk", "-n", "1:2048:0", "-t", "1:ef00", "-u", f"1:{self.part_guid}", self.path)
        sectors = (DISK_MB * 1024 * 1024 - PART_OFFSET) // 512 - 34
        run("mformat", "-i", self._img(), "-T", str(sectors), "-h", "1", "-s", "32", "-v", "ESP", "::")
        for dest, src in self.files.items():
            self.put(dest, src)

    def put(self, dest: str, src: Path) -> None:
        parts = dest.strip("\\").split("\\")
        for i in range(1, len(parts)):
            d = "::/" + "/".join(parts[:i])
            subprocess.run(["mmd", "-D", "s", "-i", self._img(), d], capture_output=True)
        run("mcopy", "-o", "-i", self._img(), src, "::/" + "/".join(parts))

    def delete(self, dest: str) -> None:
        run("mdel", "-i", self._img(), "::/" + dest.strip("\\").replace("\\", "/"))


@dataclass
class Result:
    output: str
    exited: bool

    def has(self, s: str) -> bool:
        return s in self.output

    def target(self) -> str | None:
        for line in self.output.splitlines():
            line = line.strip()
            if line.startswith("TARGET "):
                return line[len("TARGET "):].strip()
        return None


class Machine:
    def __init__(self, workdir: Path, disks: list[Disk], secure_boot: bool = False):
        self.workdir = workdir
        self.disks = disks
        self.secure_boot = secure_boot
        self.vars = workdir / "vars.fd"
        shutil.copy(OVMF_VARS_MS if secure_boot else OVMF_VARS, self.vars)

    def boot(self, timeout: float = 60, keys: list[tuple[str, str]] | None = None,
             extra: list[str] | None = None, attach: list[Disk] | None = None,
             enforce: bool | None = None, nic: str = "none") -> Result:
        """Boot until the VM powers off. `keys` is a list of (wait_for, send):
        once `wait_for` appears on the console, `send` is typed over serial."""
        # The non-SB firmware build never verifies images, even with keys
        # enrolled; testsetup (unsigned) runs that way against the same store.
        sb = self.secure_boot if enforce is None else enforce
        args = [
            "qemu-system-x86_64", "-enable-kvm", "-machine", "q35,smm=on" if sb else "q35", "-m", "512",
            "-display", "none", "-monitor", "none", "-serial", "stdio",
            "-drive", f"if=pflash,format=raw,readonly=on,file={OVMF_CODE_SB if sb else OVMF_CODE}",
            "-drive", f"if=pflash,format=raw,file={self.vars}",
            "-nic", nic,
        ]
        if sb:
            args += ["-global", "driver=cfi.pflash01,property=secure,value=on"]
        # No -no-reboot: NetBooty's reset must restart the firmware in the same
        # VM; the run ends when the stand-in target powers off.
        for d in attach if attach is not None else self.disks:
            args += ["-drive", f"format=raw,file={d.path},if=virtio"]
        args += extra or []

        proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        chunks: list[bytes] = []

        def reader():
            assert proc.stdout
            while b := proc.stdout.read1(4096):
                chunks.append(b)

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        pending = list(keys or [])
        deadline = time.monotonic() + timeout
        exited = False
        seen = 0  # each trigger only matches output after the previous keystroke
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                exited = True
                break
            text = b"".join(chunks).decode(errors="replace")
            if pending and pending[0][0] in text[seen:]:
                _, send = pending.pop(0)
                seen = len(text)
                assert proc.stdin
                proc.stdin.write(send.encode())
                proc.stdin.flush()
            time.sleep(0.05)
        if not exited:
            proc.kill()
        proc.wait()
        t.join(timeout=2)
        out = b"".join(chunks).decode(errors="replace")
        (self.workdir / f"console-{int(time.time() * 1000)}.log").write_text(out)
        return Result(out, exited)

    def setup(self, script: str, setup_disk: Disk) -> Result:
        """Run testsetup.efi from `setup_disk` as the removable-media loader,
        then remove it so later boots cannot fall back into it."""
        script_file = self.workdir / "netbooty-test.txt"
        script_file.write_text(script)
        setup_disk.put("\\netbooty-test.txt", script_file)
        setup_disk.put("\\EFI\\BOOT\\BOOTX64.EFI", EFI_DIR / "testsetup.efi")
        r = self.boot(timeout=60, enforce=False)
        setup_disk.delete("\\EFI\\BOOT\\BOOTX64.EFI")
        assert r.has("TESTSETUP: done"), r.output
        return r


def patch(workdir: Path, *args: str) -> Path:
    out = workdir / "netbooty.efi"
    run(SETUP_BIN, "patch", *args, EFI_DIR / "netbooty.efi", out)
    return out


def make_test_key(directory: Path) -> tuple[Path, Path, Path]:
    """Throwaway signing key (like `netbooty-setup keygen`) for QEMU tests."""
    key, crt, der = directory / "test.key", directory / "test.crt", directory / "test.der"
    run("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "3650",
        "-subj", "/CN=NetBooty test key/", "-addext", "extendedKeyUsage=codeSigning",
        "-keyout", key, "-out", crt)
    run("openssl", "x509", "-outform", "DER", "-in", crt, "-out", der)
    return key, crt, der


def sign(src: Path, dst: Path, key: Path, crt: Path) -> Path:
    run("sbsign", "--key", key, "--cert", crt, "--output", dst, src)
    return dst
