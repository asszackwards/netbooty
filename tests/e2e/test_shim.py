"""Booting NetBooty behind the distro shim installed on this machine
(Microsoft-signed), with and without Secure Boot enforced.

Layout matches `netbooty-setup install` in shim mode: a private copy of shim
and MokManager in \\EFI\\netbooty\\ with NetBooty as shim's default second stage
(grubx64.efi), so NetBooty's entry never shares a boot path with the distro's
entry (AMI firmware deletes such duplicates)."""

import shutil
from pathlib import Path

import pytest

import harness
from conftest import GUID_A

SHIM_DIR = Path("/boot/efi/EFI/ubuntu")
SHIM = SHIM_DIR / "shimx64.efi"
MM = SHIM_DIR / "mmx64.efi"

pytestmark = pytest.mark.skipif(
    not (SHIM.exists() and MM.exists() and harness.OVMF_CODE_SB.exists() and shutil.which("sbsign")),
    reason="needs a distro shim in /boot/efi/EFI/ubuntu, Secure Boot OVMF and sbsign",
)

# 0050 is a leftover entry from the old install layout (Ubuntu's shim with a
# path argument): it shares loader and partition with the `linux` target and
# must never be chosen as that target.
SCRIPT = """\
entry 0050 NetBooty_old \\EFI\\ubuntu\\shimx64.efi opt=\\EFI\\netbooty\\grubx64.efi
entry 0100 NetBooty \\EFI\\netbooty\\shimx64.efi
entry 0101 ubuntu \\EFI\\ubuntu\\shimx64.efi
order 0100 0101
"""


@pytest.fixture(scope="module")
def test_key(tmp_path_factory):
    return harness.make_test_key(tmp_path_factory.mktemp("key"))


def boot_via_shim(tmp_path, *, secure_boot, sign_netbooty, key=None, enroll=False, **boot_kw):
    efi = harness.EFI_DIR
    nb = harness.patch(tmp_path, "--target", f"name=linux,path=\\EFI\\ubuntu\\shimx64.efi,part={GUID_A}",
                       "--default", "linux")
    grub = efi / "target.efi"  # stands in for GRUB behind Ubuntu's entry
    if key:
        k, crt, _ = key
        grub = harness.sign(grub, tmp_path / "grubx64.efi", k, crt)
        if sign_netbooty:
            nb = harness.sign(nb, tmp_path / "netbooty.signed.efi", k, crt)
    disk = harness.Disk(tmp_path / "a.img", GUID_A, {
        "\\EFI\\ubuntu\\shimx64.efi": SHIM,
        "\\EFI\\ubuntu\\mmx64.efi": MM,
        "\\EFI\\ubuntu\\grubx64.efi": grub,
        "\\EFI\\netbooty\\shimx64.efi": SHIM,
        "\\EFI\\netbooty\\mmx64.efi": MM,
        "\\EFI\\netbooty\\grubx64.efi": nb,
    })
    if key:
        disk.files["\\test.der"] = key[2]
    disk.create()
    m = harness.Machine(tmp_path, [disk], secure_boot=secure_boot)
    m.setup(SCRIPT + ("mok \\test.der\n" if enroll else ""), disk)
    return m.boot(**boot_kw)


def test_private_shim_copy_without_secure_boot(tmp_path):
    r = boot_via_shim(tmp_path, secure_boot=False, sign_netbooty=False)
    assert r.has("NETBOOTY: target=linux -> Boot0101")
    assert r.target() == "ubuntu"


def test_signed_with_enrolled_mok_under_secure_boot(tmp_path, test_key):
    r = boot_via_shim(tmp_path, secure_boot=True, sign_netbooty=True, key=test_key, enroll=True)
    assert r.has("NETBOOTY: target=linux -> Boot0101")
    assert r.target() == "ubuntu"


def test_unenrolled_netbooty_falls_through(tmp_path, test_key):
    # Signed, but its key is not in MokList: shim refuses it, waits at the
    # error, and the firmware then boots the next entry.
    r = boot_via_shim(tmp_path, secure_boot=True, sign_netbooty=False, key=test_key, enroll=True,
                      keys=[("Verification failed", "\r")] * 4, timeout=120)
    assert r.has("Verification failed")
    assert not r.has("NETBOOTY:")
    assert r.target() == "ubuntu"
