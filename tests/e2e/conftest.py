import shutil

import pytest

import harness

GUID_A = "aaaaaaaa-0000-4000-8000-00000000000a"
GUID_B = "bbbbbbbb-0000-4000-8000-00000000000b"

BASE_SCRIPT = """\
entry 0100 NetBooty \\EFI\\netbooty\\netbooty.efi
entry 0101 alpha \\EFI\\alpha\\a.efi
entry 0102 beta \\EFI\\beta\\b.efi
entry 0103 Windows_Boot_Manager \\EFI\\Microsoft\\Boot\\bootmgfw.efi
entry 0104 UEFI_OS \\EFI\\BOOT\\BOOTX64.EFI fs=0
entry 0105 UEFI_OS \\EFI\\BOOT\\BOOTX64.EFI fs=1
entry 0106 gone \\EFI\\gone\\g.efi
order 0100 0101 0102 0103
"""

BASE_TARGETS = [
    "name=alpha,path=\\EFI\\alpha\\a.efi,key=a",
    "name=beta,path=\\EFI\\beta\\b.efi",
    f"name=windows,path=\\EFI\\Microsoft\\Boot\\bootmgfw.efi,part={GUID_B}",
    "name=fb,path=\\EFI\\BOOT\\BOOTX64.EFI",
    f"name=fbb,path=\\EFI\\BOOT\\BOOTX64.EFI,part={GUID_B}",
    "name=gone,path=\\EFI\\gone\\g.efi",
]


@pytest.fixture(scope="session", autouse=True)
def built():
    for tool in ("qemu-system-x86_64", "sgdisk", "mformat", "mcopy"):
        if not shutil.which(tool):
            pytest.skip(f"{tool} not installed")
    harness.build_all()


class Scenario:
    """Two disks: A holds NetBooty and the alpha/beta targets, B stands in for
    a separate Windows disk. Both carry an \\EFI\\BOOT\\BOOTX64.EFI."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.a = harness.Disk(tmp_path / "a.img", GUID_A)
        self.b = harness.Disk(tmp_path / "b.img", GUID_B)

    def prepare(self, *patch_args: str, script_extra: str = "", targets=None):
        efi = harness.EFI_DIR
        target_args = [x for t in (targets or BASE_TARGETS) for x in ("--target", t)]
        nb = harness.patch(self.tmp, *target_args, *patch_args)
        self.a.files = {
            "\\EFI\\netbooty\\netbooty.efi": nb,
            "\\EFI\\alpha\\a.efi": efi / "target.efi",
            "\\EFI\\beta\\b.efi": efi / "target.efi",
            "\\EFI\\gone\\g.efi": efi / "target.efi",
        }
        self.b.files = {
            "\\EFI\\Microsoft\\Boot\\bootmgfw.efi": efi / "target.efi",
            "\\EFI\\BOOT\\BOOTX64.EFI": efi / "target.efi",
        }
        self.a.create()
        self.b.create()
        self.machine = harness.Machine(self.tmp, [self.a, self.b])
        # testsetup runs as disk A's BOOTX64.EFI; both volumes have that path
        # during setup, so entries 0104/0105 can be created on each.
        self.machine.setup(BASE_SCRIPT + script_extra, self.a)
        self.a.put("\\EFI\\BOOT\\BOOTX64.EFI", efi / "target.efi")
        self.a.delete("\\EFI\\gone\\g.efi")
        return self

    def boot(self, **kw):
        return self.machine.boot(**kw)


@pytest.fixture
def scenario(tmp_path):
    return Scenario(tmp_path)
