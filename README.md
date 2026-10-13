# NetBooty

A small UEFI boot selector for multi-boot PCs. NetBooty shows a GRUB-style menu
(or none), picks a boot target, sets the firmware's `BootNext` and resets, so the
firmware starts the chosen OS's **own** boot entry. Nothing is chainloaded, so
each OS's measured boot stays as if it had been started directly (BitLocker
keeps its PCR7 binding, for example).

- Works with any UEFI firmware and any set of OSes on one or more disks
- Secure Boot via the distro's signed shim and a dedicated MOK, your own keys
  (e.g. sbctl), or Secure Boot off
- OS-side one-shot requests ("boot Windows next") from Linux and Windows
- Keeps itself first in the boot order after OS updates
- Remote selection over the LAN (signed UDP) is in progress

## Quick start (Linux)

Requirements: a UEFI system, Linux with systemd, and `efibootmgr`, `openssl`,
`lsblk` (plus `sbsign` and `mokutil` with Secure Boot). The bootstrap script
tells you the exact package names for your distro and installs Rust targets as
needed (Rust itself comes from [rustup](https://rustup.rs)).

```bash
git clone https://github.com/asszackwards/netbooty
cd netbooty
scripts/bootstrap.sh                      # checks tools, builds
sudo ./target/release/netbooty-setup      # interactive installer
```

The installer finds your OSes from the firmware's boot entries and asks which
to offer, their names and menu keys, the default, and how the menu behaves.
Preview it first, without changing anything:

```bash
./target/release/netbooty-setup setup --dry-run
```

Then it walks you through the rest. Run `sudo netbooty-setup` again at any step:

1. **Secure Boot only:** it creates a signing key and queues it for shim
   (`mokutil` asks for a one-time password). Reboot; in the blue **MokManager**
   screen press a key within 10 seconds, choose *Enroll MOK → Continue → Yes*,
   enter the password, *Reboot*.
2. **Try it once.** NetBooty is installed but not yet the default; the installer
   offers a one-time reboot into it. Your normal boot is untouched if anything
   is wrong.
3. **Activate.** Choose *Make NetBooty the default boot entry* (or run
   `sudo netbooty-setup activate`).

After installing, `netbooty-setup` lives in `/usr/local/sbin`, its settings in
`/etc/netbooty/netbooty.toml`, and a systemd service keeps the installation
healthy (see [Maintenance](#maintenance)).

### Menu

↑/↓ move, Enter boots the highlighted entry, numbers and the shown letters boot
directly. *Automatic* (the first row, chosen when the countdown ends) boots a
pending OS request, otherwise the default.

## Everyday use

| From | Command |
|---|---|
| Linux | `sudo netbooty-setup next windows` boots *windows* once on the next boot (`next clear` cancels) |
| Linux | `sudo netbooty-setup doctor` shows a read-only report of boot entries, targets, keys and services |
| Linux | `sudo netbooty-setup` lets you change settings, repair or uninstall |
| Windows | `tools\windows\netbooty.ps1 next linux` (elevated PowerShell) |

### Windows helper

`tools/windows/netbooty.ps1` (run from an elevated PowerShell):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\netbooty.ps1 status              # boot order and pending request
.\netbooty.ps1 next linux          # boot "linux" once on the next boot
.\netbooty.ps1 install-task        # keep NetBooty first after Windows Update
```

## Maintenance

OS updates can put their own boot entry first, and a distro shim update makes
NetBooty's copy outdated. `netbooty-maintain.service` runs `netbooty-setup
maintain` at every boot and shutdown, and `netbooty-refresh.path` runs it when
the distro shim changes. It:

- moves NetBooty back to the front of BootOrder,
- refreshes NetBooty's copy of shim and MokManager,
- reinstalls NetBooty if its boot entry or files disappeared,

and changes nothing when all is well. On Windows, `install-task` does the boot
order part at startup.

## How it is installed (shim mode)

```
\EFI\netbooty\shimx64.efi   copy of the distro's shim (Microsoft-signed)
\EFI\netbooty\mmx64.efi     copy of MokManager
\EFI\netbooty\grubx64.efi   NetBooty, signed with its own MOK
Boot#### "NetBooty"         -> \EFI\netbooty\shimx64.efi
```

NetBooty's boot entry points at its own copy of shim rather than the distro's
shim with an argument: some firmware (seen on AMI Aptio) treats entries with the
same file path as duplicates and deletes one of them.

## Uninstall

```bash
sudo netbooty-setup uninstall
```

Removes the boot entry, the files on the ESP, the services, settings and the
installed tool. The signing key in `/var/lib/netbooty/keys` is kept; to also
remove it from shim: `sudo mokutil --delete /var/lib/netbooty/keys/netbooty.der`.

## Recovery

NetBooty never removes other boot entries, and if it cannot boot its choice it
returns to the firmware, which continues with the next entry. If something still
goes wrong, use your firmware's boot menu (often F12, F11 or Esc at power-on) to
start an OS directly, then run `sudo netbooty-setup` to repair or uninstall.

## Development

```bash
cargo test                                  # host crates
cd tests/e2e && python3 -m pytest -q       # QEMU/OVMF boot scenarios (needs qemu, ovmf, mtools, sgdisk)
```

The QEMU suite boots NetBooty against real GPT disk images, including two-disk
layouts, the distro shim with Secure Boot enforced, and simulated firmware that
ignores `BootNext`. See `design.md` for the design and the network protocol.
