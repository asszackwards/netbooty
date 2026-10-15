# NetBooty

```
        ((o))
          |
  .-"""-. | .-"""-.
 /       \|/       \
|         |         |
|         |         |
 \        |        /
  '-.___.-'-.___.-'
```

Choose which OS your multi-boot PCs start, see what they're running, and wake
them straight into an OS, from anywhere on your network.

NetBooty is a small UEFI boot selector. On every boot it asks a boot server on
your LAN which OS to start. You set that from a web page or a JSON API, either
until you change it or for the next boot only, so nobody needs to be at the PC.
The same page shows which PCs are on and wakes those that are off. NetBooty
then sets the firmware's `BootNext` and resets, and the firmware starts
the chosen OS's **own** boot entry. Nothing is chainloaded, so each OS's
measured boot stays as if it had been started directly (BitLocker keeps its
PCR7 binding, for example).

- **Remote OS choice:** the boot server (one small Docker container) decides
  what each paired PC boots, always or just once
- **Power and wake:** the web page shows which PCs are on and what they are
  probably running, and wakes a PC that is off straight into the OS you pick
  (Wake-on-LAN)
- **Signed answers:** NetBooty only acts on replies signed by its paired server
  for this PC and this boot. Anyone else on the LAN can at most make it fall
  back to its default
- **No PXE or extra hardware:** it uses the firmware's own network stack, and
  the network step runs during the menu countdown
- Local control too: a GRUB-style menu, and one-shot requests ("boot Windows
  next") from Linux and Windows
- Works with any UEFI firmware, and boots any OS that has a UEFI boot entry, on
  one or more disks. Installing and configuring it needs one Linux install on
  the PC
- Secure Boot via the distro's signed shim and a dedicated MOK, your own keys
  (e.g. sbctl), or Secure Boot off
- Keeps itself first in the boot order after OS updates

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
pending OS request, otherwise the default. The first key press restarts the
countdown at 20 s, and later keys do not restart it again, so a stuck key or a
forgotten menu cannot hold up the boot. A menu opened by holding a key counts
down 20 s from the start.

### Network

On every boot NetBooty asks the LAN for a boot server, using the firmware's own
network stack (DHCP, then a UDP broadcast on port 47000, plus the server's
address if it is known). It runs during the menu countdown, so it normally adds
no boot time; the menu shows its progress on the *Network:* line and the
server's choice on the *Automatic* row.

Order of precedence: **menu pick → OS request (`next`) → boot server → default.**

- Enable the firmware's network stack in its setup (often *Network Stack* or
  *UEFI Network Stack*; PXE itself can stay off).
- `sudo netbooty-setup doctor` shows the last result under *Last network*.
  `no network stack` with "network card found…" means the stack is disabled
  in firmware setup, or the firmware lacks a random number generator (newer
  EDK2-based firmware won't start networking without one).
- Settings: `--network off`, `--net-timeout <ms>` (time to get an address,
  default 10000; the wait overlaps the menu countdown), `--net-server <ip>`,
  `--net-port`. Pass them to `sudo netbooty-setup install`.

## Boot server

A small server on your LAN decides what each paired PC boots. It is one
container (host networking) running two processes as separate users:

- **responder** (Rust, UDP 47000): answers PCs at boot. The only user that can
  read the signing key.
- **web** (Python, Flask served by waitress, port 8470): pairing, approving
  PCs, choosing what they boot, power status and Wake-on-LAN, and a JSON API.
  It cannot read the key.

```bash
cd server
cp .env.example .env            # set NETBOOTY_PASSWORD
docker compose up -d
```

To build on another machine instead, run `scripts/push-server.sh` there (after
`docker login ghcr.io` with a token that has `write:packages`); it pushes
`ghcr.io/asszackwards/netbooty-server:latest`. On the server, update with
`docker compose pull && docker compose up -d`. A private package needs
`docker login ghcr.io` (with `read:packages`) on the server too.

Open `http://<server>:8470` and log in. On the PC, either let it find the
server itself:

```bash
sudo netbooty-setup pair --discover      # or "Find a NetBooty server" in `sudo netbooty-setup`
```

or copy the command from the web page's **Pair** tab:

```bash
sudo netbooty-setup pair 'netbooty-pair:1:…'
```

Either way it shows the server's key fingerprint: **check that it matches the
web page** (that check is what stops another machine on the LAN from posing as
your server). It then reinstalls NetBooty with the server's key and announces
the PC. Approve it under *New PCs* on the **Pair** tab (the tab shows how many
are waiting), then choose what it boots on the **PCs** tab. Changes save as you
pick them:

- **Boots**: the persistent choice, or *its own default*.
- **Next boot only**: boot a target on the next boot only, then go back to the
  choice.
- **Settings** (on each PC): rename it, change its targets, set its MAC
  address, or remove it.

Security: NetBooty only acts on replies signed by the paired key, for its own
client ID and a fresh nonce from this boot. Anyone else on the LAN can at most
make it fall back to its default. Unapproved PCs get no answer.

**Without the web app** (`docker compose exec netbooty netbooty-server …`):
`status`, `client list`, `client approve <id|hostname> --name pc`,
`set <pc> <target|none>`, `next <pc> <target>`, `pair`.

**API** (`Authorization: Bearer $NETBOOTY_API_TOKEN`, or a login session):

```bash
curl -H "Authorization: Bearer $TOKEN" http://server:8470/api/state
curl -H "Authorization: Bearer $TOKEN" -d '{"target":"windows"}' http://server:8470/api/pcs/gamingpc/once
curl -H "Authorization: Bearer $TOKEN" -d '{"target":null}'      http://server:8470/api/pcs/gamingpc/choice
curl -H "Authorization: Bearer $TOKEN" -d '{"target":"linux"}'   http://server:8470/api/pcs/gamingpc/wake
curl -H "Authorization: Bearer $TOKEN" -d '{"mac":"aa:bb:cc:dd:ee:ff"}' http://server:8470/api/pcs/gamingpc/mac
curl -H "Authorization: Bearer $TOKEN" -d '{"name":"bigrig","targets":["windows","linux"]}' http://server:8470/api/pcs/gamingpc
```

### Power and wake

The server pings each PC (every 15 s, `NETBOOTY_PING_SECS`) at the address it
last asked from, and shows it as **On** or **Off**. For a PC that is on it also
shows what it is *probably* running: what the server answered when it booted,
if it asked during this power-on (a menu pick or OS request on the PC is not
seen), plus a hint from the ping's TTL (Windows replies with 128, Linux with 64).

When a PC is off, *Wake into* sets a one-time choice (or keeps its usual one)
and sends a Wake-on-LAN packet. NetBooty then asks the server and boots that OS.
The server learns the PC's MAC address the first time it sees it on; you can
also enter it under the PC's *Settings*.

- Enable Wake-on-LAN in the BIOS (on many boards: *ErP* off, *Wake on LAN*
  on), and in the OS's network card settings if it should also wake from sleep.
- Windows does not answer ping by default. In an elevated PowerShell:
  `Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In`.
- The container pings with a raw socket its launcher opens before dropping
  root, so no host setting is needed. If the page says *Power status
  unavailable*, the container was started without Docker's default
  capabilities (it needs `NET_RAW`).

Notes:
- PCs find the server by broadcast and also ask its address directly, for
  networks where broadcast does not reach. `--discover` records the address
  the server answered from; a copied code uses the address you opened the web
  page at (or `NETBOOTY_ADVERTISE_IP`, if set in `compose.yaml`). Give the
  server a fixed address (DHCP reservation).
- The container must use host networking (as in `compose.yaml`): broadcasts
  from PCs and Wake-on-LAN packets do not cross Docker's networks. The
  responder logs a warning if it finds itself on a container network.
- The web port is plain HTTP. Keep it on your LAN or put it behind a reverse
  proxy with TLS.
- **Key rotation:** `docker compose exec netbooty netbooty-server keygen --next`,
  re-pair each PC with the new code (it lists both keys), then
  `… keygen --promote`.

## Everyday use

| From | Command |
|---|---|
| Linux | `sudo netbooty-setup next windows` boots *windows* once on the next boot (`next clear` cancels) |
| Linux | `sudo netbooty-setup announce` shows this PC to the paired server again for approval |
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
cd server/web && python3 -m pytest -q     # web app
```

The QEMU suite boots NetBooty against real GPT disk images, including two-disk
layouts, the distro shim with Secure Boot enforced, and simulated firmware that
ignores `BootNext`.
