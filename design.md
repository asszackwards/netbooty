# bootsel — remote-controlled UEFI next-boot selector

## Goal
Dual-boot PC (Windows 11 + Ubuntu) on a Gigabyte Aorus Z790 (AMI Aptio V firmware).
Let a trusted boot server on the LAN choose which OS boots, while keeping both OSes'
TPM measurements pristine (BitLocker PCR7 binding stays valid; no Windows chainload via GRUB).

## Core idea
A tiny pre-boot UEFI application ("selector") that never loads an OS itself:
1. Decide which OS to boot.
2. `SetVariable(BootNext = <Boot#### of chosen OS>)`.
3. `ResetSystem(EfiResetWarm)`.
The firmware consumes BootNext and launches the chosen OS's own boot entry directly after
a platform reset, so PCRs contain no trace of the selector.

It is a "next-boot selector", not a bootloader. rEFInd and GRUB are NOT used for Windows.

## Boot entries (created with efibootmgr from Ubuntu)
```
Boot0001 "Selector" -> \EFI\ubuntu\shimx64.efi  optional data: \EFI\bootsel\selector.efi
Boot0002 "ubuntu"   -> \EFI\ubuntu\shimx64.efi  (no options -> shim loads grubx64.efi)
Boot0000 "Windows Boot Manager" -> \EFI\Microsoft\Boot\bootmgfw.efi
BootOrder: 0001,0002,0000
```
- Selector binary lives on the shared ESP in its own dir: `\EFI\bootsel\` (outside `\EFI\ubuntu`,
  which Ubuntu packages manage).
- Uses Ubuntu's signed shim (already trusted on this machine) so shim stays updated by apt.
- Fallback if firmware drops optional data or dedupes entries pointing at the same file:
  copy shim + mmx64.efi into `\EFI\bootsel\`, name selector `grubx64.efi`, and keep the copy fresh
  with an apt `DPkg::Post-Invoke` hook on shim-signed updates.
- `GRUB_DISABLE_OS_PROBER=true` so GRUB never offers a Windows chainload entry.

## Selector decision order (first that answers wins; whole decision budget ~2 s)
1. Held key at startup -> local text menu (physical presence override).
2. Network: signed UDP exchange with boot server (see protocol).
3. (Optional) SMBIOS Type 1 wake-up type (offset 0x18: 0x05 LAN Remote, 0x06 Power Switch,
   0x07 PCI PME#, 0x08 AC Power Restored) — e.g. WoL -> Windows. Verify board reports it.
4. Built-in default (Linux).
Any error/timeout/invalid reply -> default. Never trust unsigned data.

Each run also re-asserts BootOrder so the selector stays first (Windows Update reorders it).

## Network protocol (UDP, custom — no HTTP/TLS in pre-boot)
- Use the firmware's network stack (BIOS: Settings -> IO Ports -> Network Stack: Enabled; IPv4 PXE off).
- Steps: ConnectController on NIC handles if SNP missing (Fast Boot) -> EFI_IP4_CONFIG2 policy DHCP,
  poll for StationAddress with deadline -> EFI_UDP4 service binding CreateChild -> send/recv.
- Server addressed by IP literal (no DNS). Port 47000 (configurable).
- Request:  `"BSEL1" || nonce[16]`  (nonce from EFI_RNG_PROTOCOL)
- Reply:    `choice[1] || sig[64]`, choice in {'L','W'}
- sig = Ed25519 over `"BSEL1-resp" || nonce || choice`
- Verify with embedded public key(s) (support current + next key for rotation). ~500 ms wait, 1–2 retries.
- Threat model: only the trusted server can choose the OS; LAN attacker can at most DoS -> default boot.
- HTTPS/Tailscale belongs only on the control side (user/Home Assistant -> boot server).

## Config / key provisioning ("provision, then sign")
- Reserved fixed-size section `.bselcfg` (e.g. 256 bytes) starting with magic `BSELCFG1`, holding:
  server pubkey(s) (raw 32-byte Ed25519), server IP/port, Boot#### numbers, default.
- Read via `core::ptr::read_volatile` so the optimizer can't constant-fold the placeholder.
- Setup tool: verify release hash -> patch `.bselcfg` in place (no size change) -> sign with user's key
  -> install to ESP -> create efibootmgr entry. Users never need to compile.
- Do NOT put config/keys in a loose file on the ESP or appended overlay (unauthenticated / TOCTOU).
- Optional later: MokManager-style enrollment into a boot-services-only NV variable.

## Secure Boot / signing
- Sign selector with a dedicated MOK (NOT Ubuntu's DKMS MOK — it has the module-signing-only EKU
  1.3.6.1.4.1.2312.16.1.2 which shim rejects for EFI images).
- Binary must contain a `.sbat` section or modern shim refuses it:
  ```
  sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
  bootsel,1,<author>,bootsel,0.1,<repo url>
  ```
  Embed via `#[used] #[link_section = ".sbat"] static SBAT: [u8; N] = *b"...";`
- Sign: `sbsign --key sel.key --cert sel.crt --output out.efi in.efi`.
  Verify: `sbverify --cert sel.crt out.efi`. Enroll: `mokutil --import sel.der`.

## Build (Rust, on the PC's Ubuntu install)
- Packages: `sudo apt install qemu-system-x86 ovmf sbsigntool efitools mokutil efibootmgr dmidecode`.
- `rustup target add x86_64-unknown-uefi`; crate `uefi` (features panic_handler, logger).
- `.cargo/config.toml`: `[build] target = "x86_64-unknown-uefi"`.
- Ed25519 verify: `ed25519-compact` (no_std).
- Some protocols (IP4Config2, UDP4) may need hand-written bindings with `#[unsafe_protocol("GUID")]`
  from EDK2 headers depending on uefi crate version.
- Pin toolchain + Cargo.lock for reproducible builds.

## Test
- QEMU + OVMF on Ubuntu (KVM-accelerated):
  ```
  cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
  mkdir -p esp/EFI/BOOT && cp target/x86_64-unknown-uefi/release/selector.efi esp/EFI/BOOT/BOOTX64.EFI
  qemu-system-x86_64 -enable-kvm -machine q35 -m 512 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=vars.fd \
    -drive format=raw,file=fat:rw:esp \
    -nic user,model=virtio-net-pci -serial stdio
  ```
  (vars.fd is writable so BootNext persists; host reachable at 10.0.2.2 for the UDP test server.)
- Optional Secure Boot testing in QEMU: use `OVMF_CODE_4M.secboot.fd` with a copy of
  `OVMF_VARS_4M.ms.fd` (Microsoft keys pre-enrolled) and add `-global driver=cfi.pflash01,property=secure,value=on`
  with `-machine q35,smm=on`; then boot Ubuntu's shim with the selector and enroll the MOK in the VM.
- Final Secure Boot + shim validation on real hardware.

## Real-hardware checks still to do
- [ ] BootNext honored (efibootmgr -n, reboot, confirm fallback to BootOrder afterward).
- [ ] Entry with optional data survives reboots, entering/exiting BIOS setup, and isn't deduped.
- [ ] Ubuntu's shim honors load-option path.
- [ ] `dmidecode -t system` Wake-up Type after WoL vs power button.
- [ ] Firmware network stack exposes UDP4/IP4Config2 under current Fast Boot setting.
- [ ] msinfo32 shows "PCR7 Configuration: Bound" after setup.

## Board notes (Gigabyte Z790)
- Fast Boot: Disabled or plain Fast (not Ultra Fast). Memory Context Restore on (shortens extra POST).
- WoL: ErP Disabled, Wake on LAN enabled; disable Windows Fast Startup.
- BIOS updates may trigger BitLocker recovery (suspend first) and can wipe boot entries / SB keys.

## Boot server
- Small UDP responder (Python `cryptography` Ed25519, or ESP32-S3) holding the private key;
  current choice set via authenticated web UI / Home Assistant.

## Milestones
1. Hello-world selector in QEMU: set BootNext + reset.
2. Local key menu + BootOrder re-assert.
3. UDP4 + DHCP via firmware stack, plain reply.
4. Ed25519 nonce protocol + Python server.
5. `.bselcfg` provisioning + setup tool + signing.
6. Real hardware with shim/MOK; run the checks above.
7. Optional: SMBIOS wake type, ESP32 server, MOK-style key enrollment.

