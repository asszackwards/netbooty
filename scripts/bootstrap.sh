#!/usr/bin/env bash
# Check dependencies and build NetBooty and its setup tool.
# Usage: scripts/bootstrap.sh   (then: sudo ./target/release/netbooty-setup)
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -m)" in
    x86_64) uefi_target=x86_64-unknown-uefi ;;
    aarch64) uefi_target=aarch64-unknown-uefi ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ ! -d /sys/firmware/efi ]; then
    echo "warning: this system did not boot in UEFI mode; NetBooty can be built but not installed here" >&2
fi

# Runtime tools used by netbooty-setup, with package names per distro family.
declare -A pkg_debian=([sbsign]=sbsigntool [efibootmgr]=efibootmgr [mokutil]=mokutil [openssl]=openssl [lsblk]=util-linux)
declare -A pkg_fedora=([sbsign]=sbsigntools [efibootmgr]=efibootmgr [mokutil]=mokutil [openssl]=openssl [lsblk]=util-linux)
declare -A pkg_arch=([sbsign]=sbsigntools [efibootmgr]=efibootmgr [mokutil]=mokutil [openssl]=openssl [lsblk]=util-linux)
declare -A pkg_suse=([sbsign]=sbsigntools [efibootmgr]=efibootmgr [mokutil]=mokutil [openssl]=openssl [lsblk]=util-linux)

missing=()
for tool in sbsign efibootmgr mokutil openssl lsblk; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "missing tools: ${missing[*]}"
    if command -v apt-get >/dev/null; then
        echo "  sudo apt install $(for t in "${missing[@]}"; do printf '%s ' "${pkg_debian[$t]}"; done)"
    elif command -v dnf >/dev/null; then
        echo "  sudo dnf install $(for t in "${missing[@]}"; do printf '%s ' "${pkg_fedora[$t]}"; done)"
    elif command -v pacman >/dev/null; then
        echo "  sudo pacman -S $(for t in "${missing[@]}"; do printf '%s ' "${pkg_arch[$t]}"; done)"
    elif command -v zypper >/dev/null; then
        echo "  sudo zypper install $(for t in "${missing[@]}"; do printf '%s ' "${pkg_suse[$t]}"; done)"
    fi
    echo "(mokutil/sbsign are only needed with Secure Boot; install them and rerun this script)"
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "Rust is not installed. Install it with:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo "then rerun this script."
        exit 1
    fi
fi

# rust-toolchain.toml pins the compiler and installs the UEFI targets on first use.
echo "building NetBooty ($uefi_target) and netbooty-setup..."
cargo build --release --target "$uefi_target" -p netbooty
cargo build --release -p netbooty-setup

echo
echo "Done. Start the interactive installer with:"
echo "  sudo ./target/release/netbooty-setup"
echo "(add 'setup --dry-run' to preview without changing anything)"
