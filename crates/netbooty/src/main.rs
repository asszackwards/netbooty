//! NetBooty: a pre-boot next-boot selector.
//!
//! Decides which boot target to start, sets `BootNext` and resets, so the
//! firmware launches the target's own boot entry after a clean reset. It never
//! loads an OS itself unless the opt-in chainload fallback is configured.
#![no_main]
#![no_std]

extern crate alloc;

mod bootvars;
mod device;
mod guard;
mod menu;
mod oneshot;
#[cfg(feature = "test-hooks")]
mod test_hooks;

use alloc::string::String;
use alloc::vec::Vec;

use netbooty_cfg::config::{self, Config, Fallback, ResetKind};
use netbooty_cfg::loadopt::{Resolution, resolve};
use uefi::boot::{self, LoadImageSource};
use uefi::proto::BootPolicy;
use uefi::proto::device_path::DevicePath;
use uefi::proto::loaded_image::LoadedImage;
use uefi::runtime::{self, ResetType};
use uefi::{Status, entry, println};

use device::Presence;

/// Placeholder overwritten in place by `netbooty-setup patch`.
#[used]
#[unsafe(link_section = ".nbtycfg")]
static CONFIG: [u8; config::SIZE] = config::placeholder();

/// SBAT metadata; shim refuses second-stage images without it.
/// https://github.com/rhboot/shim/blob/main/SBAT.md
#[used]
#[unsafe(link_section = ".sbat")]
static SBAT: [u8; SBAT_TEXT.len()] = sbat_bytes();
const SBAT_TEXT: &[u8] = concat!(
    "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n",
    "netbooty,1,NetBooty,netbooty,",
    env!("CARGO_PKG_VERSION"),
    ",https://github.com/netbooty/netbooty\n"
)
.as_bytes();

const fn sbat_bytes() -> [u8; SBAT_TEXT.len()] {
    let mut out = [0u8; SBAT_TEXT.len()];
    let mut i = 0;
    while i < out.len() {
        out[i] = SBAT_TEXT[i];
        i += 1;
    }
    out
}

fn load_config() -> Config {
    // Volatile so the optimizer cannot constant-fold the placeholder.
    let raw = unsafe { core::ptr::read_volatile(&CONFIG) };
    Config::decode(&raw).unwrap_or_else(|e| {
        println!("NETBOOTY: invalid config ({e:?}), using defaults");
        Config::default()
    })
}

/// A target that resolved to a present boot entry.
struct Resolved {
    num: u16,
    /// Full device path for chainloading, when it could be determined.
    full_path: Option<Vec<u8>>,
}

/// ESP-relative path this image was loaded from, e.g. `\\EFI\\netbooty\\netbooty.efi`.
fn own_image_path() -> Option<String> {
    let li = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()).ok()?;
    let dp = li.file_path()?;
    let fake = netbooty_cfg::loadopt::build::load_option(0, "", dp.as_bytes(), &[]);
    Some(netbooty_cfg::loadopt::LoadOption::parse(&fake)?.loader_path).filter(|p| !p.is_empty())
}

fn resolve_targets(cfg: &Config, own: Option<u16>) -> Vec<Option<Resolved>> {
    // Entries that start NetBooty itself (directly or via shim) are never
    // targets, even when they share a loader and partition with one.
    let me = own_image_path();
    let entries: Vec<_> = bootvars::entries()
        .into_iter()
        .filter(|(_, o)| !me.as_deref().is_some_and(|p| netbooty_cfg::loadopt::launches(o, p)))
        .collect();
    cfg.targets
        .iter()
        .map(|t| {
            let num = match resolve(t, &entries, own) {
                Resolution::Found(n) => n,
                r => {
                    println!("NETBOOTY: target {} unavailable ({r:?})", t.name);
                    return None;
                }
            };
            let opt = &entries.iter().find(|(n, _)| *n == num)?.1;
            let full_path = match device::locate(opt) {
                Presence::Present(p) => Some(p),
                Presence::Unknown => None,
                Presence::Absent => {
                    println!("NETBOOTY: target {} unavailable (partition not present)", t.name);
                    return None;
                }
            };
            Some(Resolved { num, full_path })
        })
        .collect()
}

enum Choice {
    Target(usize),
    Exit,
}

fn decide(cfg: &Config, resolved: &[Option<Resolved>]) -> Choice {
    let available = |i: usize| resolved.get(i).is_some_and(|r| r.is_some());

    // The OS request is consumed up front so the menu can show it.
    let request = oneshot::take().and_then(|r| match r {
        oneshot::Request::Name(name) => {
            let i = cfg.target_index(&name);
            if i.is_none() {
                println!("NETBOOTY: OS requested unknown target {name}");
            }
            i
        }
        oneshot::Request::BootNum(n) => resolved.iter().position(|r| r.as_ref().is_some_and(|r| r.num == n)),
    });

    let items: Vec<menu::Item> = cfg
        .targets
        .iter()
        .enumerate()
        .map(|(i, t)| menu::Item { name: &t.name, hotkey: t.hotkey, available: available(i) })
        .collect();
    let pending = request.map(|i| cfg.targets[i].name.as_str());
    if let menu::Outcome::Pick(i) = menu::run(cfg.menu_mode, cfg.menu_timeout_s, &items, pending) {
        println!("NETBOOTY: decision=menu target={}", cfg.targets[i].name);
        return Choice::Target(i);
    }

    if let Some(i) = request.filter(|&i| available(i)) {
        println!("NETBOOTY: decision=os-request target={}", cfg.targets[i].name);
        return Choice::Target(i);
    }

    // Network step (milestone 3/4) goes here.

    match cfg.default {
        Some(i) if available(i) => {
            println!("NETBOOTY: decision=default target={}", cfg.targets[i].name);
            Choice::Target(i)
        }
        _ => {
            println!("NETBOOTY: decision=default exit");
            Choice::Exit
        }
    }
}

/// Status returned to the firmware so it continues with the next BootOrder
/// entry. An error status is used because some boot managers treat a
/// successful return as "boot done" and drop into their own menu.
const EXIT_STATUS: Status = Status::ABORTED;

fn chainload(r: &Resolved) -> Status {
    let Some(bytes) = r.full_path.as_deref() else {
        println!("NETBOOTY: cannot chainload Boot{:04X}: no full device path", r.num);
        return EXIT_STATUS;
    };
    let Ok(dp) = <&DevicePath>::try_from(bytes) else { return EXIT_STATUS };
    println!("NETBOOTY: chainloading Boot{:04X} (PCRs will include NetBooty)", r.num);
    let src = LoadImageSource::FromDevicePath { device_path: dp, boot_policy: BootPolicy::ExactMatch };
    match boot::load_image(boot::image_handle(), src).and_then(boot::start_image) {
        Ok(()) => Status::SUCCESS,
        Err(e) => {
            println!("NETBOOTY: chainload failed: {:?}", e.status());
            EXIT_STATUS
        }
    }
}

fn fallback(cfg: &Config, r: Option<&Resolved>) -> Status {
    match (cfg.fallback, r) {
        (Fallback::Chainload, Some(r)) => chainload(r),
        _ => {
            println!("NETBOOTY: exiting to firmware boot order");
            EXIT_STATUS
        }
    }
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    println!("NETBOOTY: v{}", env!("CARGO_PKG_VERSION"));

    let cfg = load_config();
    let own = bootvars::boot_current();
    let resolved = resolve_targets(&cfg, own);

    if let guard::Entry::Loop(num) = guard::check() {
        println!("NETBOOTY: loop guard: BootNext=Boot{num:04X} was not honored");
        let r = resolved.iter().flatten().find(|r| r.num == num);
        return fallback(&cfg, r);
    }

    if cfg.reassert_bootorder
        && let Some(own) = own
    {
        bootvars::reassert_first(own);
    }

    let idx = match decide(&cfg, &resolved) {
        Choice::Target(i) => i,
        Choice::Exit => return EXIT_STATUS,
    };
    let Some(r) = resolved[idx].as_ref() else { return EXIT_STATUS };

    guard::stamp(r.num);
    if let Err(e) = bootvars::set_boot_next(r.num) {
        println!("NETBOOTY: setting BootNext failed: {:?}", e.status());
        return fallback(&cfg, Some(r));
    }
    println!("NETBOOTY: target={} -> Boot{:04X}", cfg.targets[idx].name, r.num);
    #[cfg(feature = "test-hooks")]
    test_hooks::after_boot_next();
    let kind = match cfg.reset {
        ResetKind::Warm => ResetType::WARM,
        ResetKind::Cold => ResetType::COLD,
    };
    runtime::reset(kind, Status::SUCCESS, None)
}
