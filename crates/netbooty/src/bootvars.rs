//! `Boot####`, `BootOrder`, `BootCurrent` and `BootNext` access.

use alloc::format;
use alloc::vec::Vec;

use netbooty_cfg::loadopt::{LoadOption, boot_var_number};
use uefi::runtime::{self, VariableAttributes, VariableVendor};
use uefi::{CStr16, CString16, Guid, Result, cstr16};

pub const GLOBAL: VariableVendor = VariableVendor::GLOBAL_VARIABLE;

pub fn netbooty_vendor() -> VariableVendor {
    VariableVendor(Guid::from_bytes(netbooty_cfg::VENDOR_GUID_BYTES))
}

pub fn nv_bs_rt() -> VariableAttributes {
    VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
}

fn read_u16(name: &CStr16) -> Option<u16> {
    let mut buf = [0u8; 2];
    match runtime::get_variable(name, &GLOBAL, &mut buf) {
        Ok((data, _)) if data.len() == 2 => Some(u16::from_le_bytes([data[0], data[1]])),
        _ => None,
    }
}

pub fn boot_current() -> Option<u16> {
    read_u16(cstr16!("BootCurrent"))
}

pub fn boot_next() -> Option<u16> {
    read_u16(cstr16!("BootNext"))
}

pub fn set_boot_next(n: u16) -> Result {
    runtime::set_variable(cstr16!("BootNext"), &GLOBAL, nv_bs_rt(), &n.to_le_bytes())
}

pub fn delete_boot_next() {
    let _ = runtime::delete_variable(cstr16!("BootNext"), &GLOBAL);
}

pub fn boot_order() -> Vec<u16> {
    match runtime::get_variable_boxed(cstr16!("BootOrder"), &GLOBAL) {
        Ok((data, _)) => data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect(),
        Err(_) => Vec::new(),
    }
}

fn set_boot_order(order: &[u16]) -> Result {
    let bytes: Vec<u8> = order.iter().flat_map(|n| n.to_le_bytes()).collect();
    runtime::set_variable(cstr16!("BootOrder"), &GLOBAL, nv_bs_rt(), &bytes)
}

/// Move `own` to the front of BootOrder; writes only when something changes
/// to spare NVRAM.
pub fn reassert_first(own: u16) {
    let order = boot_order();
    if order.first() == Some(&own) {
        return;
    }
    let mut new = Vec::with_capacity(order.len() + 1);
    new.push(own);
    new.extend(order.iter().copied().filter(|&n| n != own));
    match set_boot_order(&new) {
        Ok(()) => log::info!("BootOrder re-asserted: Boot{own:04X} first"),
        Err(e) => log::warn!("could not rewrite BootOrder: {e:?}"),
    }
}

pub fn boot_var_name(n: u16) -> CString16 {
    CString16::try_from(format!("Boot{n:04X}").as_str()).unwrap()
}

pub fn read_entry(n: u16) -> Option<LoadOption> {
    let (data, _) = runtime::get_variable_boxed(&boot_var_name(n), &GLOBAL).ok()?;
    LoadOption::parse(&data)
}

/// Every parseable `Boot####` variable, found by enumerating variable names so
/// entries missing from BootOrder (or renumbered by firmware) are still seen.
pub fn entries() -> Vec<(u16, LoadOption)> {
    let mut out = Vec::new();
    for key in runtime::variable_keys().flatten() {
        if key.vendor != GLOBAL {
            continue;
        }
        let Some(n) = boot_var_number(&format!("{}", key.name)) else { continue };
        if let Some(opt) = read_entry(n) {
            out.push((n, opt));
        }
    }
    out.sort_by_key(|(n, _)| *n);
    out
}
