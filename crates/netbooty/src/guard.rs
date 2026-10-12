//! Reset-loop guard.
//!
//! Before resetting, NetBooty records when it set BootNext and to what. On the
//! next entry, a firmware that ignored BootNext shows up as either BootNext
//! still holding our value, or NetBooty running again within seconds.

use netbooty_cfg::{LOOP_GUARD_SECS, VAR_STAMP, rtc_seconds};
use uefi::CString16;
use uefi::runtime::{self, VariableAttributes};

use crate::bootvars::{self, netbooty_vendor};

fn stamp_name() -> CString16 {
    CString16::try_from(VAR_STAMP).unwrap()
}

fn now() -> Option<i64> {
    let t = runtime::get_time().ok()?;
    Some(rtc_seconds(t.year(), t.month(), t.day(), t.hour(), t.minute(), t.second()))
}

pub enum Entry {
    /// No sign of a loop.
    Normal,
    /// BootNext was not honored last time; it pointed at this entry.
    Loop(u16),
}

/// Inspect (and clear) the stamp left by the previous run.
pub fn check() -> Entry {
    let mut buf = [0u8; 10];
    let stamp = runtime::get_variable(&stamp_name(), &netbooty_vendor(), &mut buf)
        .ok()
        .filter(|(d, _)| d.len() == 10)
        .map(|(d, _)| (i64::from_le_bytes(d[..8].try_into().unwrap()), u16::from_le_bytes([d[8], d[9]])));
    let Some((when, target)) = stamp else { return Entry::Normal };

    // On a loop the stamp is left to expire, so every re-entry inside the
    // window keeps falling back even if the firmware restarts BootOrder from
    // the top (which would otherwise alternate between deciding and falling back).
    if bootvars::boot_next() == Some(target) {
        log::warn!("BootNext=Boot{target:04X} is still set: firmware did not consume it");
        bootvars::delete_boot_next();
        return Entry::Loop(target);
    }
    if let Some(t) = now()
        && (0..LOOP_GUARD_SECS).contains(&(t - when))
    {
        log::warn!("re-entered {}s after setting BootNext=Boot{target:04X}", t - when);
        return Entry::Loop(target);
    }
    let _ = runtime::delete_variable(&stamp_name(), &netbooty_vendor());
    Entry::Normal
}

/// Record that BootNext is about to be set to `target`.
pub fn stamp(target: u16) {
    let mut data = [0u8; 10];
    data[..8].copy_from_slice(&now().unwrap_or(i64::MIN).to_le_bytes());
    data[8..].copy_from_slice(&target.to_le_bytes());
    let attrs = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
    if let Err(e) = runtime::set_variable(&stamp_name(), &netbooty_vendor(), attrs, &data) {
        log::warn!("could not write loop-guard stamp: {e:?}");
    }
}
