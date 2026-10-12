//! One-shot requests from an OS: the `NetBootyNext` variable, or a leftover
//! native `BootNext` the firmware did not consume.

use alloc::string::String;

use netbooty_cfg::VAR_NEXT;
use netbooty_cfg::config::{NAME_LEN, name_from_bytes};
use uefi::CString16;
use uefi::runtime;

use crate::bootvars::{self, netbooty_vendor};

pub enum Request {
    Name(String),
    BootNum(u16),
}

/// Read and consume a pending request. The variable is deleted before the
/// request is acted on so a failure can never make it stick.
pub fn take() -> Option<Request> {
    let name = CString16::try_from(VAR_NEXT).unwrap();
    let mut buf = [0u8; 64];
    if let Ok((data, _)) = runtime::get_variable(&name, &netbooty_vendor(), &mut buf) {
        let mut fixed = [0u8; NAME_LEN];
        let n = data.len().min(NAME_LEN);
        fixed[..n].copy_from_slice(&data[..n]);
        let parsed = (data.len() <= NAME_LEN).then(|| name_from_bytes(&fixed)).flatten().map(String::from);
        let _ = runtime::delete_variable(&name, &netbooty_vendor());
        match parsed {
            Some(s) if !s.is_empty() => return Some(Request::Name(s)),
            _ => log::warn!("ignoring malformed {VAR_NEXT}"),
        }
    }
    let n = bootvars::boot_next()?;
    bootvars::delete_boot_next();
    Some(Request::BootNum(n))
}
