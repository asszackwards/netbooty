//! Firmware misbehavior simulations for QEMU tests. Only compiled with the
//! `test-hooks` feature; release builds never contain this.

use uefi::CString16;
use uefi::runtime;

use crate::bootvars::{self, netbooty_vendor};

/// `NetBootyTestHook` = "ignore-bootnext": drop BootNext before resetting, as
/// a firmware that ignores it would.
pub fn after_boot_next() {
    let name = CString16::try_from("NetBootyTestHook").unwrap();
    let mut buf = [0u8; 32];
    if let Ok((data, _)) = runtime::get_variable(&name, &netbooty_vendor(), &mut buf)
        && data == b"ignore-bootnext"
    {
        uefi::println!("NETBOOTY: test hook: discarding BootNext");
        bootvars::delete_boot_next();
    }
}
