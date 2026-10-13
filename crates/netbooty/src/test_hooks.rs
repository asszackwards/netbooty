//! Firmware misbehavior simulations for QEMU tests. Only compiled with the
//! `test-hooks` feature; release builds never contain this.

use uefi::CString16;
use uefi::runtime;

use crate::bootvars::{self, netbooty_vendor};

/// The value of `NetBootyTestHook`, if set.
fn hook_is(value: &[u8]) -> bool {
    let name = CString16::try_from("NetBootyTestHook").unwrap();
    let mut buf = [0u8; 32];
    runtime::get_variable(&name, &netbooty_vendor(), &mut buf).is_ok_and(|(data, _)| data == value)
}

/// "ignore-bootnext": drop BootNext before resetting, as a firmware that
/// ignores it would.
pub fn after_boot_next() {
    if hook_is(b"ignore-bootnext") {
        uefi::println!("NETBOOTY: test hook: discarding BootNext");
        bootvars::delete_boot_next();
    }
}

/// "counter-nonce": behave as if there were no hardware RNG for nonces.
pub fn no_hardware_rng() -> bool {
    hook_is(b"counter-nonce")
}
