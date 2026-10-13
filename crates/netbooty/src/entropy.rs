//! Request nonces: the firmware's RNG protocol, else the CPU's hardware RNG,
//! else a never-repeating counter. The network step always runs.
//!
//! The nonce only has to guarantee that a recorded reply cannot be replayed
//! later. A counter kept in NVRAM never repeats, so it still does that; it is
//! predictable, so someone on the LAN could pre-request a reply for a future
//! nonce from the real server, which only replays a choice the server made.

use uefi::boot;
use uefi::proto::rng::Rng;
use uefi::runtime::{self, VariableAttributes};

use crate::bootvars::netbooty_vendor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Firmware,
    Cpu,
    /// No hardware RNG: NVRAM counter + clock + timestamp counter.
    Counter,
}

pub fn nonce() -> ([u8; 16], Source) {
    #[cfg(feature = "test-hooks")]
    if crate::test_hooks::no_hardware_rng() {
        return (counter(), Source::Counter);
    }
    if let Some(n) = firmware() {
        return (n, Source::Firmware);
    }
    if let Some(n) = cpu() {
        return (n, Source::Cpu);
    }
    (counter(), Source::Counter)
}

/// 8 bytes of a persistent counter (incremented on every use) followed by
/// the RTC and timestamp counter, so values never repeat across boots even if
/// the counter write fails.
fn counter() -> [u8; 16] {
    let name = uefi::CString16::try_from("NetBootyNonceCounter").unwrap();
    let vendor = netbooty_vendor();
    let mut buf = [0u8; 8];
    let n = runtime::get_variable(&name, &vendor, &mut buf)
        .ok()
        .and_then(|(d, _)| d.try_into().ok())
        .map_or(0, u64::from_le_bytes)
        .wrapping_add(1);
    let attrs = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
    let _ = runtime::set_variable(&name, &vendor, attrs, &n.to_le_bytes());

    let t = runtime::get_time().ok();
    let clock = t.map_or(0u64, |t| {
        netbooty_cfg::rtc_seconds(t.year(), t.month(), t.day(), t.hour(), t.minute(), t.second()) as u64
            ^ (t.nanosecond() as u64) << 32
    });
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out[8..].copy_from_slice(&(clock ^ tsc()).to_le_bytes());
    out
}

#[cfg(target_arch = "x86_64")]
fn tsc() -> u64 {
    // SAFETY: RDTSC is available on every x86_64 CPU.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(not(target_arch = "x86_64"))]
fn tsc() -> u64 {
    0
}

fn firmware() -> Option<[u8; 16]> {
    let handle = boot::get_handle_for_protocol::<Rng>().ok()?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle).ok()?;
    let mut out = [0u8; 16];
    rng.get_rng(None, &mut out).ok()?;
    Some(out)
}

#[cfg(target_arch = "x86_64")]
fn cpu() -> Option<[u8; 16]> {
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    let (max_leaf, leaf1) = (__cpuid(0).eax, __cpuid(1));
    let has_rdrand = leaf1.ecx & (1 << 30) != 0;
    let has_rdseed = max_leaf >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0;
    if !has_rdrand && !has_rdseed {
        return None;
    }

    let mut out = [0u8; 16];
    for chunk in out.chunks_mut(8) {
        let mut v = 0u64;
        // Both instructions may transiently fail; retry a bounded number of times.
        // SAFETY: the instruction is only used when CPUID reports it.
        let ok = (0..64).any(|_| unsafe { if has_rdseed { rdseed(&mut v) } else { rdrand(&mut v) } });
        if !ok {
            return None;
        }
        chunk.copy_from_slice(&v.to_le_bytes());
    }
    Some(out)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand(v: &mut u64) -> bool {
    core::arch::x86_64::_rdrand64_step(v) == 1
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdseed")]
unsafe fn rdseed(v: &mut u64) -> bool {
    core::arch::x86_64::_rdseed64_step(v) == 1
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu() -> Option<[u8; 16]> {
    None
}
