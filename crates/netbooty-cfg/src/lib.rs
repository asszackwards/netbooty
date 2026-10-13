//! Shared definitions for NetBooty: the `.nbtycfg` config layout, `Boot####`
//! load-option parsing and target resolution, and (later) the network protocol.
//! `no_std` + `alloc` so the same code runs in the UEFI selector and host tools.
#![no_std]

extern crate alloc;

pub mod config;
pub mod loadopt;
pub mod proto;

/// Vendor GUID for NetBooty's own UEFI variables.
pub const VENDOR_GUID: &str = "6adaeca3-9d97-4b60-90a8-a9f2d55969e1";
/// Same GUID in the mixed-endian byte order UEFI stores it in.
pub const VENDOR_GUID_BYTES: [u8; 16] =
    [0xa3, 0xec, 0xda, 0x6a, 0x97, 0x9d, 0x60, 0x4b, 0x90, 0xa8, 0xa9, 0xf2, 0xd5, 0x59, 0x69, 0xe1];

/// One-shot target request set by an OS: NUL-padded target name (16 bytes).
pub const VAR_NEXT: &str = "NetBootyNext";
/// Reset-loop guard: timestamp written just before NetBooty resets.
pub const VAR_STAMP: &str = "NetBootyStamp";
/// Outcome of the last network step (ASCII), readable from the OS.
pub const VAR_NET_STATUS: &str = "NetBootyNetStatus";

/// Seconds within which re-entering NetBooty after it set BootNext means the
/// firmware did not honor BootNext.
pub const LOOP_GUARD_SECS: i64 = 20;

/// Days-from-civil (proleptic Gregorian) for comparing RTC timestamps.
pub fn rtc_seconds(year: u16, month: u8, day: u8, h: u8, m: u8, s: u8) -> i64 {
    let (y, mo) = (year as i64, month as i64);
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + h as i64 * 3600 + m as i64 * 60 + s as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtc() {
        assert_eq!(rtc_seconds(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(rtc_seconds(2026, 10, 12, 0, 0, 0), 1_791_763_200);
        assert_eq!(rtc_seconds(2024, 3, 1, 0, 0, 5) - rtc_seconds(2024, 2, 29, 23, 59, 50), 15);
    }

    #[test]
    fn guid_bytes_match_string() {
        let hex: alloc::string::String = VENDOR_GUID.chars().filter(|c| *c != '-').collect();
        let b: alloc::vec::Vec<u8> =
            (0..16).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
        let mixed = [b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6]];
        assert_eq!(VENDOR_GUID_BYTES[..8], mixed);
        assert_eq!(VENDOR_GUID_BYTES[8..], b[8..]);
    }
}
