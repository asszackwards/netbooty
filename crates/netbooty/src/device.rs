//! Partition presence checks and short-form device path expansion.
//!
//! Boot entries created by OS tools are usually short-form (`HD(...)/File(...)`),
//! which `LocateDevicePath` cannot match. Instead, walk every block device's
//! path and look for a hard-drive node with the same partition signature.

use alloc::vec::Vec;

use netbooty_cfg::loadopt::{LoadOption, hd_node_offset, hd_signature, nodes};
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::device_path::DevicePath;
use uefi::proto::media::block::BlockIO;

pub enum Presence {
    /// Partition found; full device path to the loader (for chainloading).
    Present(Vec<u8>),
    /// The entry names a partition that is not attached.
    Absent,
    /// No partition in the path (network, firmware app, ...): cannot check.
    Unknown,
}

fn device_path_bytes(handle: uefi::Handle) -> Option<Vec<u8>> {
    // SAFETY: GetProtocol does not take ownership; the bytes are copied out
    // before the scoped protocol is dropped.
    let dp = unsafe {
        boot::open_protocol::<DevicePath>(
            OpenProtocolParams { handle, agent: boot::image_handle(), controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    Some(dp.as_bytes().to_vec())
}

pub fn locate(opt: &LoadOption) -> Presence {
    let fpl = &opt.file_path_list;
    let Some(off) = hd_node_offset(fpl) else { return Presence::Unknown };
    let hd_len = u16::from_le_bytes([fpl[off + 2], fpl[off + 3]]) as usize;
    let want = hd_signature(&fpl[off..off + hd_len]);
    if want.is_none() {
        return Presence::Unknown;
    }

    let Ok(handles) = boot::find_handles::<BlockIO>() else { return Presence::Absent };
    for h in handles {
        let Some(dp) = device_path_bytes(h) else { continue };
        let mut end = 0;
        let mut hit = false;
        for n in nodes(&dp) {
            end += n.raw.len();
            if n.ty == 0x04 && n.sub == 0x01 && hd_signature(n.raw) == want {
                hit = true;
                break;
            }
        }
        if hit && end == dp.len() - 4 {
            // Partition's own path (ending at its HD node) + the entry's tail.
            let mut full = dp[..end].to_vec();
            full.extend_from_slice(&fpl[off + hd_len..]);
            return Presence::Present(full);
        }
    }
    Presence::Absent
}
