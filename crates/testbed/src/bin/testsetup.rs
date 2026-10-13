//! Prepares UEFI variables for a QEMU test from `\netbooty-test.txt` on its
//! own volume, then powers off. One command per line:
//!
//!   entry <hex> <description> <path> [fs=<n>] [opt=<text>]
//!                                                short-form HD()/File() entry; `opt`
//!                                                is stored as UCS-2 optional data (shim);
//!                                                `optraw` omits the NUL terminator
//!   order <hex> <hex> ...                        BootOrder
//!   bootnext <hex>                               native BootNext
//!   nbnext <name>                                NetBootyNext
//!   del <hex>                                    delete Boot####
//!   hook <value>                                 NetBootyTestHook (test-hooks builds)
//!   mok <path>                                   pre-enroll a DER cert in shim's MokList
//!
//! `<path>` is looked up on every FAT volume; `fs=<n>` picks the n-th volume
//! (0-based) that has it when several do.
#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use netbooty_cfg::config::name_bytes;
use netbooty_cfg::loadopt::{build, hd_node_offset, nodes};
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::fs::{FileSystem, Path};
use uefi::proto::device_path::DevicePath;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::{CString16, Guid, Handle, Status, cstr16, entry, println};

const GLOBAL: VariableVendor = VariableVendor::GLOBAL_VARIABLE;

fn attrs() -> VariableAttributes {
    VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
}

fn hex(s: &str) -> u16 {
    u16::from_str_radix(s, 16).expect("bad hex")
}

fn boot_name(n: u16) -> CString16 {
    CString16::try_from(alloc::format!("Boot{n:04X}").as_str()).unwrap()
}

fn device_path(h: Handle) -> Option<Vec<u8>> {
    let dp = unsafe {
        boot::open_protocol::<DevicePath>(
            OpenProtocolParams { handle: h, agent: boot::image_handle(), controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    Some(dp.as_bytes().to_vec())
}

/// HD node of every volume containing `path`, in handle order.
fn volumes_with(path: &str) -> Vec<Vec<u8>> {
    let p = CString16::try_from(path).unwrap();
    let mut out = Vec::new();
    for h in boot::find_handles::<SimpleFileSystem>().unwrap_or_default() {
        let Some(dp) = device_path(h) else { continue };
        let Some(off) = hd_node_offset(&dp) else { continue };
        let Ok(sfs) = boot::open_protocol_exclusive::<SimpleFileSystem>(h) else { continue };
        if FileSystem::new(sfs).try_exists(Path::new(&p)).unwrap_or(false) {
            let hd = nodes(&dp[off..]).next().unwrap().raw.to_vec();
            out.push(hd);
        }
    }
    out
}

fn run(line: &str) {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["entry", num, desc, path, rest @ ..] => {
            let fs_idx = rest.iter().find_map(|w| w.strip_prefix("fs=")).map_or(0, |n| n.parse().unwrap());
            let vols = volumes_with(path);
            let hd = vols.get(fs_idx).unwrap_or_else(|| panic!("{path} not found on volume {fs_idx}"));
            let mut fpl = hd.clone();
            fpl.extend(build::file_node(path));
            fpl.extend(build::end_node());
            let data: Vec<u8> = rest
                .iter()
                .find_map(|w| w.strip_prefix("opt="))
                .map(|o| o.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect())
                .or_else(|| {
                    // Unterminated UCS-2, as `efibootmgr -u` writes it.
                    let o = rest.iter().find_map(|w| w.strip_prefix("optraw="))?;
                    Some(o.encode_utf16().flat_map(u16::to_le_bytes).collect())
                })
                .unwrap_or_default();
            let opt = build::load_option(1, &desc.replace('_', " "), &fpl, &data);
            runtime::set_variable(&boot_name(hex(num)), &GLOBAL, attrs(), &opt).unwrap();
        }
        ["order", nums @ ..] => {
            let b: Vec<u8> = nums.iter().flat_map(|n| hex(n).to_le_bytes()).collect();
            runtime::set_variable(cstr16!("BootOrder"), &GLOBAL, attrs(), &b).unwrap();
        }
        ["bootnext", num] => {
            runtime::set_variable(cstr16!("BootNext"), &GLOBAL, attrs(), &hex(num).to_le_bytes()).unwrap();
        }
        ["nbnext", name] => {
            let vendor = VariableVendor(Guid::from_bytes(netbooty_cfg::VENDOR_GUID_BYTES));
            let var = CString16::try_from(netbooty_cfg::VAR_NEXT).unwrap();
            runtime::set_variable(&var, &vendor, attrs(), &name_bytes(name).unwrap()).unwrap();
        }
        ["hook", value] => {
            let vendor = VariableVendor(Guid::from_bytes(netbooty_cfg::VENDOR_GUID_BYTES));
            runtime::set_variable(cstr16!("NetBootyTestHook"), &vendor, attrs(), value.as_bytes()).unwrap();
        }
        ["del", num] => {
            let _ = runtime::delete_variable(&boot_name(hex(num)), &GLOBAL);
        }
        ["mok", der_path] => {
            // What MokManager stores after "Enroll MOK": one EFI_SIGNATURE_LIST
            // holding an X.509 certificate, boot-services-only (shim rejects a
            // MokList that the OS could write).
            let sfs = boot::get_image_file_system(boot::image_handle()).unwrap();
            let der = FileSystem::new(sfs).read(Path::new(&CString16::try_from(*der_path).unwrap())).unwrap();
            let x509 = Guid::parse_or_panic("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").to_bytes();
            let owner = Guid::parse_or_panic("605dab50-e046-4300-abb6-3dd810dd8b23");
            let sig_size = 16 + der.len() as u32;
            let mut list = Vec::new();
            list.extend_from_slice(&x509);
            list.extend_from_slice(&(28 + sig_size).to_le_bytes());
            list.extend_from_slice(&0u32.to_le_bytes());
            list.extend_from_slice(&sig_size.to_le_bytes());
            list.extend_from_slice(&owner.to_bytes());
            list.extend_from_slice(&der);
            let bs_only = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
            runtime::set_variable(cstr16!("MokList"), &VariableVendor(owner), bs_only, &list).unwrap();
        }
        [] => {}
        _ => panic!("bad testsetup line: {line}"),
    }
    println!("TESTSETUP: {line}");
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    let sfs = boot::get_image_file_system(boot::image_handle()).expect("own volume");
    let script = FileSystem::new(sfs).read_to_string(cstr16!("\\netbooty-test.txt")).expect("script");
    for line in script.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        run(line);
    }
    println!("TESTSETUP: done");
    runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None)
}
