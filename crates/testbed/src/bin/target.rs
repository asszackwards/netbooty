//! Stand-in OS loader for QEMU tests. Prints which boot entry started it and
//! some variable state, then powers off so the test run ends.
#![no_main]
#![no_std]

extern crate alloc;

use netbooty_cfg::loadopt::LoadOption;
use uefi::runtime::{self, ResetType, VariableVendor};
use uefi::{CString16, Guid, Status, cstr16, entry, println};

/// Shim refuses images without SBAT metadata, so the stand-in needs it too
/// when it is signed and loaded behind shim.
#[used]
#[unsafe(link_section = ".sbat")]
static SBAT: [u8; 116] =
    *b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\nnbtestbed,1,NetBooty,testbed,0.1.0,none\n";

fn u16_var(name: &uefi::CStr16) -> Option<u16> {
    let mut b = [0u8; 2];
    runtime::get_variable(name, &VariableVendor::GLOBAL_VARIABLE, &mut b)
        .ok()
        .map(|(d, _)| u16::from_le_bytes([d[0], d[1]]))
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    let current = u16_var(cstr16!("BootCurrent"));
    let desc = current
        .and_then(|n| {
            let name = CString16::try_from(alloc::format!("Boot{n:04X}").as_str()).ok()?;
            let (data, _) = runtime::get_variable_boxed(&name, &VariableVendor::GLOBAL_VARIABLE).ok()?;
            LoadOption::parse(&data)
        })
        .map(|o| o.description)
        .unwrap_or_default();

    let nb_vendor = VariableVendor(Guid::from_bytes(netbooty_cfg::VENDOR_GUID_BYTES));
    let next_name = CString16::try_from(netbooty_cfg::VAR_NEXT).unwrap();
    let nb_next = runtime::variable_exists(&next_name, &nb_vendor).unwrap_or(false);
    let order = runtime::get_variable_boxed(cstr16!("BootOrder"), &VariableVendor::GLOBAL_VARIABLE)
        .map(|(d, _)| {
            d.as_chunks::<2>()
                .0
                .iter()
                .map(|c| alloc::format!("{:04X}", u16::from_le_bytes([c[0], c[1]])))
                .collect::<alloc::vec::Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();

    println!("TARGET {desc}");
    println!(
        "TESTBED: BootCurrent={current:04X?} BootNext={:04X?} NetBootyNext={nb_next} BootOrder={order}",
        u16_var(cstr16!("BootNext"))
    );
    runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None)
}
