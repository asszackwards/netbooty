//! EFI_UDP4_PROTOCOL bindings (UEFI spec 2.10, section 28.4), which the `uefi`
//! crate does not provide. Layouts follow EDK2's `MdePkg/Include/Protocol/Udp4.h`.

use core::ffi::c_void;

use uefi::proto::unsafe_protocol;
use uefi_raw::protocol::driver::ServiceBindingProtocol;
use uefi_raw::{Event, Status};

/// EFI_IPv4_ADDRESS
pub type Ipv4 = [u8; 4];

/// EFI_UDP4_CONFIG_DATA. BOOLEANs are `u8` so firmware values are never UB.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigData {
    pub accept_broadcast: u8,
    pub accept_promiscuous: u8,
    pub accept_any_port: u8,
    pub allow_duplicate_port: u8,
    pub type_of_service: u8,
    pub time_to_live: u8,
    pub do_not_fragment: u8,
    pub receive_timeout: u32,
    pub transmit_timeout: u32,
    pub use_default_address: u8,
    pub station_address: Ipv4,
    pub subnet_mask: Ipv4,
    pub station_port: u16,
    pub remote_address: Ipv4,
    pub remote_port: u16,
}

/// EFI_UDP4_SESSION_DATA
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SessionData {
    pub source_address: Ipv4,
    pub source_port: u16,
    pub destination_address: Ipv4,
    pub destination_port: u16,
}

/// EFI_UDP4_FRAGMENT_DATA
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FragmentData {
    pub fragment_length: u32,
    pub fragment_buffer: *mut c_void,
}

/// EFI_UDP4_TRANSMIT_DATA with one fragment.
#[repr(C)]
#[derive(Debug)]
pub struct TransmitData {
    pub udp_session_data: *mut SessionData,
    pub gateway_address: *mut Ipv4,
    pub data_length: u32,
    pub fragment_count: u32,
    pub fragment_table: [FragmentData; 1],
}

/// EFI_UDP4_RECEIVE_DATA. The fragment table is variable-length; only the
/// first entry is declared, the rest follow in memory.
#[repr(C)]
#[derive(Debug)]
pub struct ReceiveData {
    /// EFI_TIME (16 bytes, 4-byte aligned).
    pub time_stamp: [u32; 4],
    pub recycle_signal: Event,
    pub udp_session: SessionData,
    pub data_length: u32,
    pub fragment_count: u32,
    pub fragment_table: [FragmentData; 1],
}

/// EFI_UDP4_COMPLETION_TOKEN. `packet` is `*mut ReceiveData` or
/// `*mut TransmitData` (a union in C).
#[repr(C)]
#[derive(Debug)]
pub struct CompletionToken {
    pub event: Event,
    pub status: Status,
    pub packet: *mut c_void,
}

#[repr(C)]
#[derive(Debug)]
pub struct Udp4Protocol {
    pub get_mode_data: unsafe extern "efiapi" fn(
        this: *mut Self,
        udp4_config: *mut ConfigData,
        ip4_mode: *mut c_void,
        mnp_config: *mut c_void,
        snp_mode: *mut c_void,
    ) -> Status,
    pub configure: unsafe extern "efiapi" fn(this: *mut Self, config: *const ConfigData) -> Status,
    pub groups: unsafe extern "efiapi" fn(this: *mut Self, join: u8, address: *const Ipv4) -> Status,
    pub routes: unsafe extern "efiapi" fn(
        this: *mut Self,
        delete: u8,
        subnet: *const Ipv4,
        mask: *const Ipv4,
        gateway: *const Ipv4,
    ) -> Status,
    pub transmit: unsafe extern "efiapi" fn(this: *mut Self, token: *mut CompletionToken) -> Status,
    pub receive: unsafe extern "efiapi" fn(this: *mut Self, token: *mut CompletionToken) -> Status,
    pub cancel: unsafe extern "efiapi" fn(this: *mut Self, token: *mut CompletionToken) -> Status,
    pub poll: unsafe extern "efiapi" fn(this: *mut Self) -> Status,
}

#[unsafe_protocol("3ad9df29-4501-478d-b1f8-7f7fe70e50f3")]
#[repr(transparent)]
#[derive(Debug)]
pub struct Udp4(pub Udp4Protocol);

#[unsafe_protocol("83f01464-99bd-45e5-b383-af6305d8e9e6")]
#[repr(transparent)]
#[derive(Debug)]
pub struct Udp4ServiceBinding(pub ServiceBindingProtocol);

const _: () = {
    assert!(core::mem::size_of::<ConfigData>() == 36);
    assert!(core::mem::size_of::<SessionData>() == 12);
    assert!(core::mem::offset_of!(ReceiveData, udp_session) == 24);
};
