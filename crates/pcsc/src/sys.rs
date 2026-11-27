//! Hand-declared `PCSC.framework` externs. On macOS `LONG` is `i32`,
//! `DWORD` is `u32`, and `SCARDCONTEXT` / `SCARDHANDLE` are `i32`.

use core::ffi::{c_char, c_void};

pub type Long = i32;
pub type Dword = u32;
pub type Context = i32;
pub type Handle = i32;

pub const SCOPE_SYSTEM: Dword = 2;
pub const SHARE_SHARED: Dword = 2;
pub const PROTOCOL_T1: Dword = 2;
pub const LEAVE_CARD: Dword = 0;
pub const RESET_CARD: Dword = 1;

#[repr(C)]
pub struct IoRequest {
    pub protocol: Dword,
    pub pci_length: Dword,
}

pub static PCI_T1: IoRequest = IoRequest {
    protocol: PROTOCOL_T1,
    pci_length: core::mem::size_of::<IoRequest>() as Dword,
};

/// `SCARD_READERSTATE`; Apple's headers declare it under `#pragma pack(1)`.
#[repr(C, packed)]
pub struct ReaderState {
    pub reader: *const c_char,
    pub user_data: *mut c_void,
    pub current_state: Dword,
    pub event_state: Dword,
    pub atr_len: Dword,
    pub atr: [u8; 33],
}

#[link(name = "PCSC", kind = "framework")]
unsafe extern "C" {
    pub fn SCardEstablishContext(
        scope: Dword,
        reserved1: *const c_void,
        reserved2: *const c_void,
        context: *mut Context,
    ) -> Long;
    pub fn SCardReleaseContext(context: Context) -> Long;
    pub fn SCardListReaders(
        context: Context,
        groups: *const c_char,
        readers: *mut c_char,
        len: *mut Dword,
    ) -> Long;
    pub fn SCardConnect(
        context: Context,
        reader: *const c_char,
        share_mode: Dword,
        preferred_protocols: Dword,
        card: *mut Handle,
        active_protocol: *mut Dword,
    ) -> Long;
    pub fn SCardDisconnect(card: Handle, disposition: Dword) -> Long;
    pub fn SCardBeginTransaction(card: Handle) -> Long;
    pub fn SCardEndTransaction(card: Handle, disposition: Dword) -> Long;
    pub fn SCardTransmit(
        card: Handle,
        send_pci: *const IoRequest,
        send: *const u8,
        send_len: Dword,
        recv_pci: *mut IoRequest,
        recv: *mut u8,
        recv_len: *mut Dword,
    ) -> Long;
    pub fn SCardGetStatusChange(
        context: Context,
        timeout_ms: Dword,
        states: *mut ReaderState,
        count: Dword,
    ) -> Long;
    pub fn SCardCancel(context: Context) -> Long;
}
