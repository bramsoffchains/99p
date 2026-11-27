//! Safe wrappers over `sys` (macOS only).

use std::ffi::CString;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ykvault_core::{Error, SmartCard};

use crate::sys;
use crate::util::{PcscError, Step, classify, code, is_yubikey_reader, parse_reader_list, state};

const SELECT_PIV: [u8; 10] = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
/// Short APDUs answer at most 256 data bytes plus SW1 SW2.
const RECV_MAX: usize = 258;
/// Watcher poll interval, so `RemovalWatcher` stops promptly even if
/// `SCardCancel` does not wake it.
const POLL_MS: u32 = 500;

fn check(op: &'static str, rv: sys::Long) -> Result<(), PcscError> {
    match rv as u32 {
        code::SUCCESS => Ok(()),
        code => Err(PcscError::Scard { op, code }),
    }
}

/// An owned `SCARDCONTEXT`.
struct Context(sys::Context);

impl Context {
    fn establish() -> Result<Self, PcscError> {
        let mut ctx = 0;
        // SAFETY: valid out-pointer; reserved arguments must be null.
        let rv = unsafe {
            sys::SCardEstablishContext(sys::SCOPE_SYSTEM, ptr::null(), ptr::null(), &mut ctx)
        };
        check("SCardEstablishContext", rv)?;
        Ok(Context(ctx))
    }

    fn list_readers(&self) -> Result<Vec<String>, PcscError> {
        loop {
            let mut len: sys::Dword = 0;
            // SAFETY: a null buffer asks for the required length.
            let rv =
                unsafe { sys::SCardListReaders(self.0, ptr::null(), ptr::null_mut(), &mut len) };
            if rv as u32 == code::E_NO_READERS_AVAILABLE {
                return Ok(Vec::new());
            }
            check("SCardListReaders", rv)?;
            let mut buf = vec![0u8; len as usize];
            // SAFETY: `buf` holds `len` bytes.
            let rv = unsafe {
                sys::SCardListReaders(self.0, ptr::null(), buf.as_mut_ptr().cast(), &mut len)
            };
            match rv as u32 {
                code::E_NO_READERS_AVAILABLE => return Ok(Vec::new()),
                // A reader was plugged in between the two calls.
                code::E_INSUFFICIENT_BUFFER => continue,
                _ => check("SCardListReaders", rv)?,
            }
            buf.truncate(len as usize);
            return Ok(parse_reader_list(&buf));
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: we own the context.
        unsafe { sys::SCardReleaseContext(self.0) };
    }
}

/// Names of connected readers that look like YubiKeys (SPEC §7.5). Use
/// [`PcscCard::open`] to also check that PIV answers.
pub fn yubikey_readers() -> Result<Vec<String>, PcscError> {
    let ctx = match Context::establish() {
        Ok(ctx) => ctx,
        Err(PcscError::Scard {
            code: code::E_NO_SERVICE,
            ..
        }) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(ctx
        .list_readers()?
        .into_iter()
        .filter(|r| is_yubikey_reader(r))
        .collect())
}

/// A YubiKey connected over T=1 in shared mode.
///
/// Wrap each multi-APDU operation (unlock, save, provisioning) in
/// [`PcscCard::transaction`] so no other app can interleave APDUs, select
/// another applet or drop the management key authentication in between.
pub struct PcscCard {
    // `Drop` disconnects the handle before the context field is released.
    handle: sys::Handle,
    reader: String,
    _ctx: Context,
    dead: bool,
}

// The handle is only used through `&mut self`.
unsafe impl Send for PcscCard {}

impl PcscCard {
    /// Connects to `reader`, or to the first YubiKey reader whose PIV
    /// application answers SELECT.
    pub fn open(reader: Option<&str>) -> Result<Self, PcscError> {
        let candidates = match reader {
            Some(r) => vec![r.to_owned()],
            None => yubikey_readers()?,
        };
        for name in candidates {
            if let Ok(mut card) = Self::connect(name) {
                if card.select_piv().is_ok() {
                    return Ok(card);
                }
            }
        }
        Err(PcscError::NoYubiKey)
    }

    fn connect(reader: String) -> Result<Self, PcscError> {
        let c_reader = CString::new(reader.as_str()).map_err(|_| PcscError::NoYubiKey)?;
        let ctx = Context::establish()?;
        let (mut handle, mut proto) = (0, 0);
        // SAFETY: valid C string and out-pointers.
        let rv = unsafe {
            sys::SCardConnect(
                ctx.0,
                c_reader.as_ptr(),
                sys::SHARE_SHARED,
                sys::PROTOCOL_T1,
                &mut handle,
                &mut proto,
            )
        };
        check("SCardConnect", rv)?;
        Ok(PcscCard {
            handle,
            reader,
            _ctx: ctx,
            dead: false,
        })
    }

    fn disconnect(&mut self) {
        if self.handle != 0 {
            // Reset so the card forgets the management key authentication.
            // SAFETY: we own the handle.
            unsafe { sys::SCardDisconnect(self.handle, sys::RESET_CARD) };
            self.handle = 0;
        }
    }

    fn select_piv(&mut self) -> ykvault_core::Result<()> {
        let resp = self.transmit(&SELECT_PIV)?;
        match resp[resp.len() - 2..] {
            [0x90, 0x00] | [0x61, _] => Ok(()),
            [sw1, sw2] => Err(Error::Card {
                sw: u16::from_be_bytes([sw1, sw2]),
                context: "SELECT PIV",
            }),
            _ => unreachable!(),
        }
    }

    /// Starts an exclusive PC/SC transaction and selects PIV (another app may
    /// have selected a different applet since). Pair with [`PcscCard::end`].
    /// Callers that nest operations count depth themselves.
    pub fn begin(&mut self) -> ykvault_core::Result<()> {
        if self.dead {
            return Err(Error::CardRemoved);
        }
        // SAFETY: valid handle.
        if unsafe { sys::SCardBeginTransaction(self.handle) } != 0 {
            self.dead = true;
            return Err(Error::CardRemoved);
        }
        let r = self.select_piv();
        if r.is_err() {
            self.end();
        }
        r
    }

    /// Ends the transaction started by [`PcscCard::begin`], leaving the card
    /// as it is (the management key authentication survives until the next
    /// transaction by another app resets or reselects).
    pub fn end(&mut self) {
        if self.handle != 0 && !self.dead {
            // SAFETY: valid handle; a failure here means the card is gone and
            // the next call reports it.
            unsafe { sys::SCardEndTransaction(self.handle, sys::LEAVE_CARD) };
        }
    }

    /// Runs `f` inside one exclusive transaction (`begin`, `f`, `end`).
    pub fn transaction<R>(
        &mut self,
        f: impl FnOnce(&mut Self) -> ykvault_core::Result<R>,
    ) -> ykvault_core::Result<R> {
        self.begin()?;
        let result = f(self);
        self.end();
        result
    }

    /// Starts a watcher that calls `on_removed(reader)` once when this card's
    /// reader reports no card, disappears, or PC/SC fails.
    pub fn watch_removal(
        &self,
        on_removed: impl FnOnce(&str) + Send + 'static,
    ) -> Result<RemovalWatcher, PcscError> {
        RemovalWatcher::spawn(&self.reader, on_removed)
    }
}

impl SmartCard for PcscCard {
    fn transmit(&mut self, apdu: &[u8]) -> ykvault_core::Result<Vec<u8>> {
        if self.dead {
            return Err(Error::CardRemoved);
        }
        let mut buf = [0u8; RECV_MAX];
        let mut len = RECV_MAX as sys::Dword;
        // SAFETY: valid handle, input slice and output buffer of `len` bytes.
        let rv = unsafe {
            sys::SCardTransmit(
                self.handle,
                &sys::PCI_T1,
                apdu.as_ptr(),
                apdu.len() as sys::Dword,
                ptr::null_mut(),
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        // Removal, reset by another app (PIV state lost) and other transport
        // failures all end the session, as the trait requires.
        if rv != 0 || (len as usize) < 2 {
            self.dead = true;
            zeroize::Zeroize::zeroize(&mut buf);
            return Err(Error::CardRemoved);
        }
        let resp = buf[..len as usize].to_vec();
        zeroize::Zeroize::zeroize(&mut buf);
        Ok(resp)
    }

    fn reader_id(&self) -> &str {
        &self.reader
    }
}

impl Drop for PcscCard {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Background thread on `SCardGetStatusChange` for one reader. Dropping it
/// stops the thread.
pub struct RemovalWatcher {
    stop: Arc<AtomicBool>,
    ctx: sys::Context,
    thread: Option<JoinHandle<()>>,
}

impl RemovalWatcher {
    pub fn spawn(
        reader: &str,
        on_removed: impl FnOnce(&str) + Send + 'static,
    ) -> Result<Self, PcscError> {
        let c_reader = CString::new(reader).map_err(|_| PcscError::NoYubiKey)?;
        let ctx = Context::establish()?;
        let raw_ctx = ctx.0;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let name = reader.to_owned();
        let thread = thread::Builder::new()
            .name("ykvault-removal".into())
            .spawn(move || {
                let mut current = state::UNAWARE;
                while !stop2.load(Ordering::Acquire) {
                    let mut rs = sys::ReaderState {
                        reader: c_reader.as_ptr(),
                        user_data: ptr::null_mut(),
                        current_state: current,
                        event_state: 0,
                        atr_len: 0,
                        atr: [0; 33],
                    };
                    // SAFETY: one valid reader state; `c_reader` outlives the call.
                    let rv = unsafe { sys::SCardGetStatusChange(ctx.0, POLL_MS, &mut rs, 1) };
                    let event = rs.event_state;
                    match classify(rv as u32, event, current) {
                        Step::Wait(next) => {
                            // Guard against a busy loop if PC/SC keeps
                            // returning immediately without a change.
                            if rv == 0 && next == current {
                                thread::sleep(Duration::from_millis(100));
                            }
                            current = next;
                        }
                        Step::Removed => {
                            if !stop2.load(Ordering::Acquire) {
                                on_removed(&name);
                            }
                            break;
                        }
                    }
                }
                drop(ctx);
            })
            .map_err(|_| PcscError::Scard {
                op: "spawn watcher",
                code: 0,
            })?;
        Ok(RemovalWatcher {
            stop,
            ctx: raw_ctx,
            thread: Some(thread),
        })
    }
}

impl Drop for RemovalWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return;
        };
        if thread.thread().id() == thread::current().id() {
            return; // dropped from inside the callback: the loop exits by itself
        }
        if !thread.is_finished() {
            // SAFETY: the thread still owns the context; SCardCancel may be
            // called from another thread. Worst case the poll times out.
            unsafe { sys::SCardCancel(self.ctx) };
        }
        let _ = thread.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_state_matches_apple_layout() {
        assert_eq!(
            core::mem::size_of::<sys::ReaderState>(),
            8 + 8 + 4 + 4 + 4 + 33
        );
        assert_eq!(core::mem::size_of::<sys::IoRequest>(), 8);
    }

    /// Links PCSC.framework and calls into it. CI runners have no reader.
    #[test]
    fn enumerates_without_hardware() {
        let readers = yubikey_readers().expect("PC/SC enumeration");
        if readers.is_empty() {
            assert_eq!(PcscCard::open(None).err(), Some(PcscError::NoYubiKey));
        }
    }

    #[test]
    fn watcher_on_missing_reader_reports_removal() {
        let (tx, rx) = std::sync::mpsc::channel();
        let w = RemovalWatcher::spawn("No Such YubiKey Reader", move |r| {
            tx.send(r.to_owned()).unwrap();
        });
        if let Ok(w) = w {
            let got = rx.recv_timeout(Duration::from_secs(5)).expect("callback");
            assert_eq!(got, "No Such YubiKey Reader");
            drop(w);
        }
    }

    /// Run on a Mac with a YubiKey: `cargo test -p ykvault-pcsc -- --ignored`.
    #[test]
    #[ignore = "needs a physical YubiKey"]
    fn hardware_select_and_serial() {
        let mut card = PcscCard::open(None).expect("YubiKey");
        let resp = card
            .transaction(|c| c.transmit(&[0x00, 0xF8, 0x00, 0x00]))
            .unwrap();
        assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00]);
        println!(
            "reader {} serial {:02X?}",
            card.reader_id(),
            &resp[..resp.len() - 2]
        );
    }
}
