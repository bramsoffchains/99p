//! `SecretBytes`: heap buffer that is page-locked (best effort) and zeroized on drop.

use zeroize::Zeroize;

#[cfg(unix)]
unsafe extern "C" {
    fn mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
    fn munlock(addr: *const core::ffi::c_void, len: usize) -> i32;
}

/// Fixed-size secret. The buffer never reallocates, so the locked pages stay valid.
pub struct SecretBytes {
    buf: Box<[u8]>,
    locked: bool,
}

impl SecretBytes {
    pub fn new(bytes: &[u8]) -> Self {
        let buf: Box<[u8]> = bytes.to_vec().into_boxed_slice();
        let locked = lock(&buf);
        SecretBytes { buf, locked }
    }

    pub fn zeroed(len: usize) -> Self {
        let buf = vec![0u8; len].into_boxed_slice();
        let locked = lock(&buf);
        SecretBytes { buf, locked }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(unix)]
fn lock(buf: &[u8]) -> bool {
    // SAFETY: the pointer and length describe a live allocation owned by the caller.
    !buf.is_empty() && unsafe { mlock(buf.as_ptr().cast(), buf.len()) } == 0
}

#[cfg(not(unix))]
fn lock(_: &[u8]) -> bool {
    false
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        SecretBytes::new(&self.buf)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.buf.zeroize();
        #[cfg(unix)]
        if self.locked {
            // SAFETY: same allocation that was locked in `new`.
            unsafe { munlock(self.buf.as_ptr().cast(), self.buf.len()) };
        }
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.buf.len())
    }
}
