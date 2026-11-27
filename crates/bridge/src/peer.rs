//! Peer check on the app socket: the process on the other end must run as
//! our own uid (SPEC §12.1). The code-signature check is added once the app
//! has a real signing identity (it is ad-hoc signed for now).

use std::io;
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_void};
use std::os::unix::net::UnixStream;

unsafe extern "C" {
    fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut u32) -> c_int;
    fn getuid() -> u32;
}

/// The uid of the process at the other end of `s`.
#[cfg(target_os = "macos")]
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    const SOL_LOCAL: c_int = 0;
    const LOCAL_PEERCRED: c_int = 1;
    #[repr(C)]
    struct XuCred {
        cr_version: u32,
        cr_uid: u32,
        cr_ngroups: i16,
        cr_groups: [u32; 16],
    }
    let mut c = XuCred { cr_version: 0, cr_uid: u32::MAX, cr_ngroups: 0, cr_groups: [0; 16] };
    let mut len = std::mem::size_of::<XuCred>() as u32;
    // SAFETY: `c` is a valid out-buffer of `len` bytes.
    let rc = unsafe {
        getsockopt(s.as_raw_fd(), SOL_LOCAL, LOCAL_PEERCRED, (&raw mut c).cast(), &mut len)
    };
    if rc != 0 || c.cr_version != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(c.cr_uid)
}

/// The uid of the process at the other end of `s`.
#[cfg(target_os = "linux")]
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    const SOL_SOCKET: c_int = 1;
    const SO_PEERCRED: c_int = 17;
    #[repr(C)]
    struct UCred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    let mut c = UCred { pid: 0, uid: u32::MAX, gid: 0 };
    let mut len = std::mem::size_of::<UCred>() as u32;
    // SAFETY: `c` is a valid out-buffer of `len` bytes.
    let rc = unsafe {
        getsockopt(s.as_raw_fd(), SOL_SOCKET, SO_PEERCRED, (&raw mut c).cast(), &mut len)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(c.uid)
}

/// Fails unless the peer runs as the same user as this process.
pub fn verify(s: &UnixStream) -> io::Result<()> {
    // SAFETY: getuid has no preconditions.
    let me = unsafe { getuid() };
    if peer_uid(s)? == me {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "socket peer is another user"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn socketpair_peer_is_us() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        super::verify(&a).unwrap();
    }
}
