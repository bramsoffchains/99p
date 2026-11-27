//! `ykvault-bridge`: Chrome starts this as the native messaging host
//! `app.99passwords.bridge`. It connects to the menu bar app's socket
//! (launching the app if needed) and relays frames both ways. See SPEC §12.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use ykvault_bridge::{Endian, bridge_hello, caller_origin, error_msg, peer, relay, write_frame};

const BUNDLE_ID: &str = "app.99passwords";

fn socket_path() -> PathBuf {
    // Debug builds can point at a test socket; release builds cannot.
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("YKV_BRIDGE_SOCK") {
        return p.into();
    }
    let home = std::env::var_os("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Application Support/99Passwords/bridge.sock")
}

fn launch_app() {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("/usr/bin/open")
        .args(["-g", "-b", BUNDLE_ID, "--args", "--background"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    #[cfg(not(target_os = "macos"))]
    let _ = BUNDLE_ID;
}

/// Connects, launching the app once and retrying for 5 s if it is not running.
fn connect() -> io::Result<UnixStream> {
    let path = socket_path();
    if let Ok(s) = UnixStream::connect(&path) {
        return Ok(s);
    }
    launch_app();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(&path) {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn fail(code: &str, why: impl std::fmt::Display) -> ExitCode {
    eprintln!("ykvault-bridge: {code}: {why}");
    let _ = write_frame(&mut io::stdout().lock(), Endian::Native, error_msg(code).as_bytes());
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let caller = caller_origin(&arg);

    let sock = match connect() {
        Ok(s) => s,
        Err(e) => return fail("app_unavailable", e),
    };
    if let Err(e) = peer::verify(&sock) {
        return fail("app_untrusted", e);
    }
    let mut to_app = match sock.try_clone() {
        Ok(s) => s,
        Err(e) => return fail("app_unavailable", e),
    };
    if let Err(e) = write_frame(&mut to_app, Endian::Little, bridge_hello(caller).as_bytes()) {
        return fail("app_unavailable", e);
    }

    // App -> Chrome. When the app hangs up, we are done.
    let mut from_app = sock;
    std::thread::spawn(move || {
        let mut out = io::stdout().lock();
        let r = relay(&mut from_app, Endian::Little, &mut out, Endian::Native);
        if let Err(e) = r {
            eprintln!("ykvault-bridge: app->chrome: {e}");
        }
        let _ = out.flush();
        std::process::exit(0);
    });

    // Chrome -> app. Chrome closes stdin when the port disconnects.
    let r = relay(&mut io::stdin().lock(), Endian::Native, &mut to_app, Endian::Little);
    let _ = to_app.shutdown(std::net::Shutdown::Both);
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ykvault-bridge: chrome->app: {e}");
            ExitCode::FAILURE
        }
    }
}
