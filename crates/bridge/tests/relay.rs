//! End-to-end: run the real bridge binary against a fake app socket.

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use p99_bridge::{Endian, read_frame, write_frame};

const EXT: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

#[test]
fn relays_both_ways_and_says_hello() {
    let dir = std::env::temp_dir().join(format!("p99b-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("bridge.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap();

    let app = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let hello = read_frame(&mut s, Endian::Little).unwrap().unwrap();
        let req = read_frame(&mut s, Endian::Little).unwrap().unwrap();
        write_frame(&mut s, Endian::Little, br#"{"v":1,"type":"cancel","req_id":"r1"}"#).unwrap();
        (String::from_utf8(hello).unwrap(), String::from_utf8(req).unwrap())
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_99p-bridge"))
        .arg(EXT)
        .env("P99_BRIDGE_SOCK", &sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let req = br#"{"v":1,"type":"fill_request","req_id":"r1","mode":"login","host":"github.com","origin":"https://github.com"}"#;
    let mut stdin = child.stdin.take().unwrap();
    write_frame(&mut stdin, Endian::Native, req).unwrap();
    stdin.flush().unwrap();

    let mut stdout = child.stdout.take().unwrap();
    let reply = read_frame(&mut stdout, Endian::Native).unwrap().unwrap();
    assert_eq!(reply, br#"{"v":1,"type":"cancel","req_id":"r1"}"#);

    let (hello, got) = app.join().unwrap();
    assert!(hello.contains(r#""type":"bridge_hello""#) && hello.contains(EXT), "{hello}");
    assert_eq!(got.as_bytes(), req);
    drop(stdin);
    assert!(child.wait().unwrap().success());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reports_app_unavailable() {
    let out = Command::new(env!("CARGO_BIN_EXE_99p-bridge"))
        .env("P99_BRIDGE_SOCK", "/nonexistent/99p/bridge.sock")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let msg = read_frame(&mut &out.stdout[..], Endian::Native).unwrap().unwrap();
    assert_eq!(msg, br#"{"v":1,"type":"error","code":"app_unavailable"}"#);
}
