# 99passwords menu bar app

SwiftUI + AppKit, linked to the Rust core through `crates/ffi/` (C ABI, `ykvault.h`).
A Swift package, no Xcode project.

```sh
macos/build-app.sh                 # builds "macos/build/99passwords.app"
open macos/build/99passwords.app
```

- Click the 99passwords icon in the menu bar to open the panel; right-click for Lock and Quit.
  The footer shows when the vault was last changed and how full the key is.
- With a YubiKey 5 plugged in, "Set up this YubiKey" then "Create vault" provisions it (slot 0x82, new
  PIN and PIV management key: use a key whose PIV application you don't need).
- Chrome: load `extension/` unpacked. The app writes the native host manifest at
  launch and the bridge lives in `Contents/MacOS/ykvault-bridge`. Click the
  extension icon (or Cmd+Shift+L) on a login page.
- The gear in the footer opens **Settings**: auto-lock, **Clone my YubiKey**
  (clone the vault to an empty second YubiKey, sync one that is behind),
  encrypted `.ykv` backup files with an optional recovery key, and plaintext
  CSV/JSON import and export (written 0600 behind a warning).
- Every multi-APDU operation (unlock, save, clone, sync, import) runs in one
  PC/SC transaction per card, so other apps cannot interleave with it.
- Locks on: the lock button, idle time (5 min by default, set in Settings),
  sleep, screen lock, and YubiKey removal.
  Copied secrets are marked concealed and cleared after 30 s.
- Tests of the Swift wrapper and the bridge server: `cargo build -p ykvault-ffi --release && scripts/swift-tests.sh`.
