# AGENTS.md

Guidance for coding agents (and humans) working in this repository.

## What this is

99passwords: a macOS password manager whose encrypted vault is stored only on
a YubiKey 5 (PIV data objects). Rust core, C ABI, Swift menu bar app, Chrome
MV3 extension talking to the app through a native messaging bridge.
`docs/SPEC.md` is the source of truth for formats, crypto and protocol.

## Layout

| Path | What | Language |
|---|---|---|
| `crates/core` | `ykvault-core`: model, TLV codec, crypto, container, PIV APDU client, A/B bank storage, session, merge, `.ykv` / CSV / JSON, TOTP, generator, `MockYubiKey` | Rust |
| `crates/pcsc` | `ykvault-pcsc`: PCSC.framework transport, card removal watcher (macOS only, stubs elsewhere) | Rust |
| `crates/ffi` | `ykvault-ffi`: hand-written C ABI staticlib; header `crates/ffi/include/ykvault.h` | Rust, C |
| `crates/cli` | `ykvault`: admin CLI (`info`, `piv-reset`) | Rust |
| `crates/bridge` | `ykvault-bridge`: Chrome native messaging host, relays to the app's Unix socket | Rust |
| `macos/` | Swift package: `VaultKit` (Swift wrapper over the C ABI), `NinetyNinePasswords` (the app) | Swift |
| `macos/BridgeServer` | App-side socket server, peer check, message router, native host manifest | Swift |
| `extension/` | Chrome extension: `sw.js` service worker, `content.js` field UI, `page.js` fill, `lib.js` pure helpers | JS |
| `scripts/` | `check.sh` (all portable checks), `swift-tests.sh` (macOS) | sh |
| `.github/workflows/` | `ci.yml` (checks), `release.yml` (tag -> GitHub release) | YAML |

Data flow: Chrome tab -> `extension/sw.js` -> native messaging ->
`ykvault-bridge` -> Unix socket -> `BridgeServer` in the app -> `VaultKit` ->
C ABI -> `ykvault-core` -> `ykvault-pcsc` -> YubiKey.

## Commands

```sh
scripts/check.sh                      # build + all Rust tests, C header smoke test, dependency deny list, extension unit (+ e2e if playwright)
cargo test -p ykvault-core            # core only, fastest loop
cargo test -p ykvault-core --test session   # one integration test file
node --test extension/test/*.test.js  # extension unit tests
cargo build -p ykvault-bridge && node extension/e2e/run.js   # extension e2e (needs playwright)
# macOS only:
cargo test -p ykvault-pcsc
cargo build -p ykvault-ffi --release && scripts/swift-tests.sh
macos/build-app.sh                    # -> macos/build/99passwords.app
open macos/build/99passwords.app     # needs a YubiKey 5
```

GitHub Actions (`.github/workflows/ci.yml`) runs these on Linux and macOS
for every push and PR. Still run `scripts/check.sh` before you finish, and
the macOS commands too if you changed Swift, `crates/pcsc` or `crates/ffi`;
if you cannot, the macOS CI job covers them. Releases: add
`docs/releases/vX.Y.Z.md`, then push the tag `vX.Y.Z`
(`.github/workflows/release.yml`).

## Rules

- **Security first.** This handles passwords. Do not log, print or persist
  secrets. Keep secret buffers in the zeroizing types the core already uses
  (`secret.rs`). Nothing but the documented files may be written to disk
  (SPEC §1).
- **Minimal dependencies.** The core is offline by construction: no async
  runtime, no HTTP/TLS, no sockets, no proc-macros, no build scripts, no serde.
  `scripts/check.sh` fails on forbidden crates. Ask before adding any crate.
- **Format changes need the spec.** Any change to the on-card layout, payload
  TLV tags, crypto, `.ykv`, FFI or bridge messages must update `docs/SPEC.md`
  and stay backward compatible with existing vaults, or bump the version
  explicitly.
- **C ABI.** `crates/ffi/include/ykvault.h` is hand-written; keep it in sync
  with `crates/ffi/src/lib.rs`. The smoke test in `check.sh` compiles against it.
- **Tests use `MockYubiKey`.** Never require a real YubiKey for a test. The
  app has no demo mode; the mock is for tests only. Use
  `example.com` addresses and made-up names in fixtures.
- **Extension** stays vanilla JS with no dependencies and no popup.
- Keep changes small and simple. Match the surrounding style (the code is not
  run through `cargo fmt`; do not reformat files you are not changing).
