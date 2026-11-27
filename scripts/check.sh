#!/bin/sh
# Portable checks, run locally and by CI. Run from the repo root: scripts/check.sh
# macOS-only parts (pcsc, Swift BridgeServer, the app) need a Mac:
#   cargo test -p ykvault-pcsc && scripts/swift-tests.sh && macos/build-app.sh
# Swift needs only the Command Line Tools (no Xcode); tests use Swift Testing.
set -eu

cargo build --workspace --locked
cargo test --workspace --locked

echo "== C header matches the FFI staticlib"
extra=""; [ "$(uname)" = Darwin ] && extra="-framework PCSC"
# shellcheck disable=SC2086
cc -Wall -Wextra -Werror -I crates/ffi/include crates/ffi/tests/smoke.c \
  target/debug/libykvault_ffi.a -lpthread -ldl -lm $extra -o target/ffi-smoke
./target/ffi-smoke

echo "== Offline, minimal dependency policy (SPEC §1)"
if cargo tree --workspace -e normal,build --prefix none | sort -u |
  grep -Ei '^(tokio|async-std|hyper|reqwest|ureq|rustls|openssl|native-tls|ring|cc|bindgen|syn|proc-macro2|serde_derive|uniffi) '; then
  echo "forbidden dependency found"; exit 1
fi

if ! command -v node >/dev/null; then
  echo "== Skipping extension tests (node not installed)"
  exit 0
fi

echo "== Extension unit tests"
node --test extension/test/*.test.js

if node -e 'require("playwright")' 2>/dev/null; then
  echo "== Extension end-to-end in Chromium"
  node extension/e2e/run.js
else
  echo "== Skipping extension e2e (npm install playwright to run it)"
fi
