#!/bin/bash
# Builds "build/99passwords.app" (ad-hoc signed). Run on macOS from anywhere.
set -euo pipefail
cd "$(dirname "$0")"
cargo build -p p99-ffi -p p99-bridge --release --locked --manifest-path ../Cargo.toml
swift build -c release
app="build/99passwords.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp .build/release/NinetyNinePasswords ../target/release/99p-bridge "$app/Contents/MacOS/"
cp Info.plist "$app/Contents/"
mkdir -p "$app/Contents/Resources" && cp AppIcon.icns "$app/Contents/Resources/"
# The Chrome extension, for "Load unpacked" from the app (tests left out).
rsync -a --exclude test --exclude e2e --exclude node_modules ../extension/ "$app/Contents/Resources/extension/"
codesign --force --sign - "$app"
echo "built $app"
