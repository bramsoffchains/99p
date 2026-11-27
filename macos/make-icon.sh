#!/bin/bash
# Regenerates macos/AppIcon.icns from LogoView (Design.swift). Run after
# build-app.sh whenever the logo changes, and commit the .icns.
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
P99_ICON_OUT="$tmp/icon.png" "build/99passwords.app/Contents/MacOS/NinetyNinePasswords"
set_=$tmp/AppIcon.iconset
mkdir "$set_"
for s in 16 32 128 256 512; do
  sips -z $s $s "$tmp/icon.png" --out "$set_/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$tmp/icon.png" --out "$set_/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$set_" -o AppIcon.icns
rm -rf "$tmp"
echo "wrote macos/AppIcon.icns"
