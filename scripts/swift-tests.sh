#!/bin/sh
# Runs the Swift test suites (macOS). With only the Command Line Tools, the
# build sometimes forgets the Swift Testing macro plugin ("plugin for module
# 'TestingMacros' not found"), so load it explicitly when it is there.
set -u
cd "$(dirname "$0")/.."
plugin=/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib
extra=""
[ -f "$plugin" ] && extra="-Xswiftc -load-plugin-library -Xswiftc $plugin"
status=0
for p in macos/BridgeServer macos; do
  # shellcheck disable=SC2086
  out=$(swift test --package-path "$p" --scratch-path "$p/.build-test" $extra 2>&1)
  echo "$out" | tail -1
  echo "$out" | grep -q "passed after" && ! echo "$out" | grep -q "✘" || status=1
done
exit $status
