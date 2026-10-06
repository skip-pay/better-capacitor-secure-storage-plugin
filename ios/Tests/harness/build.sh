#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
DEVICE="${SIMULATOR_ID:-booted}"
BUILD="$PWD/.build"
WRAPPER="$BUILD/SwiftKeychainWrapper"
mkdir -p "$BUILD"
if [ ! -d "$WRAPPER" ]; then
  git clone --quiet --depth 1 --branch 4.0.1 https://github.com/jrendel/SwiftKeychainWrapper.git "$WRAPPER"
fi
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun --sdk iphonesimulator swiftc -swift-version 5 -suppress-warnings -sdk "$SDK" -target "$(uname -m)-apple-ios15.0-simulator" -o "$BUILD/harness" \
  main.swift "$WRAPPER"/SwiftKeychainWrapper/*.swift ../../Sources/SecureStoragePlugin/SecureStorageVault.swift \
  -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __entitlements -Xlinker entitlements.plist
status=0
xcrun simctl spawn "$DEVICE" "$BUILD/harness" > "$BUILD/run.txt" || status=$?
grep "^FAIL " "$BUILD/run.txt" || true
echo "passed $(grep -c "^PASS" "$BUILD/run.txt"), failed $(grep -c "^FAIL " "$BUILD/run.txt" || true)"
exit $status
