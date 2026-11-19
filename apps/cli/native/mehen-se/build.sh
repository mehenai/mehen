#!/usr/bin/env bash
# Builds mehen-se as a universal (arm64 + x86_64) binary and ad-hoc signs it.
# Usage: ./build.sh [--native]   (--native: host architecture only, faster)
set -euo pipefail

cd "$(dirname "$0")"
min_macos=13.0
out=build/mehen-se
identifier=dev.mehen.mehen-se

mkdir -p build
if [[ "${1:-}" == "--native" ]]; then
  swiftc -O -swift-version 6 -target "$(uname -m)-apple-macos${min_macos}" -o "$out" mehen-se.swift
else
  swiftc -O -swift-version 6 -target "arm64-apple-macos${min_macos}" -o build/mehen-se-arm64 mehen-se.swift
  swiftc -O -swift-version 6 -target "x86_64-apple-macos${min_macos}" -o build/mehen-se-x86_64 mehen-se.swift
  lipo -create -output "$out" build/mehen-se-arm64 build/mehen-se-x86_64
  rm -f build/mehen-se-arm64 build/mehen-se-x86_64
fi

# Ad-hoc signature with a stable identifier and the hardened runtime. No
# entitlements: Secure Enclave keys held as dataRepresentation blobs never touch
# the keychain, so no keychain-access-groups entitlement is needed.
codesign --force --sign - --identifier "$identifier" --options runtime "$out"

lipo -info "$out"
codesign --display --verbose=2 "$out" 2>&1 | grep -E '^(Identifier|Format|CodeDirectory|Signature)'
