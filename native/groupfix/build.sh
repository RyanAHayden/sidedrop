#!/usr/bin/env bash
# Builds the app-group and keychain fix (groupfix.m, B23; a copy of iFizBox's B211/B227 fix) as an arm64 iOS 15+ dylib
# into native/groupfix/sidedrop-groupfix.dylib, which is committed: the image (python:3.13-slim) has no iOS toolchain,
# and app.py's sign_ipa injects that file with zsign -l. Run it after changing groupfix.m and commit the result (and
# its .source-sha256); test_app.py checks the committed dylib matches the current source.
#
#   build.sh            build it
#   build.sh <out>      build it to <out> instead (a look at it; no .source-sha256)
#
# Needs IOS_SDK (an iPhoneOS.sdk; this machine has ~/.local/share/ios-sdk/iPhoneOS27.1.sdk), clang and ld64.lld
# (LD64_LLD, else rustup's, else the one on PATH).
set -euo pipefail
cd "$(dirname "$0")"
sdk=${IOS_SDK:?set IOS_SDK to an iPhoneOS.sdk}
lld=${LD64_LLD:-$(rustc --print sysroot 2>/dev/null || true)/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld64.lld}
[ -x "$lld" ] || lld=$(command -v ld64.lld)
out=${1:-sidedrop-groupfix.dylib}
mkdir -p "$(dirname "$out")"
# No debug paths that differ per checkout (lld's LC_UUID is a hash of the output, which dyld needs for new SDKs).
clang -target arm64-apple-ios15.0 -isysroot "$sdk" -dynamiclib -fobjc-arc -O2 -Wall -Wextra -Werror \
  -fdebug-prefix-map="$PWD"=. -fuse-ld=lld --ld-path="$lld" -Wl,-adhoc_codesign \
  -install_name @executable_path/sidedrop-groupfix.dylib -framework Foundation -framework Security \
  -o "$out" groupfix.m
# The source it was built from, for the test (no toolchain needed to tell a stale dylib).
[ $# -gt 0 ] || sha256sum groupfix.m | cut -d' ' -f1 > "$out.source-sha256"
