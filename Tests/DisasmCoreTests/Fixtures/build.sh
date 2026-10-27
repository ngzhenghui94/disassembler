#!/bin/sh
# Regenerate tiny Android ELF fixtures with Xcode clang and Homebrew lld/llvm.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' 'int puts(const char *s) { return 0; }' 'int printf(const char *s, ...) { return 0; }' 'int external_counter = 17;' > "$tmp/dependency.c"
lld="$(brew --prefix lld)/bin/ld.lld"
strip="$(brew --prefix llvm)/bin/llvm-strip"
for pair in arm64:aarch64-linux-android21 arm:armv7a-linux-androideabi21 arm-thumb:armv7a-linux-androideabi21 arm-mixed:armv7a-linux-androideabi21 x86_64:x86_64-linux-android21 x86_64-got:x86_64-linux-android21 x86:i686-linux-android21; do
    arch=${pair%%:*}
    target=${pair#*:}
    xcrun clang --target="$target" -fuse-ld="$lld" -nostdlib -shared -fPIC -Wl,-soname,libfixture-dep.so "$tmp/dependency.c" -o "$tmp/libfixture-dep.so"
    mode=
    if [ "$arch" = arm-thumb ]; then mode=-mthumb; fi
    if [ "$arch" = arm-mixed ]; then mode='-mthumb -DMIXED_ARM'; fi
    if [ "$arch" = x86_64-got ]; then mode=-fno-plt; fi
    xcrun clang --target="$target" $mode -fuse-ld="$lld" -nostdlib -shared -fPIC -O1 -fno-omit-frame-pointer android.c -L"$tmp" -lfixture-dep -o "$arch.so"
    "$strip" --strip-all "$arch.so" -o "$arch-stripped.so"
done
