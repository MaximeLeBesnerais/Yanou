#!/usr/bin/env bash
# Builds the Yanou native core for OpenHarmony and stages it into entry/libs/<abi>.
#
# The NDK ships clang wrappers named after the Rust target triple; each carries its own
# --target and --sysroot, which is also why the same wrapper is the C compiler below.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
abi=${1:-arm64-v8a}
case "$abi" in
  arm64-v8a) rust_target=aarch64-unknown-linux-ohos ;;
  *) echo "only arm64-v8a is wired up" >&2; exit 1 ;;
esac

ndk=${YANOU_OHOS_NDK:-/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/native}
compiler="$ndk/llvm/bin/${rust_target}-clang"
[[ -x "$compiler" ]] || { echo "missing $compiler" >&2; exit 1; }

# aws-lc-sys (the TLS/AEAD backend the WireGuard crate needs later) shells out to cmake
# and reads OHOS_NDK_HOME. DevEco bundles both the NDK and a cmake/ninja pair.
export PATH="$ndk/build-tools/cmake/bin:$PATH"
export OHOS_NDK_HOME="$(dirname "$ndk")"

underscored=${rust_target//-/_}
cargo_linker="CARGO_TARGET_$(printf '%s' "$underscored" | tr '[:lower:]' '[:upper:]')_LINKER"

# Keep the registry inside the project: the default ~/.cargo is outside the sandbox this
# build runs in, and a project-local cache makes the native build reproducible anyway.
export CARGO_HOME="${CARGO_HOME:-$root/rust/.cargo}"

out="$root/entry/libs/$abi"
mkdir -p "$out"

env "CC_${underscored}=$compiler" \
    "CXX_${underscored}=${compiler}++" \
    "AR_${underscored}=$ndk/llvm/bin/llvm-ar" \
    "$cargo_linker=$compiler" \
    CARGO_TARGET_DIR="$root/rust/target" \
    cargo build --manifest-path "$root/rust/Cargo.toml" \
      -p yanou-core --target "$rust_target" --release

cp "$root/rust/target/$rust_target/release/libyanou_core.so" "$out/"

# C only: no libc++_shared.so to package, unlike a C++ NAPI shim.
"$compiler" -shared -fPIC -O2 -Wall -Wextra -Werror \
  -Wl,--no-undefined -Wl,-soname,libyanou.so \
  "$root/entry/src/main/cpp/yanou_napi.c" \
  -I"$ndk/sysroot/usr/include" \
  -L"$out" -lyanou_core -lace_napi.z \
  -o "$out/libyanou.so"

"$ndk/llvm/bin/llvm-readobj" --file-headers "$out/libyanou.so" | grep "EM_AARCH64" >/dev/null
# The registration constructor is a local symbol, so this is the full symbol table, not -D.
"$ndk/llvm/bin/llvm-nm" --defined-only "$out/libyanou.so" | grep "RegisterYanouModule" >/dev/null
"$ndk/llvm/bin/llvm-readobj" --needed-libs "$out/libyanou.so" | grep "libyanou_core.so" >/dev/null

echo "native libraries:"
ls -la "$out"
