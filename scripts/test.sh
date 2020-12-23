#!/usr/bin/env bash
SCRIPTDIR=$PWD
for d in $(ls -d ./pallets/*/) ; do
    cd "$SCRIPTDIR/$d" && WASM_BUILD_TOOLCHAIN=nightly-2020-10-05 cargo test
done

cd "$SCRIPTDIR/wasm-utils" && WASM_BUILD_TOOLCHAIN=nightly-2020-10-05 cargo test