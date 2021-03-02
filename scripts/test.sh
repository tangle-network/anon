#!/usr/bin/env bash
SCRIPTDIR=$PWD

# test each pallets tests
for d in $(ls -d ./pallets/*/) ; do
    cd "$SCRIPTDIR/$d" && cargo test --features runtime-benchmarks
done

# test wasm utils
cd "$SCRIPTDIR/wasm-utils" && ./test.sh