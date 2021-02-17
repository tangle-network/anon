#!/usr/bin/env bash
pallet="mixer"
./target/release/node-template benchmark --chain dev --pallet "pallet_${pallet}" --extrinsic "*" --steps 10 --repeat 4 --output "./pallets/${pallet}/src/"