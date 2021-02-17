#!/usr/bin/env bash
pallet="mixer"
./target/release/node-template benchmark --chain dev --pallet "pallet_${pallet}" --extrinsic "*" --steps 20 --repeat 5 --output "./pallets/${pallet}/src/"