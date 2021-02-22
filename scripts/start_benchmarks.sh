#!/usr/bin/env bash
pallet=${1:-"merkle"}
extrinsic=${2:-"*"}
echo "Running benchmarks for pallet: $pallet"
echo "Extrinsic: $extrinsic"
./target/release/node-template benchmark --chain dev --pallet "pallet_${pallet}" --extrinsic "$extrinsic" --steps 20 --repeat 5 --output "./pallets/${pallet}/src/"