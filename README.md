# anon
Substrate based mixer w/ relayable transactions using bulletproofs and Curve25519.

## Overview
At the highest-level, this is a cryptocurrency mixing pallet that uses non-trusted setup zero-knowledge proofs to facilitate mixing operations. It uses the bulletproofs library built from [dalek-cryptography](https://github.com/dalek-cryptography). The repo contains pallets that allow for creation of merkle trees with elements in Curve25519's scalar field and a mixer that utilises these merkle trees to built an on-chain application or protocol.

### Pallet documentation
- https://docs.rs/pallet-mixer/3.0.0/pallet_mixer/
- https://docs.rs/pallet-merkle/3.0.0/pallet_merkle/

### Dependencies
The library utilises a variety of zero-knowledge primitives, gadgets, circuits, etc. that are all implemented using bulletproofs R1CS api with Curve25519. You can find more about the components below and descriptions following thereafter.
- [Bulletproof zero-knowledge gadgets](https://github.com/webb-tools/bulletproof-gadgets)
- [Transaction Relayer](https://github.com/webb-tools/relayer)
- [Mixer CLI](https://github.com/webb-tools/cli)
- [Mixer dApp](https://github.com/webb-tools/webb-dapp)
- [Anon Typescript API](https://github.com/webb-tools/webb.js)

The architecture for the project is as follows. We have pallets in this repo and a Substrate chain for running this runtime logic. We developed zero-knowledge gadgets that expose a prover and a verifier for interacting with this runtime. Specifically, we embed the gadget's verifiers on-chain so that proofs can be verified on-chain to eliminate any trust involved in mixing currencies. Users are responsible with generating proofs, using the tools in the gadget repo, off-chain and broadcasting these proofs to the network using a signed extrinsic or a live relayer.

Relayers are used to relay transactions on behalf of users. This is necessary because extrinsics normally charge a fee for submission and so we enable a "fee-less" experience by allowing users to offload extrinsic submission to a third-party relayer who can submit transactions on behalf of users who wish to remain more anonymous. Note that there should still be more work put into the fee-mechanism to ensure that relayers are incentivised to run such a service in production.

### Tools

The flow for integrating these tools into your Substrate project are fairly straightforward. You will add the pallets of interest to your Substrate project and follow the runtime implementations necessary to get your node to compile. From there, you will have integrated a mixer to your Substrate project.

It is possible by extending your dApp with our types in our Typescript API to have this functionality in a front-end application for users to interact with. It is also possible to run a transaction relayer to submit withdrawal transactions from the mixers on behalf of users. Please refer to the documentation in these respective projects when facing issues and asking questions.

## Build

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Initialize your Wasm Build environment:

```bash
./scripts/init.sh
```

Build Wasm and native code:

```bash
cargo build --release
```

## Run

### Single node development chain

Purge any existing developer chain state:

```bash
./target/release/webb-node purge-chain --dev
```

Start a development chain with:

```bash
./target/release/webb-node --dev
```
