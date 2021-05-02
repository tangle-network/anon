
<h1 align="center">Webb Anon</h1>
<br />
<p align="center">
    <strong>🕸️  The Webb Anon Node 🕵️‍♂️</strong>
    <br />
    <sub> ⚠️ Under Heavy Development ⚠️ </sub>
</p>

<br />

✨ Substrate based Mixer w/ Relayable transactions using bulletproofs and Curve25519 ✨.

## Overview 📜

At the highest-level, this is a cryptocurrency mixing pallet that uses non-trusted 👤 setup [zero-knowledge proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof) to facilitate mixing operations. It uses the bulletproofs library built from [dalek-cryptography](https://github.com/dalek-cryptography). The repo contains pallets that allow for creation of merkle trees with elements in Curve25519's scalar field and a mixer that utilises these merkle trees to built an on-chain application or protocol.

### Pallet documentation 💎
- Mixer Pallet: [Docs](https://docs.rs/pallet-mixer)
- Merkle Pallet: [Docs](https://docs.rs/pallet-merkle)

### Dependencies 🧱

The library utilises a variety of zero-knowledge primitives, gadgets, circuits, etc. that are all implemented using bulletproofs R1CS api with Curve25519. You can find more about the components below and descriptions following thereafter:

- 🔐 [Bulletproof zero-knowledge gadgets](https://github.com/webb-tools/bulletproof-gadgets)
- 🧑‍✈️ [Transaction Relayer](https://github.com/webb-tools/relayer)
- 🧰 [Mixer CLI](https://github.com/webb-tools/cli)
- 🖥️ [Mixer dApp](https://github.com/webb-tools/webb-dapp)
- 🔋 [Webb.js SDK](https://github.com/webb-tools/webb.js)

### Architecture 🏗️

The architecture for the project is as follows: 

We have pallets in this repo and a Substrate chain for running this runtime logic. We developed zero-knowledge gadgets that expose a prover and a verifier for interacting with this runtime. Specifically, we embed the gadget's verifiers on-chain so that proofs can be verified on-chain to eliminate any trust involved in mixing currencies. Users are responsible with generating proofs, using the tools in the gadget repo, off-chain and broadcasting these proofs to the network using a signed extrinsic or a live relayer.

Relayers are used to relay transactions on behalf of users. This is necessary because extrinsics normally charge a fee for submission and so we enable a "fee-less" experience by allowing users to offload extrinsic submission to a third-party relayer who can submit transactions on behalf of users who wish to remain more anonymous. Note that there should still be more work put into the fee-mechanism to ensure that relayers are incentivised to run such a service in production.

### Tools 🛠️

The flow for integrating these tools into your Substrate project are fairly straightforward. You will add the pallets of interest to your Substrate project and follow the runtime implementations necessary to get your node to compile. From there, you will have integrated a mixer to your Substrate project.

It is possible by extending your dApp with our types in our Typescript API to have this functionality in a front-end application for users to interact with. It is also possible to run a transaction relayer to submit withdrawal transactions from the mixers on behalf of users. Please refer to the documentation in these respective projects when facing issues and asking questions.

## Build 👷

Install Rust 🦀:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Initialize your Wasm Build environment:

```bash
./scripts/init.sh
```

Build Wasm and native code:

```bash
./scripts/build.sh
```

## Run 🚀

### Single node development chain

Simply Run:

```bash
./scripts/start.sh
```

Or, you could, first by purge any existing developer chain state:

```bash
./target/release/webb-node purge-chain --dev
```

and then, start a development chain with:

```bash
./target/release/webb-node --dev
```

## Using Docker 🐳

We have a 3 pipelines right now, one for the main/master branch and this should be the stable release, and one is `edge` from the `develop` branch:

1. Pull the Docker Image

```bash
$ docker pull docker.pkg.github.com/webb-tools/anon/node:edge # change edge to latest for the master branch
```

2. Run the node using docker

```bash
$ docker run --rm -it docker.pkg.github.com/webb-tools/anon/node:edge webb-node --dev
```
This will run the node in dev mode, **without** saving any state, that is easy for testing and development.


## Safety ⚡

This crate uses `#![deny(unsafe_code)]` to ensure everything implemented in
100% Safe Rust.

## Contributing 🧑‍🤝‍🧑

Want to join us? take a look at some of these issues:

- [Issues labeled "good first issue"][good-first-issue]
- [Issues labeled "help wanted"][help-wanted]

[good-first-issue]: https://github.com/webb-tools/anon/labels/good%20first%20issue
[help-wanted]: https://github.com/webb-tools/anon/labels/help%20wanted

## License

<sup>
Licensed under <a href="LICENSE">The Unlicense</a>.
</sup>

<br/>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the `The Unlicense` license, shall
be licensed as above, without any additional terms or conditions.
</sub>
