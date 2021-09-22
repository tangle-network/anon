# Pallet Overview

## assets-mixer
The `assets-mixer` pallet is meant to expose a simple deposit/withdraw API and consume a merkle tree interface, implemented for example by the `merkle` pallet. The `assets-mixer` pallet uses `pallet-assets` assets to interface with the deposit and withdraw functionality.
## mixer
The regular `mixer` follows similarly from the `assets-mixer` but uses ORML style tokens provided in the `tokens` to interface with the deposit and withdraw functionality.
## merkle
The `merkle` pallet deals primarily with merkle tree storage and zero-knowledge proof verification of merkle membership proofs. This pallet exposes an API for mixers to consume and interact directly with the underlying merkle tree and zero-knowledge verifiers.
## tokens
The `tokens` pallet provides a wrapper over ORML style tokens. It is taken and adapted directly from the [ORML tokens](https://github.com/open-web3-stack/open-runtime-module-library/tree/master/tokens) repository. It is adapted to include functionality provided by the [pallet-assets](https://github.com/paritytech/substrate/tree/master/frame/assets).
## traits
The `traits` library contains traits that are directly taken from ORML. This allowed us to extend our own token library and required a consistent underlying Substrate verision.
## utils
The `utlities` library contains helper functions, structs, and traits that are directly taken from ORML. This allowed us to extend our own token & trait library and required a consistent underlying Substrate verision.
