# Substrate CLSAG - Compact ring signature runtime module

A basic Substrate node, with a runtime module for verifying ring-signatures on-chain. The logic for the ring-signatures is unaudited and was taken mostly from https://github.com/crate-crypto/CLSAG. Modifications were made to be compatible inside a substrate runtime and serialization of wrapper types is added to compile `curve25519-dalek` types inside a runtime.

The runtime module is located under the name `pallet-groups` in `pallets/groups` directory. It allows the creation of rings or groups and further the verification of ring signatures over such rings or groups. The unexhaustive list of tasks left to make this robust are as follows:
- [x] Serialize key types for ring signatures using `curve25519-dalek`
- [x] Ring/group creation using a substrate runtime function
- [x] Ring signature verification using a substrate runtime function
- [ ] Ring signature linking using a substrate runtime function

The paper for this implementation is: https://eprint.iacr.org/2019/654.pdf.
