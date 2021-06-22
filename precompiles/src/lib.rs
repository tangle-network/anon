// SPDX-License-Identifier: Apache-2.0
// This file is part of Frontier.
//
// Copyright (c) 2020 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use rand_chacha::rand_core::SeedableRng;
use crate::encoding::Decode;
use rand_chacha::ChaChaRng;
use crate::types::WithdrawProof;
use bulletproofs::BulletproofGens;
use bulletproofs_gadgets::poseidon::{
	builder::{Poseidon, PoseidonBuilder},
	PoseidonSbox,
};
use sp_std::marker::PhantomData;
use sp_std::fmt::Debug;
use alloc::vec::Vec;
use frame_support::traits::Randomness;
use fp_evm::Precompile;
use evm::{ExitSucceed, ExitError, Context, executor::PrecompileOutput};
use sp_runtime::{
	traits::{
		CheckEqual,
		SimpleBitOps, Member, MaybeDisplay,
		MaybeSerializeDeserialize, MaybeMallocSizeOf, Bounded, AtLeast32BitUnsigned,
	},
};
use frame_support::{
	Parameter,
	traits::{
		MaxEncodedLen,
	},
};
use lazy_static::lazy_static;

pub struct BulletproofMerkleTreeMembershipPrecompile<O, B, R: Randomness<O, B>>(
	PhantomData<O>,
	PhantomData<B>,
	PhantomData<R>,
);

use codec::Input;

mod encoding;
mod types;

lazy_static! {
	static ref POSEIDON_HASHER: Poseidon = default_bulletproofs_poseidon_hasher();
}

pub fn default_bulletproofs_poseidon_hasher() -> Poseidon {
	let width = 6;
	// TODO: should be able to pass the number of generators
	let bp_gens = BulletproofGens::new(16500, 1);
	PoseidonBuilder::new(width)
		.bulletproof_gens(bp_gens)
		.sbox(PoseidonSbox::Exponentiation3)
		.build()
}

impl<O, B, R: Randomness<O, B>> Precompile for BulletproofMerkleTreeMembershipPrecompile<O, B, R>
	where
		O: Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + SimpleBitOps + Ord
			+ Default + Copy + CheckEqual + sp_std::hash::Hash + AsRef<[u8]> + AsMut<[u8]>
			+ MaybeMallocSizeOf + MaxEncodedLen,
		B: Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay +
			AtLeast32BitUnsigned + Default + Bounded + Copy + sp_std::hash::Hash +
			sp_std::str::FromStr + MaybeMallocSizeOf + MaxEncodedLen

{
	fn execute(
		input: &[u8],
		_target_gas: Option<u64>,
		_context: &Context,
	) -> core::result::Result<PrecompileOutput, ExitError> {
		let mut seed = [0u8; 32];
		seed.copy_from_slice(&input[0..32]);

		let withdraw_proof_res = WithdrawProof::decode(&mut input[32..].to_vec());
		let withdraw_proof = match withdraw_proof_res {
			Ok(wp) => wp,
			Err(_) => return Err(ExitError::Other("Failed to decode withdraw proof".into())),
		};
		let random_seed = R::random_seed();
		let random_bytes = random_seed.0.encode();
		let mut buf = [0u8; 32];
		for (buff_element, data) in buf.iter_mut().zip(random_bytes.iter()) {
			*buff_element = *data
		}
		println!("{:?}", buf);
		let mut rng = ChaChaRng::from_seed(buf);
		let verify_res = withdraw_proof.verify(&POSEIDON_HASHER, &mut rng);
		println!("{:?}", verify_res);
		if verify_res.is_err() {
			return Err(verify_res.err().unwrap());
		}

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			cost: 0,
			output: Vec::new(),
			logs: Vec::new(),
		})
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use sp_core::H256;
	use sp_core::H160;
	use crate::{
		encoding::Encode,
		types::{test::generate_proof_data, WithdrawProof},
	};
	use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
	use sp_core::uint::U256;

	struct Rng;
	impl Randomness<H256, u64> for Rng {
		fn random(_: &[u8]) -> (H256, u64) {
			(H256::from([1u8; 32]), 12)
		}
	}

	type TestPrecompile = BulletproofMerkleTreeMembershipPrecompile<H256, u64, Rng>;

	#[test]
	fn should_verify_with_precompile() {
		let seed = [1u8; 32];
		let mut test_rng = ChaChaRng::from_seed(seed);
		let (tree_depth, comms, leaf_index_comms, proof_comms, nullifier_hash, recipient, relayer, root, proof, _) =
			generate_proof_data(&mut test_rng);
		let withdraw_proof = WithdrawProof {
			depth: tree_depth,
			private_inputs: comms,
			index_private_inputs: leaf_index_comms,
			node_private_inputs: proof_comms,
			nullifier_hash,
			recipient,
			relayer,
			root,
			proof: proof.clone(),
		};

		let encoded_wp = withdraw_proof.encode();
		let mut buf = vec![];
		buf.extend_from_slice(&seed);
		buf.extend_from_slice(&encoded_wp);

		let context: Context = Context {
			address: Default::default(),
			caller: Default::default(),
			apparent_value: From::from(0),
		};
		println!("{:?}", buf);
		// Calling precompile
		match TestPrecompile::execute(&buf, None, &context) {
			Ok(_) => {},
			Err(_) => {
				panic!("BulletproofMerkleTreeMembershipPrecompile::execute() returned error");
			}
		}
	}

	#[test]
	fn should_verify_with_verify_directly() {
		let mut test_rng = ChaChaRng::from_seed([1u8; 32]);
		let (tree_depth, comms, leaf_index_comms, proof_comms, nullifier_hash, recipient, relayer, root, proof, _) =
			generate_proof_data(&mut test_rng);
		let withdraw_proof = WithdrawProof {
			depth: tree_depth,
			private_inputs: comms,
			index_private_inputs: leaf_index_comms,
			node_private_inputs: proof_comms,
			nullifier_hash,
			recipient,
			relayer,
			root,
			proof: proof.clone(),
		};

		let encoded_wp = withdraw_proof.encode();

		let mut encoded_copy = encoded_wp.clone();
		let decoded_wp = WithdrawProof::decode(&mut encoded_copy).unwrap();
		assert_eq!(decoded_wp.depth, tree_depth);
		assert_eq!(decoded_wp.proof.to_bytes(), proof.to_bytes());

		// Calling verify
		let mut test_rng = ChaChaRng::from_seed([2u8; 32]);
		let verify_res = withdraw_proof.verify(&POSEIDON_HASHER, &mut test_rng);
		assert!(verify_res.is_ok());
	}
}
