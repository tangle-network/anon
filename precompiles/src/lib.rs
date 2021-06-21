use bulletproofs::BulletproofGens;
use bulletproofs_gadgets::poseidon::{
	builder::{Poseidon, PoseidonBuilder},
	PoseidonSbox,
};
use evm::executor::PrecompileOutput;
use evm_runtime::{Context, ExitError, ExitSucceed};
use frame_support::traits::Randomness;
use lazy_static::lazy_static;
use pallet_evm::PrecompileSet;
use sp_core::{hash::H160, Encode};
use sp_std::{fmt::Debug, marker::PhantomData};
mod encoding;
use encoding::Decode;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
mod withdraw_proof;
use sp_std::prelude::Vec;
use withdraw_proof::WithdrawProof;

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

#[derive(Debug, Clone, Copy)]
pub struct BulletproofsPrecompiles<R>(PhantomData<R>);

impl<R: Randomness<u64, u64>> PrecompileSet for BulletproofsPrecompiles<R> {
	fn execute(
		_address: H160,
		input: &[u8],
		_target_gas: Option<u64>,
		_context: &Context,
	) -> Option<Result<PrecompileOutput, ExitError>> {
		let mut inp = input.to_vec();
		let withdraw_proof_res = WithdrawProof::decode(&mut inp);
		let withdraw_proof = match withdraw_proof_res {
			Ok(wp) => wp,
			Err(_) => return Some(Err(ExitError::Other("Failed to decode withdraw proof".into()))),
		};
		let random_seed = R::random_seed();
		let random_bytes = random_seed.0.encode();
		let mut buf = [0u8; 32];
		for (buff_element, data) in buf.iter_mut().zip(random_bytes.iter()) {
			*buff_element = *data
		}
		let mut rng = ChaChaRng::from_seed(buf);
		let verify_res = withdraw_proof.verify(&POSEIDON_HASHER, &mut rng);
		if verify_res.is_err() {
			return Some(Err(verify_res.err().unwrap()));
		}
		Some(Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			cost: 0,
			output: Vec::new(),
			logs: Vec::new(),
		}))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		encoding::Encode,
		withdraw_proof::{test::generate_proof_data, WithdrawProof},
	};
	use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
	use sp_core::uint::U256;

	struct Rng;

	impl Randomness<u64, u64> for Rng {
		fn random(_: &[u8]) -> (u64, u64) {
			(1, 12)
		}
	}

	type TestPrecompile = BulletproofsPrecompiles<Rng>;

	#[test]
	fn should_verify_with_precompile() {
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

		// let mut encoded_copy = encoded_wp.clone();
		// let decoded_wp = WithdrawProof::decode(&mut encoded_copy).unwrap();
		// assert_eq!(decoded_wp.depth, tree_depth);
		// assert_eq!(decoded_wp.proof.to_bytes(), proof.to_bytes());

		// let verify_res = withdraw_proof.verify(&POSEIDON_HASHER, &mut
		// test_rng); assert!(verify_res.is_ok());

		let address = H160::from_low_u64_be(2);
		let ap_val = U256::from(0);

		let context = Context {
			address: address.clone(),
			caller: address.clone(),
			apparent_value: ap_val,
		};

		let res = TestPrecompile::execute(address, &encoded_wp, None, &context);

		assert!(res.is_some());
		let res = res.unwrap();
		assert!(res.is_ok());
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

		let verify_res = withdraw_proof.verify(&POSEIDON_HASHER, &mut test_rng);
		assert!(verify_res.is_ok());
	}
}
