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
use pallet_merkle::Config;
use sp_core::{Encode, H160};
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

impl<R: Config> PrecompileSet for BulletproofsPrecompiles<R> {
	fn execute(
		_address: H160,
		input: &[u8],
		_target_gas: Option<u64>,
		_context: &Context,
	) -> Option<Result<PrecompileOutput, ExitError>> {
		let withdraw_proof_res = WithdrawProof::decode(&mut input.to_vec());
		let withdraw_proof = match withdraw_proof_res {
			Ok(wp) => wp,
			Err(_) => return Some(Err(ExitError::Other("Failed to decode withdraw proof".into()))),
		};
		let random_seed = R::Randomness::random_seed();
		let random_bytes = random_seed.clone().0.encode();
		let mut buf = [0u8; 32];
		buf.copy_from_slice(&random_bytes);
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
