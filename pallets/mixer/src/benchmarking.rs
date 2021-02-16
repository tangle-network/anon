#![cfg(feature = "runtime-benchmarks")]
use super::*;
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use curve25519_gadgets::{
	fixed_deposit_tree::builder::FixedDepositTreeBuilder,
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		gen_mds_matrix, gen_round_keys, PoseidonSbox,
	},
};
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::RawOrigin;
use merkle::{default_hasher, utils::keys::Data};
use merlin::Transcript;

use crate::{Config, Module as Mixer};
use balances::Module as Balances;
use merkle::Module as Merkle;

const NUM_DEPOSITS: u32 = 10;
const NUM_WITHDRAWALS: u32 = 5;

benchmarks! {
	deposit {
		let d in 1 .. NUM_DEPOSITS;
		let caller = whitelisted_caller();

		Mixer::<T>::initialize().unwrap();
		let mixer_id: T::GroupId = 0.into();
		let balance: T::Balance = 10_000.into();
		let _ = <Balances<T> as Currency<_>>::make_free_balance_be(&caller, balance);

		let data_points = vec![Data::zero(); d as usize];
	}: _(RawOrigin::Signed(caller), mixer_id, data_points)
	verify {
		let mixer_info = Mixer::<T>::get_mixer(mixer_id).unwrap();
		assert_eq!(mixer_info.leaves.len(), d as usize);
	}

	withdraw {
		let caller = whitelisted_caller();
		Mixer::<T>::initialize().unwrap();

		let mixer_id: T::GroupId = 0.into();
		let balance: T::Balance = 10_000.into();
		let _ = <Balances<T> as Currency<_>>::make_free_balance_be(&caller, balance);

		let pc_gens = PedersenGens::default();
		let poseidon = default_hasher();

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);
		let mut ftree = FixedDepositTreeBuilder::new()
			.hash_params(poseidon.clone())
			.depth(32)
			.build();

		let leaf = ftree.generate_secrets();
		ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

		Mixer::<T>::deposit(RawOrigin::Signed(caller.clone()).into(), mixer_id, vec![Data(leaf)]);

		let root = Merkle::<T>::get_merkle_root(mixer_id).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) =
			ftree.prove_zk(root.0, leaf, &ftree.hash_params.bp_gens, prover);

		let comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

		let block_number: T::BlockNumber = 0.into();
	}: _(
		RawOrigin::Signed(caller.clone()),
		mixer_id,
		block_number,
		root,
		comms,
		Data(nullifier_hash),
		proof.to_bytes(),
		leaf_index_comms,
		proof_comms
	)
	verify {
		let balance_after: T::Balance = <Balances<T> as Currency<_>>::free_balance(&caller);
		assert_eq!(balance_after, balance);
	}
}

#[cfg(test)]
mod bench_tests {
	use super::*;
	use crate::mock::{new_test_ext, Test};
	use frame_support::assert_ok;

	#[test]
	fn test_deposit() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_deposit::<Test>());
		});
	}

	#[test]
	fn test_withdraw() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_withdraw::<Test>());
		});
	}
}
