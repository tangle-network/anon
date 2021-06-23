use super::*;
use bulletproofs::{r1cs::Prover, PedersenGens};
use bulletproofs_gadgets::fixed_deposit_tree::builder::FixedDepositTreeBuilder;
use curve25519_dalek::scalar::Scalar;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_support::traits::OnFinalize;
use frame_system::RawOrigin;
use merkle::utils::{
	keys::{from_bytes_to_bp_gens, slice_to_bytes_32, ScalarBytes},
	setup::default_bulletproofs_poseidon_hasher,
};
use merlin::Transcript;
use webb_traits::MultiCurrency;

use crate::{Config, Pallet as Mixer};
use merkle::{Config as MerkleConfig, Pallet as Merkle};

const NUM_DEPOSITS: u32 = 10;
const NUM_WITHDRAWALS: u32 = 5;

benchmarks! {
	deposit {
		// Benchmarking from 1 to `NUM_DEPOSITS`
		let d in 1 .. NUM_DEPOSITS;
		let caller = whitelisted_caller();

		Mixer::<T>::initialize_first_stage().unwrap();
		Mixer::<T>::initialize_second_stage().unwrap();
		let mixer_id: T::TreeId = 0u32.into();
		let currency_id: CurrencyIdOf<T> = T::NativeCurrencyId::get();

		// Making `d` leaves/data points
		let data_points = vec![Scalar::zero().to_bytes().to_vec(); d as usize];
	}: _(RawOrigin::Signed(caller), mixer_id, data_points)
	verify {
		// Checking if deposit is sucessfull by checking number of leaves
		// let mixer_info = Mixer::<T>::get_mixer(mixer_id).unwrap();
		// assert_eq!(mixer_info.leaves.len(), d as usize);
	}

	// withdraw {
	// 	let caller: T::AccountId = whitelisted_caller();
	// 	Mixer::<T>::initialize_first_stage().unwrap();
	// 	Mixer::<T>::initialize_second_stage().unwrap();

	// 	let mixer_id: T::TreeId = 0u32.into();
	// 	let balance: BalanceOf<T> = 1_000_000_000u32.into();

	// 	let pc_gens = PedersenGens::default();
	// 	let params = Merkle::<T>::get_verifying_key(0u32.into()).unwrap();
	// 	let poseidon = default_bulletproofs_poseidon_hasher(from_bytes_to_bp_gens(&params));

	// 	let mut prover_transcript = Transcript::new(b"zk_membership_proof");
	// 	let prover = Prover::new(&pc_gens, &mut prover_transcript);
	// 	let mut ftree = FixedDepositTreeBuilder::new()
	// 		.hash_params(poseidon.clone())
	// 		.depth(<T as MerkleConfig>::MaxTreeDepth::get().into())
	// 		.build();

	// 	let leaf = ftree.generate_secrets().to_bytes();
	// 	ftree.tree.add_leaves(vec![leaf], None);

	// 	Mixer::<T>::deposit(RawOrigin::Signed(caller.clone()).into(), mixer_id, vec![leaf.to_vec()]).unwrap();

	// 	let root = Merkle::<T>::get_merkle_root(mixer_id).unwrap();
	// 	let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
	// 		Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
	// 		Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
	// 		Scalar::from_bytes_mod_order(slice_to_bytes_32(&caller.encode())),
	// 		Scalar::from_bytes_mod_order(slice_to_bytes_32(&caller.encode())),
	// 		&ftree.hash_params.bp_gens, prover
	// 	);

	// 	let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
	// 	let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
	// 	let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();

	// 	let block_number: T::BlockNumber = 0u32.into();

	// 	let withdraw_proof = WithdrawProof::<T>::new(
	// 		mixer_id,
	// 		block_number,
	// 		root,
	// 		comms,
	// 		nullifier_hash.to_bytes().to_vec(),
	// 		proof.to_bytes(),
	// 		leaf_index_comms,
	// 		proof_comms,
	// 		None,
	// 		None
	// 	);
	// }: _(
	// 	RawOrigin::Signed(caller.clone()),
	// 	withdraw_proof
	// )
	// verify {
	// 	let currency_id: CurrencyIdOf<T> = T::NativeCurrencyId::get();
	// 	let balance_after: BalanceOf<T> = T::Currency::free_balance(currency_id, &caller);
	// 	assert_eq!(balance_after, balance);
	// }

	set_stopped {
		Mixer::<T>::initialize_first_stage().unwrap();
		Mixer::<T>::initialize_second_stage().unwrap();
	}:
	// Calling the function with the root origin
	_(RawOrigin::Root, true)
	verify {
		let mixer_ids = MixerTreeIds::<T>::get();
		for i in 0..mixer_ids.len() {
			let group_id: T::TreeId = (i as u32).into();
			let stopped = Merkle::<T>::stopped(group_id);
			assert!(stopped);
		}
	}

	transfer_admin {
		Mixer::<T>::initialize_first_stage().unwrap();
		Mixer::<T>::initialize_second_stage().unwrap();
		// This account will be a new admin
		let new_admin: T::AccountId = account("new_admin", 0, 0);
	}:
	// Calling the function with the root origin
	_(RawOrigin::Root, new_admin.clone())
	verify {
		let admin: T::AccountId = Mixer::<T>::admin();
		assert_eq!(admin, new_admin);
	}

	on_finalize_uninitialized {
		let first_block: T::BlockNumber = 0u32.into();
		let second_block: T::BlockNumber = 1u32.into();
	}: {
		Mixer::<T>::on_finalize(first_block);
		Mixer::<T>::on_finalize(second_block);
	}
	verify {
		let first_stage_initialized = Mixer::<T>::first_stage_initialized();
		let second_stage_initialized = Mixer::<T>::second_stage_initialized();
		assert!(first_stage_initialized);
		assert!(second_stage_initialized);
	}

	on_finalize_initialized {
		// We first initialize to reach the first branch of if statement inside `on_finalize`
		let first_block: T::BlockNumber = 0u32.into();
		Mixer::<T>::on_finalize(first_block);
		let second_block: T::BlockNumber = 1u32.into();
	}: {
		Mixer::<T>::on_finalize(second_block);
	}
	verify {
		let first_group: T::TreeId = 0u32.into();
		let data = Merkle::<T>::get_cache(first_group, second_block);
		assert_eq!(data.len(), 1);
	}
}

// TODO: replace with impl_benchmark_test_suite macro:
// https://github.com/paritytech/substrate/blob/master/frame/lottery/src/benchmarking.rs#L173-L177
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

	#[test]
	fn test_set_stopped() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_set_stopped::<Test>());
		});
	}

	#[test]
	fn test_transfer_admin() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_transfer_admin::<Test>());
		});
	}

	#[test]
	fn test_on_finalize_uninitialized() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_on_finalize_uninitialized::<Test>());
		});
	}

	#[test]
	fn test_on_finalize_initialized() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_on_finalize_initialized::<Test>());
		});
	}
}
