use crate::mock::*;
use bulletproofs::{
	r1cs::{ConstraintSystem, LinearCombination, Prover},
	BulletproofGens, PedersenGens,
};
use curve25519_dalek::scalar::Scalar;
use merkle::{
	merkle::{
		hasher::Hasher,
		helper::{commit_leaf, commit_path_level, leaf_data},
		keys::{Commitment, Data},
		poseidon::Poseidon,
	},
	HighestCachedBlock,
};
use rand::rngs::ThreadRng;
use sp_runtime::DispatchError;

use frame_support::{assert_err, assert_ok, storage::StorageValue, traits::OnFinalize};
use merlin::Transcript;

fn default_hasher() -> impl Hasher {
	Poseidon::new(4)
	// Mimc::new(70)
}

fn create_deposit_info(mut test_rng: &mut ThreadRng) -> (Scalar, Scalar, Data, Data) {
	let h = default_hasher();
	let (s, nullifier, nullifier_hash, leaf) = leaf_data(&mut test_rng, &h);
	(s, nullifier, nullifier_hash, leaf)
}

#[test]
fn should_initialize_successfully() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize(Origin::signed(1)));
		// the mixer creates 4 groups, they should all initialise to 0
		let val = 1_000;
		for i in 0..4 {
			let g = MerkleGroups::get_group(i).unwrap();
			let m = Mixer::get_mixer(i).unwrap();
			assert_eq!(g.leaf_count, 0);
			assert_eq!(g.manager_required, true);
			assert_eq!(m.leaves.len(), 0);
			assert_eq!(m.fixed_deposit_size, val * 10_u64.pow(i))
		}
	})
}

#[test]
fn should_fail_to_deposit_with_insufficient_balance() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize(Origin::signed(1)));
		let mut test_rng = rand::thread_rng();
		let mut deposits = vec![];
		for i in 0..4 {
			let dep = create_deposit_info(&mut test_rng);
			deposits.push(dep);
			// ensure depositing works
			let (_, _, _, leaf) = dep;
			assert_err!(
				Mixer::deposit(Origin::signed(4), i, vec![leaf]),
				DispatchError::Module {
					index: 0,
					error: 4,
					message: Some("InsufficientBalance")
				}
			);
		}
	})
}

#[test]
fn should_deposit_into_each_mixer_successfully() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize(Origin::signed(1)));
		let mut deposits = vec![];
		let mut test_rng = rand::thread_rng();
		for i in 0..4 {
			let dep = create_deposit_info(&mut test_rng);
			deposits.push(dep);
			// ensure depositing works
			let (_, _, _, leaf) = dep;
			let balance_before = Balances::free_balance(1);
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf]));
			let balance_after = Balances::free_balance(1);

			// ensure state updates
			let g = MerkleGroups::get_group(i).unwrap();
			let m = Mixer::get_mixer(i).unwrap();
			assert_eq!(balance_before, balance_after + m.fixed_deposit_size);
			assert_eq!(g.leaf_count, 1);
			assert_eq!(m.leaves.len(), 1);
		}
	})
}

#[test]
fn should_withdraw_from_each_mixer_successfully() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize(Origin::signed(1)));
		let mut test_rng = rand::thread_rng();
		let h = default_hasher();
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(4096, 1);

		let mut deposits = vec![];
		for i in 0..4 {
			let dep = create_deposit_info(&mut test_rng);
			deposits.push(dep);
			// ensure depositing works
			let (s, nullifier, nullifier_hash, leaf) = dep;
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf]));

			let root = MerkleGroups::get_merkle_root(i);
			let mut prover_transcript = Transcript::new(b"zk_membership_proof");
			let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

			let (s_com, nullifier_com, leaf_com1, leaf_var1) = commit_leaf(
				&mut test_rng,
				&mut prover,
				leaf,
				s,
				nullifier,
				nullifier_hash,
				&h,
			);

			let mut lh = leaf;
			let mut lh_lc: LinearCombination = leaf_var1.into();
			let mut path = Vec::new();
			for _ in 0..32 {
				let (bit_com, leaf_com, node_con) =
					commit_path_level(&mut test_rng, &mut prover, lh, lh_lc, 1, &h);
				lh_lc = node_con;
				lh = Data::hash(lh, lh, &h);
				path.push((Commitment(bit_com), Commitment(leaf_com)));
			}
			prover.constrain(lh_lc - lh.0);

			let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

			let m = Mixer::get_mixer(i).unwrap();
			let balance_before = Balances::free_balance(2);
			// withdraw from another account
			assert_ok!(Mixer::withdraw(
				Origin::signed(2),
				i,
				0,
				root.unwrap(),
				Commitment(leaf_com1),
				path,
				Commitment(s_com),
				Commitment(nullifier_com),
				nullifier_hash,
				proof.to_bytes(),
			));
			let balance_after = Balances::free_balance(2);
			assert_eq!(balance_before + m.fixed_deposit_size, balance_after);
		}
	})
}

#[test]
fn should_cache_roots_if_no_new_deposits_show() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(Mixer::initialize(Origin::signed(1)));
		let mut deposits = vec![];
		let mut test_rng = rand::thread_rng();
		let mut merkle_roots: Vec<Data> = vec![];
		for i in 0..4 {
			let dep = create_deposit_info(&mut test_rng);
			deposits.push(dep);
			// ensure depositing works
			let (_, _, _, leaf) = dep;
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf]));
			let root = MerkleGroups::get_merkle_root(i).unwrap();
			merkle_roots.push(root);
			let cache = MerkleGroups::cached_roots(1, i);
			assert_eq!(cache.len(), 1);
		}

		System::set_block_number(2);
		<Mixer as OnFinalize<u64>>::on_finalize(2);
		for i in 0..4 {
			let cache_prev = MerkleGroups::cached_roots(1, i);
			let cache = MerkleGroups::cached_roots(2, i);
			assert_eq!(cache, cache_prev);
		}

		System::set_block_number(3);
		<Mixer as OnFinalize<u64>>::on_finalize(3);
		for i in 0..4 {
			let cache_prev = MerkleGroups::cached_roots(2, i);
			let cache = MerkleGroups::cached_roots(3, i);
			assert_eq!(cache, cache_prev);
		}
	})
}

#[test]
fn should_not_have_cache_once_cache_length_exceeded() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(Mixer::initialize(Origin::signed(1)));
		let mut deposits = vec![];
		let mut test_rng = rand::thread_rng();
		let mut merkle_roots: Vec<Data> = vec![];
		for i in 0..4 {
			let dep = create_deposit_info(&mut test_rng);
			deposits.push(dep);
			// ensure depositing works
			let (_, _, _, leaf) = dep;
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf]));
			let root = MerkleGroups::get_merkle_root(i).unwrap();
			merkle_roots.push(root);
			let cache = MerkleGroups::cached_roots(1, i);
			assert_eq!(cache.len(), 1);
		}

		<Mixer as OnFinalize<u64>>::on_finalize(1);
		<MerkleGroups as OnFinalize<u64>>::on_finalize(1);
		// iterate over next 5 blocks
		for i in 1..6 {
			System::set_block_number(i + 1);
			<Mixer as OnFinalize<u64>>::on_finalize(i + 1);
			<MerkleGroups as OnFinalize<u64>>::on_finalize(i + 1);
			// iterate over each mixer in each block
			for j in 0u32..4u32 {
				if i + 1 == 6 {
					let old_root = MerkleGroups::cached_roots(1, j);
					assert_eq!(old_root, vec![]);
				}

				// get cached root at block i + 1
				let root = MerkleGroups::cached_roots(i + 1, j);
				// check cached root is same as first updated root
				assert_eq!(root, vec![merkle_roots[j as usize]]);
				// check that highest cache block is i + 1
				assert_eq!(i + 1, HighestCachedBlock::<Test>::get());
			}
		}
	})
}
