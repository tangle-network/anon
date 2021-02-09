use crate::mock::*;
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};

use curve25519_gadgets::{
	fixed_deposit_tree::builder::FixedDepositTreeBuilder,
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		gen_mds_matrix, gen_round_keys, PoseidonSbox,
	},
};
use frame_support::{assert_err, assert_ok, storage::StorageValue, traits::OnFinalize};
use merkle::{
	merkle::keys::{Commitment, Data},
	HighestCachedBlock,
};
use merlin::Transcript;
use sp_runtime::DispatchError;

fn default_hasher(num_gens: usize) -> Poseidon {
	let width = 6;
	let (full_b, full_e) = (4, 4);
	let partial_rounds = 57;
	PoseidonBuilder::new(width)
		.num_rounds(full_b, full_e, partial_rounds)
		.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
		.mds_matrix(gen_mds_matrix(width))
		.bulletproof_gens(BulletproofGens::new(num_gens, 1))
		.sbox(PoseidonSbox::Inverse)
		.build()
}

#[test]
fn should_initialize_successfully() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize());
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
fn should_initialize_successfully_on_finalize() {
	new_test_ext().execute_with(|| {
		<Mixer as OnFinalize<u64>>::on_finalize(1);
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
		assert_ok!(Mixer::initialize());
		let mut tree = FixedDepositTreeBuilder::new().build();
		for i in 0..4 {
			let leaf = tree.generate_secrets();
			assert_err!(
				Mixer::deposit(Origin::signed(4), i, vec![Data(leaf)]),
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
		assert_ok!(Mixer::initialize());
		let mut tree = FixedDepositTreeBuilder::new().build();
		for i in 0..4 {
			let leaf = tree.generate_secrets();
			let balance_before = Balances::free_balance(1);
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![Data(leaf)]));
			let balance_after = Balances::free_balance(1);

			// ensure state updates
			let g = MerkleGroups::get_group(i).unwrap();
			let m = Mixer::get_mixer(i).unwrap();
			let tvl = Mixer::total_value_locked(i);
			assert_eq!(tvl, m.fixed_deposit_size);
			assert_eq!(balance_before, balance_after + m.fixed_deposit_size);
			assert_eq!(g.leaf_count, 1);
			assert_eq!(m.leaves.len(), 1);
		}
	})
}

#[test]
fn should_withdraw_from_each_mixer_successfully() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize());
		let pc_gens = PedersenGens::default();
		let poseidon = default_hasher(40960);

		for i in 0..4 {
			let mut prover_transcript = Transcript::new(b"zk_membership_proof");
			let prover = Prover::new(&pc_gens, &mut prover_transcript);
			let mut ftree = FixedDepositTreeBuilder::new()
				.hash_params(poseidon.clone())
				.depth(32)
				.build();

			let leaf = ftree.generate_secrets();
			ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![Data(leaf)]));

			let root = MerkleGroups::get_merkle_root(i).unwrap();
			let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) =
				ftree.prove_zk(root.0, leaf, &ftree.hash_params.bp_gens, prover);

			let comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
			let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
			let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

			let m = Mixer::get_mixer(i).unwrap();
			let balance_before = Balances::free_balance(2);
			// check TVL after depositing
			let tvl = Mixer::total_value_locked(i);
			assert_eq!(tvl, m.fixed_deposit_size);
			// withdraw from another account
			assert_ok!(Mixer::withdraw(
				Origin::signed(2),
				i,
				0,
				root,
				comms,
				Data(nullifier_hash),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms
			));
			let balance_after = Balances::free_balance(2);
			assert_eq!(balance_before + m.fixed_deposit_size, balance_after);
			// ensure TVL is 0 after withdrawing
			let tvl = Mixer::total_value_locked(i);
			assert_eq!(tvl, 0);
		}
	})
}

#[test]
fn should_cache_roots_if_no_new_deposits_show() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(Mixer::initialize());
		let mut tree = FixedDepositTreeBuilder::new().build();
		let mut merkle_roots: Vec<Data> = vec![];
		for i in 0..4 {
			let leaf = tree.generate_secrets();
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![Data(leaf)]));
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
		assert_ok!(Mixer::initialize());
		let mut tree = FixedDepositTreeBuilder::new().build();
		let mut merkle_roots: Vec<Data> = vec![];
		for i in 0..4 {
			let leaf = tree.generate_secrets();
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![Data(leaf)]));
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
