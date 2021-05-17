use super::*;
use crate::mock::{
	new_test_ext, AccountId, Balance, Balances, CurrencyId, MerkleTrees, Mixer, MixerCall, Origin, System, Test, Tokens,
};
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use bulletproofs_gadgets::{
	fixed_deposit_tree::builder::FixedDepositTreeBuilder,
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		PoseidonSbox,
	},
};
use curve25519_dalek::scalar::Scalar;
use frame_support::{
	assert_err, assert_ok,
	traits::{OnFinalize, UnfilteredDispatchable},
};
use frame_system::RawOrigin;
use merkle::{
	utils::keys::{slice_to_bytes_32, ScalarBytes},
	HighestCachedBlock,
};
use merlin::Transcript;
use sp_runtime::{traits::BadOrigin, DispatchError};
use webb_tokens::ExtendedTokenSystem;

fn default_hasher(num_gens: usize) -> Poseidon {
	let width = 6;
	PoseidonBuilder::new(width)
		.bulletproof_gens(BulletproofGens::new(num_gens, 1))
		.sbox(PoseidonSbox::Exponentiation3)
		.build()
}

#[test]
fn should_initialize_successfully() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize());
		// the mixer creates 4 groups, they should all initialise to 0
		let val = 1_000;
		for i in 0..4 {
			let g = MerkleTrees::get_tree(i).unwrap();
			let mng = MerkleTrees::get_manager(i).unwrap();
			let m = Mixer::get_mixer(i).unwrap();
			assert_eq!(g.leaf_count, 0);
			assert_eq!(mng.required, true);
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
			let g = MerkleTrees::get_tree(i).unwrap();
			let mng = MerkleTrees::get_manager(i).unwrap();
			let m = Mixer::get_mixer(i).unwrap();
			assert_eq!(g.leaf_count, 0);
			assert_eq!(mng.required, true);
			assert_eq!(m.fixed_deposit_size, val * 10_u64.pow(i))
		}
	})
}

#[test]
fn should_be_able_to_change_admin_with_root() {
	new_test_ext().execute_with(|| {
		let call = Box::new(MixerCall::transfer_admin(2));
		let res = call.dispatch_bypass_filter(RawOrigin::Root.into());
		assert_ok!(res);
		let admin = Mixer::admin();
		assert_eq!(admin, 2);

		let call = Box::new(MixerCall::transfer_admin(3));
		let res = call.dispatch_bypass_filter(RawOrigin::Signed(0).into());
		assert_err!(res, BadOrigin);
	})
}

#[test]
fn should_be_able_to_stop_mixers_with_root() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize());
		let call = Box::new(MixerCall::set_stopped(true));
		let res = call.dispatch_bypass_filter(RawOrigin::Root.into());
		assert_ok!(res);

		for i in 0..4 {
			let stopped = MerkleTrees::stopped(i);
			assert!(stopped);
		}
	})
}

#[test]
fn should_be_able_to_change_admin() {
	new_test_ext().execute_with(|| {
		let default_admin = 4;
		assert_ok!(Mixer::initialize());
		assert_err!(Mixer::transfer_admin(Origin::signed(1), 2), BadOrigin);
		assert_ok!(Mixer::transfer_admin(Origin::signed(default_admin), 2));
		let admin = Mixer::admin();

		assert_eq!(admin, 2);
	})
}

#[test]
fn should_stop_and_start_mixer() {
	new_test_ext().execute_with(|| {
		let default_admin = 4;
		assert_ok!(Mixer::initialize());
		let mut tree = FixedDepositTreeBuilder::new().build();
		let leaf = tree.generate_secrets().to_bytes().to_vec();
		assert_ok!(Mixer::deposit(Origin::signed(0), 0, vec![leaf.clone()]));

		// Stopping deposits and withdrawal
		assert_ok!(Mixer::set_stopped(Origin::signed(default_admin), true));
		assert_err!(
			Mixer::deposit(Origin::signed(0), 0, vec![]),
			Error::<Test>::MixerStopped
		);
		assert_err!(
			Mixer::withdraw(
				Origin::signed(0),
				WithdrawProof::new(
					0,
					0,
					Scalar::zero().to_bytes().to_vec(),
					Vec::new(),
					Scalar::zero().to_bytes().to_vec(),
					Vec::new(),
					Vec::new(),
					Vec::new(),
					None,
					None,
				)
			),
			Error::<Test>::MixerStopped
		);

		// Starting mixer
		assert_ok!(Mixer::set_stopped(Origin::signed(default_admin), false));
		assert_ok!(Mixer::deposit(Origin::signed(0), 0, vec![leaf]));
	})
}

#[test]
fn should_fail_to_deposit_with_insufficient_balance() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize());
		let mut tree = FixedDepositTreeBuilder::new().build();
		for i in 0..4 {
			let leaf = tree.generate_secrets().to_bytes().to_vec();
			assert_err!(
				Mixer::deposit(Origin::signed(4), i, vec![leaf]),
				DispatchError::Module {
					index: 3,
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
			let leaf = tree.generate_secrets().to_bytes().to_vec();
			let balance_before = Balances::free_balance(1);
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf]));
			let balance_after = Balances::free_balance(1);

			// ensure state updates
			let g = MerkleTrees::get_tree(i).unwrap();
			let m = Mixer::get_mixer(i).unwrap();
			let tvl = Mixer::total_value_locked(i);
			assert_eq!(tvl, m.fixed_deposit_size);
			assert_eq!(balance_before, balance_after + m.fixed_deposit_size);
			assert_eq!(g.leaf_count, 1);
		}
	})
}

#[test]
fn should_withdraw_from_each_mixer_successfully() {
	new_test_ext().execute_with(|| {
		assert_ok!(Mixer::initialize());
		let pc_gens = PedersenGens::default();
		let poseidon = default_hasher(16400);

		for i in 0..4 {
			let mut prover_transcript = Transcript::new(b"zk_membership_proof");
			let prover = Prover::new(&pc_gens, &mut prover_transcript);
			let mut ftree = FixedDepositTreeBuilder::new()
				.hash_params(poseidon.clone())
				.depth(32)
				.build();

			let leaf = ftree.generate_secrets().to_bytes();
			ftree.tree.add_leaves(vec![leaf], None);

			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf.to_vec()]));

			let root = MerkleTrees::get_merkle_root(i).unwrap();
			let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
				Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
				Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
				Scalar::from(2u32),
				Scalar::zero(),
				&ftree.hash_params.bp_gens,
				prover,
			);

			let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
			let leaf_index_comms: Vec<ScalarBytes> =
				leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
			let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();

			let m = Mixer::get_mixer(i).unwrap();
			let balance_before = Balances::free_balance(2);
			// check TVL after depositing
			let tvl = Mixer::total_value_locked(i);
			assert_eq!(tvl, m.fixed_deposit_size);
			// withdraw from another account
			assert_ok!(Mixer::withdraw(
				Origin::signed(2),
				WithdrawProof::new(
					i,
					0,
					root,
					comms,
					nullifier_hash.to_bytes().to_vec(),
					proof.to_bytes(),
					leaf_index_comms,
					proof_comms,
					Some(2),
					Some(0),
				)
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
		let mut merkle_roots: Vec<ScalarBytes> = vec![];
		for i in 0..4 {
			let leaf = tree.generate_secrets().to_bytes().to_vec();
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf]));
			let root = MerkleTrees::get_merkle_root(i).unwrap();
			merkle_roots.push(root);
			let cache = MerkleTrees::cached_roots(1, i);
			assert_eq!(cache.len(), 1);
		}

		System::set_block_number(2);
		<Mixer as OnFinalize<u64>>::on_finalize(2);
		for i in 0..4 {
			let cache_prev = MerkleTrees::cached_roots(1, i);
			let cache = MerkleTrees::cached_roots(2, i);
			assert_eq!(cache, cache_prev);
		}

		System::set_block_number(3);
		<Mixer as OnFinalize<u64>>::on_finalize(3);
		for i in 0..4 {
			let cache_prev = MerkleTrees::cached_roots(2, i);
			let cache = MerkleTrees::cached_roots(3, i);
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
		let mut merkle_roots: Vec<ScalarBytes> = vec![];
		for i in 0..4 {
			let leaf = tree.generate_secrets().to_bytes().to_vec();
			assert_ok!(Mixer::deposit(Origin::signed(1), i, vec![leaf]));
			let root = MerkleTrees::get_merkle_root(i).unwrap();
			merkle_roots.push(root);
			let cache = MerkleTrees::cached_roots(1, i);
			assert_eq!(cache.len(), 1);
		}

		<Mixer as OnFinalize<u64>>::on_finalize(1);
		<MerkleTrees as OnFinalize<u64>>::on_finalize(1);
		// iterate over next 5 blocks
		for i in 1..6 {
			System::set_block_number(i + 1);
			<Mixer as OnFinalize<u64>>::on_finalize(i + 1);
			<MerkleTrees as OnFinalize<u64>>::on_finalize(i + 1);
			// iterate over each mixer in each block
			for j in 0u32..4u32 {
				if i + 1 == 6 {
					let old_root = MerkleTrees::cached_roots(1, j);
					assert_eq!(old_root, Vec::<ScalarBytes>::new());
				}

				// get cached root at block i + 1
				let root = MerkleTrees::cached_roots(i + 1, j);
				// check cached root is same as first updated root
				assert_eq!(root, vec![merkle_roots[j as usize].clone()]);
				// check that highest cache block is i + 1
				assert_eq!(i + 1, HighestCachedBlock::<Test>::get());
			}
		}
	})
}

#[test]
fn should_make_mixer_with_non_native_token() {
	new_test_ext().execute_with(|| {
		let currency_id = 1;
		assert_ok!(<Tokens as ExtendedTokenSystem<AccountId, CurrencyId, Balance>>::create(
			currency_id,
			1, // owner
			1, // admin
			1  // min_balance
		));

		assert_ok!(<Tokens as ExtendedTokenSystem<AccountId, CurrencyId, Balance>>::mint(
			1, 0, 10000000
		));
		assert_ok!(Mixer::initialize());
		assert_ok!(<Mixer as ExtendedMixer<AccountId, CurrencyId, Balance>>::create_new(
			1,
			currency_id,
			HashFunction::PoseidonDefault,
			Backend::Bulletproofs,
			1_000
		));

		let pc_gens = PedersenGens::default();
		let poseidon = default_hasher(16400);

		let tree_id = 4u32;
		let sender: AccountId = 0;
		let recipient: AccountId = 1;
		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);
		let mut ftree = FixedDepositTreeBuilder::new()
			.hash_params(poseidon.clone())
			.depth(32)
			.build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		// Getting native balance before deposit
		let native_balance_before = Balances::free_balance(&sender);
		assert_ok!(Mixer::deposit(Origin::signed(sender), tree_id, vec![leaf.to_vec()]));
		// Native balance after deposit, to make sure its not touched
		let native_balance_after = Balances::free_balance(&sender);
		assert_eq!(native_balance_before, native_balance_after);

		let root = MerkleTrees::get_merkle_root(tree_id).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::from(recipient),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();

		let m = Mixer::get_mixer(tree_id).unwrap();
		let balance_before = Tokens::free_balance(currency_id, &recipient);
		let native_balance_before = Balances::free_balance(&sender);
		// check TVL after depositing
		let tvl = Mixer::total_value_locked(tree_id);
		assert_eq!(tvl, m.fixed_deposit_size);
		// withdraw from another account
		assert_ok!(Mixer::withdraw(
			Origin::signed(recipient),
			WithdrawProof::new(
				tree_id,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				Some(recipient),
				Some(0),
			)
		));
		let balance_after = Tokens::free_balance(currency_id, &recipient);
		assert_eq!(balance_before + m.fixed_deposit_size, balance_after);
		// Native balance after withdraw, to make sure its not changed
		let native_balance_after = Balances::free_balance(&sender);
		assert_eq!(native_balance_before, native_balance_after);
		// ensure TVL is 0 after withdrawing
		let tvl = Mixer::total_value_locked(tree_id);
		assert_eq!(tvl, 0);
	});
}
