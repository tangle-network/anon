use super::*;
use crate::{
	mock::*,
	utils::{
		keys::{from_bytes_to_bp_gens, get_bp_gen_bytes, slice_to_bytes_32},
		setup::{Backend, HashFunction, Setup, Snark},
	},
};
use ark_serialize::CanonicalSerialize;
use arkworks_gadgets::{
	prelude::{ark_bls12_381::Fr as Bls381, ark_ff::to_bytes},
	setup::mixer::{prove_groth16, setup_circuit, setup_random_groth16},
};
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use bulletproofs_gadgets::{
	fixed_deposit_tree::builder::FixedDepositTreeBuilder,
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		PoseidonSbox,
	},
	smt::gen_zero_tree,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use frame_support::{assert_err, assert_ok, traits::UnfilteredDispatchable};
use frame_system::RawOrigin;
use merlin::Transcript;
use rand_core::OsRng;
use sp_runtime::traits::BadOrigin;

fn key_bytes(x: u8) -> [u8; 32] {
	[
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x,
	]
}

fn default_hasher(bp_gens: BulletproofGens) -> Poseidon {
	PoseidonBuilder::new(6)
		.bulletproof_gens(bp_gens)
		.sbox(PoseidonSbox::Exponentiation3)
		.build()
}

#[test]
fn can_create_tree() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(3),
			true,
		));
	});
}

#[test]
fn can_update_manager_when_required() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			setup.clone(),
			Some(3),
			true,
		));

		assert_ok!(MerkleTrees::set_manager(Origin::signed(1), 0, 2,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);
	});
}

#[test]
fn can_update_manager_when_not_required() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(3),
			true,
		));

		assert_ok!(MerkleTrees::set_manager(Origin::signed(1), 0, 2,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);
	});
}

#[test]
fn cannot_update_manager_as_not_manager() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(3),
			true,
		));

		assert_err!(MerkleTrees::set_manager(Origin::signed(2), 0, 2,), BadOrigin);
	});
}

#[test]
fn can_update_manager_required_manager() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(3),
			true,
		));

		assert_ok!(MerkleTrees::set_manager_required(Origin::signed(1), 0, true,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.required, true);
	});
}

#[test]
fn cannot_update_manager_required_as_not_manager() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(3),
			true,
		));

		assert_err!(
			MerkleTrees::set_manager_required(Origin::signed(2), 0, true,),
			Error::<Test>::ManagerIsRequired
		);
	});
}

#[test]
fn can_add_member() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(3),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(4096, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
	});
}

#[test]
fn can_add_member_as_manager() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			setup.clone(),
			Some(3),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(4096, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
	});
}

#[test]
fn cannot_add_member_as_not_manager() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			setup.clone(),
			Some(3),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(4096, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_err!(
			MerkleTrees::add_members(Origin::signed(2), 0, vec![key.clone()]),
			Error::<Test>::ManagerIsRequired
		);
	});
}

#[test]
fn should_be_able_to_set_stopped_merkle() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			setup.clone(),
			Some(1),
			true,
		));
		assert_ok!(MerkleTrees::set_stopped(Origin::signed(1), 0, true));

		// stopping merkle, stopped == true
		let stopped = MerkleTrees::stopped(0);
		assert!(stopped);

		assert_ok!(MerkleTrees::set_stopped(Origin::signed(1), 0, false));

		// starting merkle again, stopped == false
		let stopped = MerkleTrees::stopped(0);
		assert!(!stopped);
	});
}

#[test]
fn should_be_able_to_change_manager_with_root() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			setup.clone(),
			Some(3),
			true,
		));
		let call = Box::new(MerkleCall::set_manager(0, 2));
		let res = call.dispatch_bypass_filter(RawOrigin::Root.into());
		assert_ok!(res);
		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);

		let call = Box::new(MerkleCall::set_manager(0, 3));
		let res = call.dispatch_bypass_filter(RawOrigin::Signed(0).into());
		assert_err!(res, BadOrigin);
	})
}

#[test]
fn should_not_have_0_depth() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_err!(
			MerkleTrees::create_tree(Origin::signed(1), false, setup.clone(), Some(0), true),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_min_depth() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(1),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(4096, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
		assert_err!(
			MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]),
			Error::<Test>::ExceedsMaxLeaves,
		);
	});
}

#[test]
fn should_have_max_depth() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(32),
			true,
		));
	});
}

#[test]
fn should_not_have_more_than_max_depth() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_err!(
			MerkleTrees::create_tree(Origin::signed(1), false, setup.clone(), Some(33), true),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_correct_root_hash_after_insertion() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(2),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(4096, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);

		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let key0 = key_bytes(0).to_vec();
		let key1 = key_bytes(1).to_vec();
		let key2 = key_bytes(2).to_vec();
		let zero_h0 = zero_tree[0].to_vec();
		let zero_h1 = zero_tree[1].to_vec();

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key0.clone()]));

		let keyh1 = setup.hash::<Test>(&key0, &zero_h0, &params).unwrap();
		let keyh2 = setup.hash::<Test>(&keyh1, &zero_h1, &params).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleTrees::add_members(Origin::signed(2), 0, vec![key1.clone()]));

		let keyh1 = setup.hash::<Test>(&key0, &key1, &params).unwrap();
		let keyh2 = setup.hash::<Test>(&keyh1, &zero_h1, &params).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleTrees::add_members(Origin::signed(3), 0, vec![key2.clone()]));

		let keyh1 = setup.hash::<Test>(&key0, &key1, &params).unwrap();
		let keyh2 = setup.hash::<Test>(&key2, &zero_h0, &params).unwrap();
		let keyh3 = setup.hash::<Test>(&keyh1, &keyh2, &params).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, keyh3, "Invalid root hash");
	});
}

#[test]
fn should_have_correct_root_hash() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(4),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(key_bytes(i as u8).to_vec());
		}
		let zero_h0 = zero_tree[0].to_vec();

		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, keys.clone()));

		let key1_1 = setup.hash::<Test>(&keys[0], &keys[1], &params).unwrap();
		let key1_2 = setup.hash::<Test>(&keys[2], &keys[3], &params).unwrap();
		let key1_3 = setup.hash::<Test>(&keys[4], &keys[5], &params).unwrap();
		let key1_4 = setup.hash::<Test>(&keys[6], &keys[7], &params).unwrap();
		let key1_5 = setup.hash::<Test>(&keys[8], &keys[9], &params).unwrap();
		let key1_6 = setup.hash::<Test>(&keys[10], &keys[11], &params).unwrap();
		let key1_7 = setup.hash::<Test>(&keys[12], &keys[13], &params).unwrap();
		let key1_8 = setup.hash::<Test>(&keys[14], &zero_h0, &params).unwrap();

		let key2_1 = setup.hash::<Test>(&key1_1, &key1_2, &params).unwrap();
		let key2_2 = setup.hash::<Test>(&key1_3, &key1_4, &params).unwrap();
		let key2_3 = setup.hash::<Test>(&key1_5, &key1_6, &params).unwrap();
		let key2_4 = setup.hash::<Test>(&key1_7, &key1_8, &params).unwrap();

		let key3_1 = setup.hash::<Test>(&key2_1, &key2_2, &params).unwrap();
		let key3_2 = setup.hash::<Test>(&key2_3, &key2_4, &params).unwrap();

		let root_hash = setup.hash::<Test>(&key3_1, &key3_2, &params).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, root_hash, "Invalid root hash");
	});
}

#[test]
fn should_be_unable_to_pass_proof_path_with_invalid_length() {
	new_test_ext().execute_with(|| {
		let key0 = key_bytes(0).to_vec();
		let key1 = key_bytes(1).to_vec();
		let key2 = key_bytes(2).to_vec();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(2),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();

		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, vec![
			key0.clone(),
			key1.clone(),
			key2.clone()
		]));

		let path = vec![(true, key0.clone())];
		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0.clone(), path),
			Error::<Test>::InvalidPathLength,
		);

		let path = vec![(true, key0.clone()), (false, key1), (true, key2)];
		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidPathLength,
		);
	});
}

#[test]
fn should_not_verify_invalid_proof() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(2),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let key0 = key_bytes(0).to_vec();
		let key1 = key_bytes(1).to_vec();
		let key2 = key_bytes(2).to_vec();
		let zero_h0 = zero_tree[0].to_vec();

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![
			key0.clone(),
			key1.clone(),
			key2.clone()
		]));

		let keyh1 = setup.hash::<Test>(&key0, &key1, &params).unwrap();
		let keyh2 = setup.hash::<Test>(&key2, &zero_h0, &params).unwrap();
		let _root_hash = setup.hash::<Test>(&keyh1, &keyh2, &params).unwrap();

		let path = vec![(false, key1.clone()), (true, keyh2.clone())];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0.clone(), path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key1), (false, keyh2)];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0.clone(), path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key2), (true, keyh1)];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);
	});
}

#[test]
fn should_verify_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(4),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(key_bytes(i as u8).to_vec());
		}
		let zero_h0 = zero_tree[0].to_vec();

		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, keys.clone()));

		let key1_1 = setup.hash::<Test>(&keys[0], &keys[1], &params).unwrap();
		let key1_2 = setup.hash::<Test>(&keys[2], &keys[3], &params).unwrap();
		let key1_3 = setup.hash::<Test>(&keys[4], &keys[5], &params).unwrap();
		let key1_4 = setup.hash::<Test>(&keys[6], &keys[7], &params).unwrap();
		let key1_5 = setup.hash::<Test>(&keys[8], &keys[9], &params).unwrap();
		let key1_6 = setup.hash::<Test>(&keys[10], &keys[11], &params).unwrap();
		let key1_7 = setup.hash::<Test>(&keys[12], &keys[13], &params).unwrap();
		let key1_8 = setup.hash::<Test>(&keys[14], &zero_h0, &params).unwrap();

		let key2_1 = setup.hash::<Test>(&key1_1, &key1_2, &params).unwrap();
		let key2_2 = setup.hash::<Test>(&key1_3, &key1_4, &params).unwrap();
		let key2_3 = setup.hash::<Test>(&key1_5, &key1_6, &params).unwrap();
		let key2_4 = setup.hash::<Test>(&key1_7, &key1_8, &params).unwrap();

		let key3_1 = setup.hash::<Test>(&key2_1, &key2_2, &params).unwrap();
		let key3_2 = setup.hash::<Test>(&key2_3, &key2_4, &params).unwrap();

		let _root_hash = setup.hash::<Test>(&key3_1, &key3_2, &params).unwrap();

		let path = vec![
			(true, keys[1].clone()),
			(true, key1_2),
			(true, key2_2),
			(true, key3_2.clone()),
		];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[0].clone(), path));

		let path = vec![(true, keys[5].clone()), (true, key1_4), (false, key2_1), (true, key3_2)];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[4].clone(), path));

		let path = vec![
			(true, keys[11].clone()),
			(false, key1_5),
			(true, key2_4),
			(false, key3_1.clone()),
		];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[10].clone(), path));

		let path = vec![(true, zero_h0), (false, key1_7), (false, key2_3), (false, key3_1)];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[14].clone(), path));
	});
}

#[test]
fn should_verify_simple_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(1),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		assert_ok!(MerkleTrees::add_members(
			Origin::signed(1),
			tree_id,
			vec![leaf.to_vec()]
		));

		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root,
			comms,
			nullifier_hash.to_bytes().to_vec(),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			key_bytes(0).to_vec(),
			key_bytes(0).to_vec(),
		));
	});
}

#[test]
fn should_not_verify_invalid_commitments_for_leaf_creation() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(1),
			true,
		));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);

		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		assert_ok!(MerkleTrees::add_members(
			Origin::signed(1),
			tree_id,
			vec![leaf.to_vec()]
		));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let mut comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut rng = OsRng::default();
		comms[0] = RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::ZkVerificationFailed
		);
	});
}

#[test]
fn should_not_verify_invalid_private_inputs() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(1),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);

		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		assert_ok!(MerkleTrees::add_members(
			Origin::signed(1),
			tree_id,
			vec![leaf.to_vec()]
		));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let mut comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();

		let mut rng = OsRng::default();
		comms.push(RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec());

		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::InvalidPrivateInputs
		);
	});
}

#[test]
fn should_not_verify_invalid_path_commitments_for_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(1),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);

		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		assert_ok!(MerkleTrees::add_members(
			Origin::signed(1),
			tree_id,
			vec![leaf.to_vec()]
		));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut leaf_index_comms: Vec<ScalarBytes> =
			leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut rng = OsRng::default();
		leaf_index_comms[0] = RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec();
		proof_comms[0] = RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec();
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::ZkVerificationFailed
		);
	});
}

#[test]
fn should_not_verify_invalid_transcript() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof_invalid";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(1),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);

		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		assert_ok!(MerkleTrees::add_members(
			Origin::signed(1),
			tree_id,
			vec![leaf.to_vec()]
		));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::ZkVerificationFailed
		);
	});
}

#[test]
fn should_verify_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(3),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);

		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(3).build();

		let leaf0 = ftree.generate_secrets();
		let leaf1 = ftree.generate_secrets();
		let leaf2 = ftree.generate_secrets();
		let leaf3 = ftree.generate_secrets();
		let leaf4 = ftree.generate_secrets();
		let leaf5 = ftree.generate_secrets();
		let leaf6 = ftree.generate_secrets();
		let keys = vec![
			leaf0.to_bytes(),
			leaf1.to_bytes(),
			leaf2.to_bytes(),
			leaf3.to_bytes(),
			leaf4.to_bytes(),
			leaf5.to_bytes(),
			leaf6.to_bytes(),
		];
		ftree.tree.add_leaves(keys.clone(), None);

		let keys_vec = keys.iter().map(|x| x.to_vec()).collect();
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, keys_vec));

		let root = MerkleTrees::get_merkle_root(0).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			leaf5,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root,
			comms,
			nullifier_hash.to_bytes().to_vec(),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			key_bytes(0).to_vec(),
			key_bytes(0).to_vec(),
		));
	});
}

#[test]
fn should_verify_large_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(32),
			true,
		));

		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(40960, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		let params = MerkleTrees::get_verifying_key(key_id).unwrap();
		let bp_gens = from_bytes_to_bp_gens(&params);
		let h = default_hasher(bp_gens);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);

		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(32).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		assert_ok!(MerkleTrees::add_members(
			Origin::signed(1),
			tree_id,
			vec![leaf.to_vec()]
		));

		let root = MerkleTrees::get_merkle_root(0).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root,
			comms,
			nullifier_hash.to_bytes().to_vec(),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			key_bytes(0).to_vec(),
			key_bytes(0).to_vec(),
		));
	});
}

#[test]
fn should_verify_simple_zk_proof_of_membership_arkworks() {
	new_test_ext().execute_with(|| {
		let mut rng = OsRng::default();
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, _) = setup_circuit(&leaves, 0, recipient, relayer, &mut rng);

		let leaf_bytes = to_bytes![leaf].unwrap();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Arkworks(Curve::Bls381, Snark::Groth16);
		let setup = Setup::new(hasher, backend);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(30),
			true,
		));

		let (pk, vk) = setup_random_groth16(&mut rng);
		let mut vk_bytes = Vec::new();
		vk.serialize(&mut vk_bytes).unwrap();

		let tree_id = 0;
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), vk_bytes));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), tree_id, vec![leaf_bytes]));

		let other_root = to_bytes![root].unwrap();
		let root_bytes = MerkleTrees::get_merkle_root(0).unwrap();
		assert_eq!(other_root, root_bytes);
		let recipient_bytes = to_bytes![recipient].unwrap();
		let relayer_bytes = to_bytes![relayer].unwrap();
		let nullifier_bytes = to_bytes![nullifier].unwrap();

		let proof = prove_groth16(&pk, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();

		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root_bytes,
			Vec::new(),
			nullifier_bytes,
			proof_bytes,
			Vec::new(),
			Vec::new(),
			recipient_bytes,
			relayer_bytes,
		));
	});
}

#[test]
fn should_fail_to_verify_empty_public_inputs_arkworks() {
	new_test_ext().execute_with(|| {
		let mut rng = OsRng::default();
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, _) = setup_circuit(&leaves, 0, recipient, relayer, &mut rng);

		let leaf_bytes = to_bytes![leaf].unwrap();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Arkworks(Curve::Bls381, Snark::Groth16);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(30),
			true,
		));

		let (pk, vk) = setup_random_groth16(&mut rng);
		let mut vk_bytes = Vec::new();
		vk.serialize(&mut vk_bytes).unwrap();

		let tree_id = 0;
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), vk_bytes));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf_bytes]));

		let other_root = to_bytes![root].unwrap();
		let root_bytes = MerkleTrees::get_merkle_root(0).unwrap();
		assert_eq!(other_root, root_bytes);
		let recipient_bytes = to_bytes![recipient].unwrap();
		let relayer_bytes = to_bytes![relayer].unwrap();
		let nullifier_bytes = to_bytes![nullifier].unwrap();

		let proof = prove_groth16(&pk, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();

		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root_bytes.clone(),
				Vec::new(),
				// Nullifier bytes
				Vec::new(),
				proof_bytes.clone(),
				Vec::new(),
				Vec::new(),
				recipient_bytes.clone(),
				relayer_bytes.clone(),
			),
			Error::<Test>::InvalidPublicInputs
		);

		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root_bytes.clone(),
				Vec::new(),
				nullifier_bytes.clone(),
				proof_bytes.clone(),
				Vec::new(),
				Vec::new(),
				// Invalid recipient bytes
				Vec::new(),
				relayer_bytes.clone(),
			),
			Error::<Test>::InvalidPublicInputs
		);

		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root_bytes.clone(),
				Vec::new(),
				nullifier_bytes.clone(),
				proof_bytes.clone(),
				Vec::new(),
				Vec::new(),
				recipient_bytes,
				// Invalid replayer bytes
				Vec::new(),
			),
			Error::<Test>::InvalidPublicInputs
		);
	});
}

#[test]
fn should_fail_to_verify_invalid_public_inputs_arkworks() {
	new_test_ext().execute_with(|| {
		let mut rng = OsRng::default();
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, _) = setup_circuit(&leaves, 0, recipient, relayer, &mut rng);

		let leaf_bytes = to_bytes![leaf].unwrap();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Arkworks(Curve::Bls381, Snark::Groth16);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(30),
			true,
		));

		let (pk, vk) = setup_random_groth16(&mut rng);
		let mut vk_bytes = Vec::new();
		vk.serialize(&mut vk_bytes).unwrap();

		let tree_id = 0;
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), vk_bytes));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf_bytes]));

		let other_root = to_bytes![root].unwrap();
		let root_bytes = MerkleTrees::get_merkle_root(0).unwrap();
		assert_eq!(other_root, root_bytes);
		let recipient_bytes = to_bytes![recipient].unwrap();
		let relayer_bytes = to_bytes![relayer].unwrap();
		let nullifier_bytes = to_bytes![nullifier].unwrap();

		let proof = prove_groth16(&pk, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();

		let mut invalid_nullifier = nullifier_bytes.clone();
		invalid_nullifier.push(0u8);
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root_bytes.clone(),
				Vec::new(),
				// Nullifier bytes
				invalid_nullifier,
				proof_bytes.clone(),
				Vec::new(),
				Vec::new(),
				recipient_bytes.clone(),
				relayer_bytes.clone(),
			),
			Error::<Test>::InvalidPublicInputs
		);

		let mut invalid_recipient = recipient_bytes.clone();
		invalid_recipient.push(0u8);
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root_bytes.clone(),
				Vec::new(),
				nullifier_bytes.clone(),
				proof_bytes.clone(),
				Vec::new(),
				Vec::new(),
				// Invalid recipient bytes
				invalid_recipient,
				relayer_bytes.clone(),
			),
			Error::<Test>::InvalidPublicInputs
		);

		let mut invalid_relayer = recipient_bytes.clone();
		invalid_relayer.push(0u8);
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root_bytes.clone(),
				Vec::new(),
				nullifier_bytes.clone(),
				proof_bytes.clone(),
				Vec::new(),
				Vec::new(),
				recipient_bytes,
				// Invalid replayer bytes
				invalid_relayer,
			),
			Error::<Test>::InvalidPublicInputs
		);
	});
}

#[test]
fn should_fail_to_add_leaf_without_a_key_arkworks() {
	new_test_ext().execute_with(|| {
		let mut rng = OsRng::default();
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (_, leaf, ..) = setup_circuit(&leaves, 0, recipient, relayer, &mut rng);

		let leaf_bytes = to_bytes![leaf].unwrap();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Arkworks(Curve::Bls381, Snark::Groth16);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(30),
			true,
		));

		assert_err!(
			MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf_bytes]),
			Error::<Test>::InvalidVerifierKey
		);
	});
}

#[test]
fn should_fail_to_verify_with_invalid_key_arkworks() {
	new_test_ext().execute_with(|| {
		let mut rng = OsRng::default();
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, _) = setup_circuit(&leaves, 0, recipient, relayer, &mut rng);

		let leaf_bytes = to_bytes![leaf].unwrap();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Arkworks(Curve::Bls381, Snark::Groth16);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			setup.clone(),
			Some(30),
			true,
		));

		let (pk, vk) = setup_random_groth16(&mut rng);
		let mut vk_bytes = Vec::new();
		vk.serialize(&mut vk_bytes).unwrap();
		// pushing invalid byte
		vk_bytes[0] = 1u8;
		let tree_id = 0;
		assert_ok!(MerkleTrees::add_verifying_key(Origin::signed(1), vk_bytes));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf_bytes]));

		let other_root = to_bytes![root].unwrap();
		let root_bytes = MerkleTrees::get_merkle_root(0).unwrap();
		assert_eq!(other_root, root_bytes);
		let recipient_bytes = to_bytes![recipient].unwrap();
		let relayer_bytes = to_bytes![relayer].unwrap();
		let nullifier_bytes = to_bytes![nullifier].unwrap();

		let proof = prove_groth16(&pk, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();

		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root_bytes.clone(),
				Vec::new(),
				nullifier_bytes,
				proof_bytes,
				Vec::new(),
				Vec::new(),
				recipient_bytes,
				relayer_bytes,
			),
			Error::<Test>::InvalidVerifierKey
		);
	});
}

#[test]
fn encode_bulletproof_gens_and_back() {
	let gens = BulletproofGens::new(16400, 1);
	let gen_bytes = get_bp_gen_bytes(&gens);
	let new_gens = from_bytes_to_bp_gens(&gen_bytes);
	// println!("{:?}, {:?}", gens.gens_capacity, new_gens.gens_capacity);
	// println!("{:?}, {:?}", gens.party_capacity, new_gens.party_capacity);
	assert!(gens.gens_capacity == new_gens.gens_capacity);
	assert!(gens.party_capacity == new_gens.party_capacity);
	assert!(gens.G_vec == new_gens.G_vec);
	assert!(gens.H_vec == new_gens.H_vec);
}
