use super::*;
use crate::{
	mock::*,
	utils::keys::{from_bytes_to_bp_gens, get_bp_gen_bytes, Commitment, ScalarData},
};
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use bulletproofs_gadgets::{
	fixed_deposit_tree::builder::FixedDepositTreeBuilder,
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		PoseidonSbox, Poseidon_hash_2,
	},
	smt::gen_zero_tree,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use frame_support::{assert_err, assert_ok, traits::UnfilteredDispatchable};
use frame_system::RawOrigin;
use merlin::Transcript;
use rand_chacha::ChaChaRng;
use sp_runtime::traits::BadOrigin;

fn key_bytes(x: u8) -> [u8; 32] {
	[
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x,
	]
}

fn default_hasher(num_gens: usize) -> Poseidon {
	let width = 6;
	PoseidonBuilder::new(width)
		.bulletproof_gens(BulletproofGens::new(num_gens, 1))
		.sbox(PoseidonSbox::Exponentiation17)
		.build()
}

#[test]
fn can_create_tree() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(3)));
	});
}

#[test]
fn can_update_manager_when_required() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), true, Some(3)));

		assert_ok!(MerkleTrees::set_manager(Origin::signed(1), 0, 2,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);
	});
}

#[test]
fn can_update_manager_when_not_required() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(3)));

		assert_ok!(MerkleTrees::set_manager(Origin::signed(1), 0, 2,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);
	});
}

#[test]
fn cannot_update_manager_as_not_manager() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(3)));

		assert_err!(MerkleTrees::set_manager(Origin::signed(2), 0, 2,), BadOrigin);
	});
}

#[test]
fn can_update_manager_required_manager() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(3)));

		assert_ok!(MerkleTrees::set_manager_required(Origin::signed(1), 0, true,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.required, true);
	});
}

#[test]
fn cannot_update_manager_required_as_not_manager() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(3)));

		assert_err!(
			MerkleTrees::set_manager_required(Origin::signed(2), 0, true,),
			Error::<Test>::ManagerIsRequired
		);
	});
}

#[test]
fn can_add_member() {
	new_test_ext().execute_with(|| {
		let key = ScalarData::from(key_bytes(1));
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(3)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
	});
}

#[test]
fn can_add_member_as_manager() {
	new_test_ext().execute_with(|| {
		let key = ScalarData::from(key_bytes(1));

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), true, Some(3)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
	});
}

#[test]
fn cannot_add_member_as_not_manager() {
	new_test_ext().execute_with(|| {
		let key = ScalarData::from(key_bytes(1));

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), true, Some(3)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
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
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), true, Some(1)));
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
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), true, Some(3)));
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
		assert_err!(
			MerkleTrees::create_tree(Origin::signed(1), false, Some(0)),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_min_depth() {
	new_test_ext().execute_with(|| {
		let key = ScalarData::from(key_bytes(1));
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(1)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
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
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(32)));
	});
}

#[test]
fn should_not_have_more_than_max_depth() {
	new_test_ext().execute_with(|| {
		assert_err!(
			MerkleTrees::create_tree(Origin::signed(1), false, Some(33)),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_correct_root_hash_after_insertion() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let key0 = ScalarData::from(key_bytes(0));
		let key1 = ScalarData::from(key_bytes(1));
		let key2 = ScalarData::from(key_bytes(2));
		let zero_h0 = ScalarData::from(zero_tree[0]);
		let zero_h1 = ScalarData::from(zero_tree[1]);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(2)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key0.clone()]));

		let keyh1 = Poseidon_hash_2(key0.0, zero_h0.0, &h);
		let keyh2 = Poseidon_hash_2(keyh1, zero_h1.0, &h);

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash.unwrap().0, keyh2, "Invalid root hash");

		assert_ok!(MerkleTrees::add_members(Origin::signed(2), 0, vec![key1.clone()]));

		let keyh1 = Poseidon_hash_2(key0.0, key1.0, &h);
		let keyh2 = Poseidon_hash_2(keyh1, zero_h1.0, &h);

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash.unwrap().0, keyh2, "Invalid root hash");

		assert_ok!(MerkleTrees::add_members(Origin::signed(3), 0, vec![key2.clone()]));

		let keyh1 = Poseidon_hash_2(key0.0, key1.0, &h);
		let keyh2 = Poseidon_hash_2(key2.0, zero_h0.0, &h);
		let keyh3 = Poseidon_hash_2(keyh1, keyh2, &h);

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash.unwrap().0, keyh3, "Invalid root hash");
	});
}

#[test]
fn should_have_correct_root_hash() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(Scalar::from_bytes_mod_order(key_bytes(i as u8)))
		}
		let zero_h0 = ScalarData::from(zero_tree[0]);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(4)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		let keys_data: Vec<ScalarData> = keys.iter().map(|x| ScalarData(*x)).collect();
		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, keys_data.clone()));

		let key1_1 = Poseidon_hash_2(keys[0], keys[1], &h);
		let key1_2 = Poseidon_hash_2(keys[2], keys[3], &h);
		let key1_3 = Poseidon_hash_2(keys[4], keys[5], &h);
		let key1_4 = Poseidon_hash_2(keys[6], keys[7], &h);
		let key1_5 = Poseidon_hash_2(keys[8], keys[9], &h);
		let key1_6 = Poseidon_hash_2(keys[10], keys[11], &h);
		let key1_7 = Poseidon_hash_2(keys[12], keys[13], &h);
		let key1_8 = Poseidon_hash_2(keys[14], zero_h0.0, &h);

		let key2_1 = Poseidon_hash_2(key1_1, key1_2, &h);
		let key2_2 = Poseidon_hash_2(key1_3, key1_4, &h);
		let key2_3 = Poseidon_hash_2(key1_5, key1_6, &h);
		let key2_4 = Poseidon_hash_2(key1_7, key1_8, &h);

		let key3_1 = Poseidon_hash_2(key2_1, key2_2, &h);
		let key3_2 = Poseidon_hash_2(key2_3, key2_4, &h);

		let root_hash = Poseidon_hash_2(key3_1, key3_2, &h);

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash.unwrap().0, root_hash, "Invalid root hash");
	});
}

#[test]
fn should_be_unable_to_pass_proof_path_with_invalid_length() {
	new_test_ext().execute_with(|| {
		let key0 = ScalarData::from(key_bytes(0));
		let key1 = ScalarData::from(key_bytes(1));
		let key2 = ScalarData::from(key_bytes(2));
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(2)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, vec![
			key0.clone(),
			key1.clone(),
			key2.clone()
		]));

		let path = vec![(true, key0)];
		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidPathLength,
		);

		let path = vec![(true, key0), (false, key1), (true, key2)];
		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidPathLength,
		);
	});
}

#[test]
fn should_not_verify_invalid_proof() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let key0 = ScalarData::from(key_bytes(9));
		let key1 = ScalarData::from(key_bytes(3));
		let key2 = ScalarData::from(key_bytes(5));
		let zero_h0 = ScalarData::from(zero_tree[0]);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(2)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![
			key0.clone(),
			key1.clone(),
			key2.clone()
		]));

		let keyh1 = Poseidon_hash_2(key0.0, key1.0, &h);
		let keyh2 = Poseidon_hash_2(key2.0, zero_h0.0, &h);
		let _root_hash = Poseidon_hash_2(keyh1, keyh2, &h);

		let path = vec![(false, key1), (true, ScalarData(keyh2))];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key1), (false, ScalarData(keyh2))];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key2), (true, ScalarData(keyh1))];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);
	});
}

#[test]
fn should_verify_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(Scalar::from_bytes_mod_order(key_bytes(i as u8)))
		}
		let zero_h0 = ScalarData::from(zero_tree[0]);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(4)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		let keys_data: Vec<ScalarData> = keys.iter().map(|x| ScalarData(*x)).collect();
		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, keys_data.clone()));

		let key1_1 = Poseidon_hash_2(keys[0], keys[1], &h);
		let key1_2 = Poseidon_hash_2(keys[2], keys[3], &h);
		let key1_3 = Poseidon_hash_2(keys[4], keys[5], &h);
		let key1_4 = Poseidon_hash_2(keys[6], keys[7], &h);
		let key1_5 = Poseidon_hash_2(keys[8], keys[9], &h);
		let key1_6 = Poseidon_hash_2(keys[10], keys[11], &h);
		let key1_7 = Poseidon_hash_2(keys[12], keys[13], &h);
		let key1_8 = Poseidon_hash_2(keys[14], zero_h0.0, &h);

		let key2_1 = Poseidon_hash_2(key1_1, key1_2, &h);
		let key2_2 = Poseidon_hash_2(key1_3, key1_4, &h);
		let key2_3 = Poseidon_hash_2(key1_5, key1_6, &h);
		let key2_4 = Poseidon_hash_2(key1_7, key1_8, &h);

		let key3_1 = Poseidon_hash_2(key2_1, key2_2, &h);
		let key3_2 = Poseidon_hash_2(key2_3, key2_4, &h);

		let _root_hash = Poseidon_hash_2(key3_1, key3_2, &h);

		let path = vec![
			(true, keys_data[1]),
			(true, ScalarData(key1_2)),
			(true, ScalarData(key2_2)),
			(true, ScalarData(key3_2)),
		];

		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys_data[0], path));

		let path = vec![
			(true, keys_data[5]),
			(true, ScalarData(key1_4)),
			(false, ScalarData(key2_1)),
			(true, ScalarData(key3_2)),
		];

		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys_data[4], path));

		let path = vec![
			(true, keys_data[11]),
			(false, ScalarData(key1_5)),
			(true, ScalarData(key2_4)),
			(false, ScalarData(key3_1)),
		];

		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys_data[10], path));

		let path = vec![
			(true, zero_h0),
			(false, ScalarData(key1_7)),
			(false, ScalarData(key2_3)),
			(false, ScalarData(key3_1)),
		];

		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys_data[14], path));
	});
}

#[test]
fn should_verify_simple_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets();
		ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(1)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![ScalarData(leaf)]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			root.0,
			leaf,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

		assert_ok!(MerkleTrees::verify_zk_membership_proof(
			0,
			0,
			root,
			comms,
			ScalarData(nullifier_hash),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			ScalarData::zero(),
			ScalarData::zero(),
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

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets();
		ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(1)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![ScalarData(leaf)]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			root.0,
			leaf,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let mut comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let mut rng = ChaChaRng::from_seed([1u8; 32]);
		comms[0] = Commitment(RistrettoPoint::random(&mut rng).compress());
		let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

		assert_err!(
			MerkleTrees::verify_zk_membership_proof(
				0,
				0,
				root,
				comms,
				ScalarData(nullifier_hash),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				ScalarData::zero(),
				ScalarData::zero(),
			),
			Error::<Test>::ZkVericationFailed
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

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets();
		ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(1)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![ScalarData(leaf)]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			root.0,
			leaf,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let mut comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

		let mut rng = ChaChaRng::from_seed([1u8; 32]);
		comms.push(Commitment(RistrettoPoint::random(&mut rng).compress()));

		assert_err!(
			MerkleTrees::verify_zk_membership_proof(
				0,
				0,
				root,
				comms,
				ScalarData(nullifier_hash),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				ScalarData::zero(),
				ScalarData::zero(),
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

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets();
		ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(1)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![ScalarData(leaf)]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			root.0,
			leaf,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let mut leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let mut proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let mut rng = ChaChaRng::from_seed([1u8; 32]);
		leaf_index_comms[0] = Commitment(RistrettoPoint::random(&mut rng).compress());
		proof_comms[0] = Commitment(RistrettoPoint::random(&mut rng).compress());

		assert_err!(
			MerkleTrees::verify_zk_membership_proof(
				0,
				0,
				root,
				comms,
				ScalarData(nullifier_hash),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				ScalarData::zero(),
				ScalarData::zero(),
			),
			Error::<Test>::ZkVericationFailed
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

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets();
		ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(1)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![ScalarData(leaf)]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			root.0,
			leaf,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

		assert_err!(
			MerkleTrees::verify_zk_membership_proof(
				0,
				0,
				root,
				comms,
				ScalarData(nullifier_hash),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				ScalarData::zero(),
				ScalarData::zero(),
			),
			Error::<Test>::ZkVericationFailed
		);
	});
}

#[test]
fn should_verify_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);
		let h = default_hasher(4096);
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

		let keys_data: Vec<ScalarData> = keys
			.iter()
			.map(|x| ScalarData(Scalar::from_bytes_mod_order(*x)))
			.collect();
		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(3)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, keys_data));

		let root = MerkleTrees::get_merkle_root(0).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			root.0,
			leaf5,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

		assert_ok!(MerkleTrees::verify_zk_membership_proof(
			0,
			0,
			root,
			comms,
			ScalarData(nullifier_hash),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			ScalarData::zero(),
			ScalarData::zero(),
		));
	});
}

#[test]
fn should_verify_large_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);
		let poseidon = default_hasher(40960);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(poseidon).depth(32).build();

		let leaf = ftree.generate_secrets();
		ftree.tree.add_leaves(vec![leaf.to_bytes()], None);

		assert_ok!(MerkleTrees::create_tree(Origin::signed(1), false, Some(32)));
		let tree_id = 0;
		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		assert_ok!(MerkleTrees::add_verifying_key(Origin::root(), key_data));
		let key_id = 0;
		assert_ok!(MerkleTrees::initialize_tree(Origin::signed(1), tree_id, key_id));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![ScalarData(leaf)]));

		let root = MerkleTrees::get_merkle_root(0).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			root.0,
			leaf,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<Commitment> = comms_cr.iter().map(|x| Commitment(*x)).collect();
		let leaf_index_comms: Vec<Commitment> = leaf_index_comms_cr.iter().map(|x| Commitment(*x)).collect();
		let proof_comms: Vec<Commitment> = proof_comms_cr.iter().map(|x| Commitment(*x)).collect();

		assert_ok!(MerkleTrees::verify_zk_membership_proof(
			0,
			0,
			root,
			comms,
			ScalarData(nullifier_hash),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			ScalarData::zero(),
			ScalarData::zero(),
		));
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
