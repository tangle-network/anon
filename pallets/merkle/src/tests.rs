use super::*;
use crate::merkle::hasher::Hasher;
use crate::merkle::helper::{commit_leaf, commit_path_level, leaf_data};
use crate::merkle::keys::{Commitment, Data};
use crate::merkle::poseidon::Poseidon;
use crate::mock::*;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::RistrettoPoint;
use frame_support::{assert_err, assert_ok};
use merlin::Transcript;

fn key_bytes(x: u8) -> [u8; 32] {
	[
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, x,
	]
}

fn default_hasher() -> impl Hasher {
	Poseidon::new(4)
	// Mimc::new(70)
}

#[test]
fn can_create_group() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(3),
		));
	});
}

#[test]
fn can_update_manager_when_required() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			true,
			Some(3),
		));

		assert_ok!(MerkleGroups::set_manager(
			Origin::signed(1),
			0,
			2,
		));
	});
}

#[test]
fn can_update_manager_when_not_required() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(3),
		));

		assert_ok!(MerkleGroups::set_manager(
			Origin::signed(1),
			0,
			2,
		));
	});
}

#[test]
fn cannot_update_manager_as_not_manager() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(3),
		));

		assert_err!(MerkleGroups::set_manager(
			Origin::signed(2),
			0,
			2,
		), Error::<Test>::ManagerIsRequired);
	});
}

#[test]
fn can_update_manager_required_manager() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(3),
		));

		assert_ok!(MerkleGroups::set_manager_required(
			Origin::signed(1),
			0,
			true,
		));
	});
}

#[test]
fn cannot_update_manager_required_as_not_manager() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(3),
		));

		assert_err!(MerkleGroups::set_manager_required(
			Origin::signed(2),
			0,
			true,
		), Error::<Test>::ManagerIsRequired);
	});
}

#[test]
fn can_add_member() {
	new_test_ext().execute_with(|| {
		let key = Data::from(key_bytes(1));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(3),
		));
		assert_ok!(MerkleGroups::add_members(
			Origin::signed(1),
			0,
			vec![key.clone()]
		));
	});
}

#[test]
fn can_add_member_as_manager() {
	new_test_ext().execute_with(|| {
		let key = Data::from(key_bytes(1));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			true,
			Some(3),
		));
		assert_ok!(MerkleGroups::add_members(
			Origin::signed(1),
			0,
			vec![key.clone()]
		));
	});
}

#[test]
fn cannot_add_member_as_not_manager() {
	new_test_ext().execute_with(|| {
		let key = Data::from(key_bytes(1));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			true,
			Some(3),
		));
		assert_err!(MerkleGroups::add_members(
			Origin::signed(2),
			0,
			vec![key.clone()]
		), Error::<Test>::ManagerIsRequired);
	});
}

#[test]
fn should_not_have_0_depth() {
	new_test_ext().execute_with(|| {
		assert_err!(
			MerkleGroups::create_group(Origin::signed(1), false, Some(0)),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_min_depth() {
	new_test_ext().execute_with(|| {
		let key = Data::from(key_bytes(1));
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(1),
		));

		assert_ok!(MerkleGroups::add_members(
			Origin::signed(1),
			0,
			vec![key.clone()]
		));
		assert_err!(
			MerkleGroups::add_members(Origin::signed(1), 0, vec![key.clone()]),
			Error::<Test>::ExceedsMaxDepth,
		);
	});
}

#[test]
fn should_have_max_depth() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(32),
		));
	});
}

#[test]
fn should_not_have_more_than_max_depth() {
	new_test_ext().execute_with(|| {
		assert_err!(
			MerkleGroups::create_group(Origin::signed(1), false, Some(33),),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_correct_root_hash_after_insertion() {
	new_test_ext().execute_with(|| {
		let h = default_hasher();
		let key0 = Data::from(key_bytes(0));
		let key1 = Data::from(key_bytes(1));
		let key2 = Data::from(key_bytes(2));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(2),
		));
		assert_ok!(MerkleGroups::add_members(
			Origin::signed(1),
			0,
			vec![key0.clone()]
		));

		let keyh1 = Data::hash(key0, key0, &h);
		let keyh2 = Data::hash(keyh1, keyh1, &h);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleGroups::add_members(
			Origin::signed(2),
			0,
			vec![key1.clone()]
		));

		let keyh1 = Data::hash(key0, key1, &h);
		let keyh2 = Data::hash(keyh1, keyh1, &h);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleGroups::add_members(
			Origin::signed(3),
			0,
			vec![key2.clone()]
		));

		let keyh1 = Data::hash(key0, key1, &h);
		let keyh2 = Data::hash(key2, key2, &h);
		let keyh3 = Data::hash(keyh1, keyh2, &h);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh3, "Invalid root hash");
	});
}

#[test]
fn should_have_correct_root_hash() {
	new_test_ext().execute_with(|| {
		let h = default_hasher();
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(Data::from(key_bytes(i as u8)))
		}

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(4),
		));

		assert_ok!(MerkleGroups::add_members(
			Origin::signed(0),
			0,
			keys.clone()
		));

		let key1_1 = Data::hash(keys[0], keys[1], &h);
		let key1_2 = Data::hash(keys[2], keys[3], &h);
		let key1_3 = Data::hash(keys[4], keys[5], &h);
		let key1_4 = Data::hash(keys[6], keys[7], &h);
		let key1_5 = Data::hash(keys[8], keys[9], &h);
		let key1_6 = Data::hash(keys[10], keys[11], &h);
		let key1_7 = Data::hash(keys[12], keys[13], &h);
		let key1_8 = Data::hash(keys[14], keys[14], &h);

		let key2_1 = Data::hash(key1_1, key1_2, &h);
		let key2_2 = Data::hash(key1_3, key1_4, &h);
		let key2_3 = Data::hash(key1_5, key1_6, &h);
		let key2_4 = Data::hash(key1_7, key1_8, &h);

		let key3_1 = Data::hash(key2_1, key2_2, &h);
		let key3_2 = Data::hash(key2_3, key2_4, &h);

		let root_hash = Data::hash(key3_1, key3_2, &h);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, root_hash, "Invalid root hash");
	});
}

#[test]
fn should_be_unable_to_pass_proof_path_with_invalid_length() {
	new_test_ext().execute_with(|| {
		let key0 = Data::from(key_bytes(0));
		let key1 = Data::from(key_bytes(1));
		let key2 = Data::from(key_bytes(2));
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(2),
		));
		assert_ok!(MerkleGroups::add_members(
			Origin::signed(0),
			0,
			vec![key0.clone(), key1.clone(), key2.clone()]
		));

		let path = vec![(true, key0)];
		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidPathLength,
		);

		let path = vec![(true, key0), (false, key1), (true, key2)];
		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidPathLength,
		);
	});
}

#[test]
fn should_not_verify_invalid_proof() {
	new_test_ext().execute_with(|| {
		let h = default_hasher();
		let key0 = Data::from(key_bytes(9));
		let key1 = Data::from(key_bytes(3));
		let key2 = Data::from(key_bytes(5));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(2),
		));
		assert_ok!(MerkleGroups::add_members(
			Origin::signed(1),
			0,
			vec![key0.clone(), key1.clone(), key2.clone()]
		));

		let keyh1 = Data::hash(key0, key1, &h);
		let keyh2 = Data::hash(key2, key2, &h);
		let _root_hash = Data::hash(keyh1, keyh2, &h);

		let path = vec![(false, key1), (true, keyh2)];

		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key1), (false, keyh2)];

		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key2), (true, keyh1)];

		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);
	});
}

#[test]
fn should_verify_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let h = default_hasher();
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(Data::from(key_bytes(i as u8)))
		}

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(4),
		));

		assert_ok!(MerkleGroups::add_members(
			Origin::signed(0),
			0,
			keys.clone()
		));

		let key1_1 = Data::hash(keys[0], keys[1], &h);
		let key1_2 = Data::hash(keys[2], keys[3], &h);
		let key1_3 = Data::hash(keys[4], keys[5], &h);
		let key1_4 = Data::hash(keys[6], keys[7], &h);
		let key1_5 = Data::hash(keys[8], keys[9], &h);
		let key1_6 = Data::hash(keys[10], keys[11], &h);
		let key1_7 = Data::hash(keys[12], keys[13], &h);
		let key1_8 = Data::hash(keys[14], keys[14], &h);

		let key2_1 = Data::hash(key1_1, key1_2, &h);
		let key2_2 = Data::hash(key1_3, key1_4, &h);
		let key2_3 = Data::hash(key1_5, key1_6, &h);
		let key2_4 = Data::hash(key1_7, key1_8, &h);

		let key3_1 = Data::hash(key2_1, key2_2, &h);
		let key3_2 = Data::hash(key2_3, key2_4, &h);

		let _root_hash = Data::hash(key3_1, key3_2, &h);

		let path = vec![
			(true, keys[1]),
			(true, key1_2),
			(true, key2_2),
			(true, key3_2),
		];

		assert_ok!(MerkleGroups::verify(Origin::signed(2), 0, keys[0], path));

		let path = vec![
			(true, keys[5]),
			(true, key1_4),
			(false, key2_1),
			(true, key3_2),
		];

		assert_ok!(MerkleGroups::verify(Origin::signed(2), 0, keys[4], path));

		let path = vec![
			(true, keys[11]),
			(false, key1_5),
			(true, key2_4),
			(false, key3_1),
		];

		assert_ok!(MerkleGroups::verify(Origin::signed(2), 0, keys[10], path));

		let path = vec![
			(false, keys[14]),
			(false, key1_7),
			(false, key2_3),
			(false, key3_1),
		];

		assert_ok!(MerkleGroups::verify(Origin::signed(2), 0, keys[14], path));
	});
}

#[test]
fn should_verify_simple_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let h = default_hasher();
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut test_rng = rand::thread_rng();
		let (s, nullifier, leaf) = leaf_data(&mut test_rng, &h);

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			false,
			Some(1),
		));
		assert_ok!(MerkleGroups::add_members(Origin::signed(1), 0, vec![leaf]));
		let nullifier_hash = Data::hash(Data(nullifier), Data(nullifier), &h);

		let (s_com, leaf_com1, nullifier_com, leaf_var1) =
			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier, nullifier_hash, &h);


		let root = Data::hash(leaf, leaf, &h);
		let (bit_com, leaf_com2, root_con) =
			commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1, &h);
		prover.constrain(root_con - root.0);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

		let path = vec![(Commitment(bit_com), Commitment(leaf_com2))];

		let root = MerkleGroups::get_merkle_root(0);
		assert_ok!(MerkleGroups::verify_zk_membership_proof(
			0,
			0,
			root.unwrap(),
			Commitment(leaf_com1),
			path,
			Commitment(s_com),
			Commitment(nullifier_com),
			nullifier_hash,
			proof.to_bytes(),
		));
	});
}

// #[test]
// fn should_not_verify_invalid_commitments_for_leaf_creation() {
// 	new_test_ext().execute_with(|| {
// 		let h = default_hasher();
// 		let pc_gens = PedersenGens::default();
// 		let bp_gens = BulletproofGens::new(2048, 1);

// 		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
// 		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

// 		let mut test_rng = rand::thread_rng();
// 		let (s, nullifier, leaf) = leaf_data(&mut test_rng, &h);

// 		assert_ok!(MerkleGroups::create_group(
// 			Origin::signed(1),
// 			false,
// 			Some(1),
// 		));
// 		assert_ok!(MerkleGroups::add_members(Origin::signed(1), 0, vec![leaf]));

// 		let (_, leaf_com1, leaf_var1) =
// 			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier, &h);
// 		let root = Data::hash(leaf, leaf, &h);
// 		let (bit_com, leaf_com2, root_con) =
// 			commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1, &h);
// 		prover.constrain(root_con - root.0);

// 		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
// 		let path = vec![(Commitment(bit_com), Commitment(leaf_com2))];

// 		let invalid_s_com = RistrettoPoint::random(&mut test_rng).compress();

// 		let root = MerkleGroups::get_merkle_root(0);
// 		assert_err!(
// 			MerkleGroups::verify_zk_membership_proof(
// 				0,
// 				0,
// 				root.unwrap(),
// 				Commitment(leaf_com1),
// 				path,
// 				Commitment(invalid_s_com),
// 				Data(nullifier),
// 				proof.to_bytes(),
// 			),
// 			Error::<Test>::ZkVericationFailed,
// 		);
// 	});
// }

// #[test]
// fn should_not_verify_invalid_commitments_for_membership() {
// 	new_test_ext().execute_with(|| {
// 		let h = default_hasher();
// 		let pc_gens = PedersenGens::default();
// 		let bp_gens = BulletproofGens::new(2048, 1);

// 		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
// 		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

// 		let mut test_rng = rand::thread_rng();
// 		let (s, nullifier, leaf) = leaf_data(&mut test_rng, &h);

// 		assert_ok!(MerkleGroups::create_group(
// 			Origin::signed(1),
// 			false,
// 			Some(1),
// 		));
// 		assert_ok!(MerkleGroups::add_members(Origin::signed(1), 0, vec![leaf]));

// 		let (s_com, leaf_com1, leaf_var1) =
// 			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier, &h);

// 		let _ = commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1, &h);

// 		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
// 		let invalid_path_com = RistrettoPoint::random(&mut test_rng).compress();
// 		let invalid_bit_com = RistrettoPoint::random(&mut test_rng).compress();
// 		let path = vec![(Commitment(invalid_bit_com), Commitment(invalid_path_com))];

// 		let root = MerkleGroups::get_merkle_root(0);
// 		assert_err!(
// 			MerkleGroups::verify_zk_membership_proof(
// 				0,
// 				0,
// 				root.unwrap(),
// 				Commitment(leaf_com1),
// 				path,
// 				Commitment(s_com),
// 				Data(nullifier),
// 				proof.to_bytes(),
// 			),
// 			Error::<Test>::ZkVericationFailed,
// 		);
// 	});
// }

// #[test]
// fn should_not_verify_invalid_transcript() {
// 	new_test_ext().execute_with(|| {
// 		let h = default_hasher();
// 		let pc_gens = PedersenGens::default();
// 		let bp_gens = BulletproofGens::new(2048, 1);

// 		let mut prover_transcript = Transcript::new(b"invalid transcript");
// 		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

// 		let mut test_rng = rand::thread_rng();
// 		let (s, nullifier, leaf) = leaf_data(&mut test_rng, &h);

// 		assert_ok!(MerkleGroups::create_group(
// 			Origin::signed(1),
// 			false,
// 			Some(1),
// 		));
// 		assert_ok!(MerkleGroups::add_members(Origin::signed(1), 0, vec![leaf]));

// 		let (s_com, leaf_com1, leaf_var1) =
// 			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier, &h);

// 		let root = Data::hash(leaf, leaf, &h);
// 		let (bit_com, leaf_com2, root_con) =
// 			commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1, &h);
// 		prover.constrain(root_con - root.0);

// 		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
// 		let path = vec![(Commitment(bit_com), Commitment(leaf_com2))];

// 		let root = MerkleGroups::get_merkle_root(0);
// 		assert_err!(
// 			MerkleGroups::verify_zk_membership_proof(
// 				0,
// 				0,
// 				root.unwrap(),
// 				Commitment(leaf_com1),
// 				path,
// 				Commitment(s_com),
// 				Data(nullifier),
// 				proof.to_bytes(),
// 			),
// 			Error::<Test>::ZkVericationFailed,
// 		);
// 	});
// }

// #[test]
// fn should_verify_zk_proof_of_membership() {
// 	new_test_ext().execute_with(|| {
// 		let h = default_hasher();
// 		let pc_gens = PedersenGens::default();
// 		let bp_gens = BulletproofGens::new(2048, 1);

// 		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
// 		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

// 		let mut test_rng = rand::thread_rng();
// 		let (_, _, leaf0) = leaf_data(&mut test_rng, &h);
// 		let (_, _, leaf1) = leaf_data(&mut test_rng, &h);
// 		let (_, _, leaf2) = leaf_data(&mut test_rng, &h);
// 		let (_, _, leaf3) = leaf_data(&mut test_rng, &h);
// 		let (_, _, leaf4) = leaf_data(&mut test_rng, &h);
// 		let (s, nullifier, leaf5) = leaf_data(&mut test_rng, &h);
// 		let (_, _, leaf6) = leaf_data(&mut test_rng, &h);

// 		assert_ok!(MerkleGroups::create_group(
// 			Origin::signed(1),
// 			false,
// 			Some(3),
// 		));
// 		assert_ok!(MerkleGroups::add_members(
// 			Origin::signed(1),
// 			0,
// 			vec![leaf0, leaf1, leaf2, leaf3, leaf4, leaf5, leaf6]
// 		));

// 		let (s_com, leaf_com5, leaf_var5) =
// 			commit_leaf(&mut test_rng, &mut prover, leaf5, s, nullifier, &h);

// 		let node0_0 = Data::hash(leaf0, leaf1, &h);
// 		let node0_1 = Data::hash(leaf2, leaf3, &h);
// 		let node0_2 = Data::hash(leaf4, leaf5, &h);
// 		let node0_3 = Data::hash(leaf6, leaf6, &h);

// 		let node1_0 = Data::hash(node0_0, node0_1, &h);
// 		let node1_1 = Data::hash(node0_2, node0_3, &h);

// 		let root = Data::hash(node1_0, node1_1, &h);

// 		let (bit_com0, node_com0, node_con0) =
// 			commit_path_level(&mut test_rng, &mut prover, leaf4, leaf_var5.into(), 1, &h);
// 		let (bit_com1, node_com1, node_con1) =
// 			commit_path_level(&mut test_rng, &mut prover, node0_3, node_con0, 0, &h);
// 		let (bit_com2, node_com2, node_con2) =
// 			commit_path_level(&mut test_rng, &mut prover, node1_0, node_con1, 1, &h);
// 		prover.constrain(node_con2 - root.0);

// 		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

// 		let path = vec![
// 			(Commitment(bit_com0), Commitment(node_com0)),
// 			(Commitment(bit_com1), Commitment(node_com1)),
// 			(Commitment(bit_com2), Commitment(node_com2)),
// 		];

// 		let root = MerkleGroups::get_merkle_root(0);
// 		assert_ok!(<MerkleGroups>::verify_zk_membership_proof(
// 			0,
// 			0,
// 			root.unwrap(),
// 			Commitment(leaf_com5),
// 			path,
// 			Commitment(s_com),
// 			Data(nullifier),
// 			proof.to_bytes(),
// 		));
// 	});
// }

// #[test]
// fn should_verify_large_zk_proof_of_membership() {
// 	new_test_ext().execute_with(|| {
// 		let h = default_hasher();
// 		let pc_gens = PedersenGens::default();
// 		let bp_gens = BulletproofGens::new(4096, 1);

// 		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
// 		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

// 		let mut test_rng = rand::thread_rng();
// 		let (s, nullifier, leaf) = leaf_data(&mut test_rng, &h);

// 		assert_ok!(MerkleGroups::create_group(
// 			Origin::signed(1),
// 			false,
// 			Some(32),
// 		));
// 		assert_ok!(MerkleGroups::add_members(Origin::signed(1), 0, vec![leaf]));

// 		let (s_com, leaf_com1, leaf_var1) =
// 			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier, &h);

// 		let mut lh = leaf;
// 		let mut lh_lc: LinearCombination = leaf_var1.into();
// 		let mut path = Vec::new();
// 		for _ in 0..32 {
// 			let (bit_com, leaf_com, node_con) =
// 				commit_path_level(&mut test_rng, &mut prover, lh, lh_lc, 1, &h);
// 			lh_lc = node_con;
// 			lh = Data::hash(lh, lh, &h);
// 			path.push((Commitment(bit_com), Commitment(leaf_com)));
// 		}
// 		prover.constrain(lh_lc - lh.0);

// 		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

// 		let root = MerkleGroups::get_merkle_root(0);
// 		assert_ok!(<MerkleGroups>::verify_zk_membership_proof(
// 			0,
// 			0,
// 			root.unwrap(),
// 			Commitment(leaf_com1),
// 			path,
// 			Commitment(s_com),
// 			Data(nullifier),
// 			proof.to_bytes(),
// 		));
// 	});
// }
