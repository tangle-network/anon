// Tests to be written here

use crate::merkle::keys::{Commitment, Data};
use crate::merkle::poseidon::Poseidon;
use crate::mock::*;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use frame_support::{assert_err, assert_ok};
use merlin::Transcript;
use rand::rngs::ThreadRng;

fn key_bytes(x: u8) -> [u8; 32] {
	[
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, x,
	]
}

fn leaf_data_mimc(rng: &mut ThreadRng) -> (Scalar, Scalar, Data) {
	let s = Scalar::random(rng);
	let nullifier = Scalar::random(rng);
	let leaf = Data::hash_mimc(Data(s), Data(nullifier));
	(s, nullifier, leaf)
}

fn leaf_data_poseidon(rng: &mut ThreadRng, p: &Poseidon) -> (Scalar, Scalar, Data) {
	let s = Scalar::random(rng);
	let nullifier = Scalar::random(rng);
	let leaf = Data::hash_poseidon(Data(s), Data(nullifier), p);
	(s, nullifier, leaf)
}

fn commit_leaf(
	rng: &mut ThreadRng,
	prover: &mut Prover,
	leaf: Data,
	s: Scalar,
	nullifier: Scalar,
) -> (CompressedRistretto, CompressedRistretto, Variable) {
	let (leaf_com1, leaf_var1) = prover.commit(leaf.0, Scalar::random(rng));
	let (s_com, s_var) = prover.commit(s, Scalar::random(rng));
	let leaf_com = Data::constrain_mimc(prover, s_var.into(), nullifier.into());
	prover.constrain(leaf_com - leaf_var1);
	(s_com, leaf_com1, leaf_var1)
}

fn commit_leaf_poseidon(
	rng: &mut ThreadRng,
	prover: &mut Prover,
	leaf: Data,
	s: Scalar,
	nullifier: Scalar,
	p: &Poseidon,
) -> (CompressedRistretto, CompressedRistretto, Variable) {
	let (leaf_com1, leaf_var1) = prover.commit(leaf.0, Scalar::random(rng));
	let (s_com, s_var) = prover.commit(s, Scalar::random(rng));
	let leaf_com = Data::constrain_poseidon_prover(prover, s_var.into(), nullifier.into(), p);
	prover.constrain(leaf_com - leaf_var1);
	(s_com, leaf_com1, leaf_var1)
}

fn commit_path_level(
	rng: &mut ThreadRng,
	prover: &mut Prover,
	leaf: Data,
	pair: LinearCombination,
	bit: u8,
) -> (CompressedRistretto, CompressedRistretto, LinearCombination) {
	let (bit_com, bit_var) = prover.commit(Scalar::from(bit), Scalar::random(rng));
	let (node_com, node_var) = prover.commit(leaf.0, Scalar::random(rng));

	let side: LinearCombination = Variable::One() - bit_var;

	let (_, _, left1) = prover.multiply(bit_var.into(), pair.clone());
	let (_, _, left2) = prover.multiply(side.clone(), node_var.into());
	let left = left1 + left2;

	let (_, _, right1) = prover.multiply(side, pair);
	let (_, _, right2) = prover.multiply(bit_var.into(), node_var.into());
	let right = right1 + right2;

	let node_con = Data::constrain_mimc(prover, left, right);
	(bit_com, node_com, node_con)
}

fn commit_path_level_poseidon(
	rng: &mut ThreadRng,
	prover: &mut Prover,
	leaf: Data,
	pair: LinearCombination,
	bit: u8,
	p: &Poseidon,
) -> (CompressedRistretto, CompressedRistretto, LinearCombination) {
	let (bit_com, bit_var) = prover.commit(Scalar::from(bit), Scalar::random(rng));
	let (node_com, node_var) = prover.commit(leaf.0, Scalar::random(rng));

	let side: LinearCombination = Variable::One() - bit_var;

	let (_, _, left1) = prover.multiply(bit_var.into(), pair.clone());
	let (_, _, left2) = prover.multiply(side.clone(), node_var.into());
	let left = left1 + left2;

	let (_, _, right1) = prover.multiply(side, pair);
	let (_, _, right2) = prover.multiply(bit_var.into(), node_var.into());
	let right = right1 + right2;

	let node_con = Data::constrain_poseidon_prover(prover, left, right, p);
	(bit_com, node_com, node_con)
}

#[test]
fn can_create_group() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(3),
		));
	});
}

#[test]
fn can_add_member() {
	new_test_ext().execute_with(|| {
		let key = Data::new(key_bytes(1));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(3),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key.clone()));
	});
}

#[test]
fn should_not_have_0_depth() {
	new_test_ext().execute_with(|| {
		assert_err!(
			MerkleGroups::create_group(Origin::signed(1), 0, Some(10), Some(0),),
			"Invalid tree depth."
		);
	});
}

#[test]
fn should_have_min_depth() {
	new_test_ext().execute_with(|| {
		let key = Data::new(key_bytes(1));
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(1),
		));

		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key.clone()));
		assert_err!(
			MerkleGroups::add_member(Origin::signed(1), 0, key.clone()),
			"Exceeded maximum tree depth."
		);
	});
}

#[test]
fn should_have_max_depth() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(32),
		));
	});
}

#[test]
fn should_not_have_more_than_max_depth() {
	new_test_ext().execute_with(|| {
		assert_err!(
			MerkleGroups::create_group(Origin::signed(1), 0, Some(10), Some(33),),
			"Invalid tree depth."
		);
	});
}

#[test]
fn should_not_use_existing_group_id() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(3),
		));
		assert_err!(
			MerkleGroups::create_group(Origin::signed(1), 0, Some(10), Some(3),),
			"Group already exists."
		);
	});
}

#[test]
fn should_have_correct_root_hash_after_insertion() {
	new_test_ext().execute_with(|| {
		let key0 = Data::new(key_bytes(0));
		let key1 = Data::new(key_bytes(1));
		let key2 = Data::new(key_bytes(2));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(2),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()));

		let keyh1 = Data::hash_mimc(key0, key0);
		let keyh2 = Data::hash_mimc(keyh1, keyh1);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleGroups::add_member(Origin::signed(2), 0, key1.clone()));

		let keyh1 = Data::hash_mimc(key0, key1);
		let keyh2 = Data::hash_mimc(keyh1, keyh1);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleGroups::add_member(Origin::signed(3), 0, key2.clone()));

		let keyh1 = Data::hash_mimc(key0, key1);
		let keyh2 = Data::hash_mimc(key2, key2);
		let keyh3 = Data::hash_mimc(keyh1, keyh2);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh3, "Invalid root hash");
	});
}

#[test]
fn should_have_correct_root_hash() {
	new_test_ext().execute_with(|| {
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(Data::new(key_bytes(i as u8)))
		}

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(4),
		));

		for i in 0..15 {
			assert_ok!(MerkleGroups::add_member(
				Origin::signed(i),
				0,
				keys[i as usize]
			));
		}

		let key1_1 = Data::hash_mimc(keys[0], keys[1]);
		let key1_2 = Data::hash_mimc(keys[2], keys[3]);
		let key1_3 = Data::hash_mimc(keys[4], keys[5]);
		let key1_4 = Data::hash_mimc(keys[6], keys[7]);
		let key1_5 = Data::hash_mimc(keys[8], keys[9]);
		let key1_6 = Data::hash_mimc(keys[10], keys[11]);
		let key1_7 = Data::hash_mimc(keys[12], keys[13]);
		let key1_8 = Data::hash_mimc(keys[14], keys[14]);

		let key2_1 = Data::hash_mimc(key1_1, key1_2);
		let key2_2 = Data::hash_mimc(key1_3, key1_4);
		let key2_3 = Data::hash_mimc(key1_5, key1_6);
		let key2_4 = Data::hash_mimc(key1_7, key1_8);

		let key3_1 = Data::hash_mimc(key2_1, key2_2);
		let key3_2 = Data::hash_mimc(key2_3, key2_4);

		let root_hash = Data::hash_mimc(key3_1, key3_2);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, root_hash, "Invalid root hash");
	});
}

#[test]
fn should_be_unable_to_pass_proof_path_with_invalid_length() {
	new_test_ext().execute_with(|| {
		let key0 = Data::new(key_bytes(0));
		let key1 = Data::new(key_bytes(1));
		let key2 = Data::new(key_bytes(2));
		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(2),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(0), 0, key0.clone()));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key1.clone()));
		assert_ok!(MerkleGroups::add_member(Origin::signed(2), 0, key2.clone()));

		let path = vec![(true, key0)];
		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			"Invalid path length."
		);

		let path = vec![(true, key0), (false, key1), (true, key2)];
		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			"Invalid path length."
		);
	});
}

#[test]
fn should_not_verify_invalid_proof() {
	new_test_ext().execute_with(|| {
		let key0 = Data::new(key_bytes(0));
		let key1 = Data::new(key_bytes(1));
		let key2 = Data::new(key_bytes(2));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(2),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()));
		assert_ok!(MerkleGroups::add_member(Origin::signed(2), 0, key1.clone()));
		assert_ok!(MerkleGroups::add_member(Origin::signed(3), 0, key2.clone()));

		let keyh1 = Data::hash_mimc(key0, key1);
		let keyh2 = Data::hash_mimc(key2, key2);
		let _root_hash = Data::hash_mimc(keyh1, keyh2);

		let path = vec![(false, key1), (true, keyh2)];

		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			"Invalid proof of membership."
		);

		let path = vec![(true, key1), (false, keyh2)];

		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			"Invalid proof of membership."
		);

		let path = vec![(true, key2), (true, keyh1)];

		assert_err!(
			MerkleGroups::verify(Origin::signed(2), 0, key0, path),
			"Invalid proof of membership."
		);
	});
}

#[test]
fn should_verify_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(Data::new(key_bytes(i as u8)))
		}

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(4),
		));

		for i in 0..15 {
			assert_ok!(MerkleGroups::add_member(
				Origin::signed(i),
				0,
				keys[i as usize]
			));
		}

		let key1_1 = Data::hash_mimc(keys[0], keys[1]);
		let key1_2 = Data::hash_mimc(keys[2], keys[3]);
		let key1_3 = Data::hash_mimc(keys[4], keys[5]);
		let key1_4 = Data::hash_mimc(keys[6], keys[7]);
		let key1_5 = Data::hash_mimc(keys[8], keys[9]);
		let key1_6 = Data::hash_mimc(keys[10], keys[11]);
		let key1_7 = Data::hash_mimc(keys[12], keys[13]);
		let key1_8 = Data::hash_mimc(keys[14], keys[14]);

		let key2_1 = Data::hash_mimc(key1_1, key1_2);
		let key2_2 = Data::hash_mimc(key1_3, key1_4);
		let key2_3 = Data::hash_mimc(key1_5, key1_6);
		let key2_4 = Data::hash_mimc(key1_7, key1_8);

		let key3_1 = Data::hash_mimc(key2_1, key2_2);
		let key3_2 = Data::hash_mimc(key2_3, key2_4);

		let _root_hash = Data::hash_mimc(key3_1, key3_2);

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
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut test_rng = rand::thread_rng();
		let (s, nullifier, leaf) = leaf_data_mimc(&mut test_rng);

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(1),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf));

		let (s_com, leaf_com1, leaf_var1) =
			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier);

		let root = Data::hash_mimc(leaf, leaf);
		let (bit_com, leaf_com2, root_con) =
			commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1);
		prover.constrain(root_con - root.0);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

		let path = vec![(Commitment(bit_com), Commitment(leaf_com2))];

		assert_ok!(MerkleGroups::verify_zk_membership_proof(
			Origin::signed(1),
			0,
			Commitment(leaf_com1),
			path,
			Commitment(s_com),
			Data(nullifier),
			proof.to_bytes(),
		));
	});
}

#[test]
fn should_not_use_nullifier_more_than_once() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut test_rng = rand::thread_rng();
		let (s, nullifier, leaf) = leaf_data_mimc(&mut test_rng);

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(1),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf));

		let (s_com, leaf_com1, leaf_var1) =
			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier);

		let root = Data::hash_mimc(leaf, leaf);
		let (bit_com, leaf_com2, root_con) =
			commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1);
		prover.constrain(root_con - root.0);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

		let path = vec![(Commitment(bit_com), Commitment(leaf_com2))];

		assert_ok!(MerkleGroups::verify_zk_membership_proof(
			Origin::signed(1),
			0,
			Commitment(leaf_com1),
			path.clone(),
			Commitment(s_com),
			Data(nullifier),
			proof.to_bytes(),
		));
		assert_err!(
			MerkleGroups::verify_zk_membership_proof(
				Origin::signed(1),
				0,
				Commitment(leaf_com1),
				path,
				Commitment(s_com),
				Data(nullifier),
				proof.to_bytes(),
			),
			"Nullifier already used."
		);
	});
}

#[test]
fn should_not_verify_invalid_commitments_for_leaf_creation() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut test_rng = rand::thread_rng();
		let (s, nullifier, leaf) = leaf_data_mimc(&mut test_rng);

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(1),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf));

		let (_, leaf_com1, leaf_var1) = commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier);
		let root = Data::hash_mimc(leaf, leaf);
		let (bit_com, leaf_com2, root_con) =
			commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1);
		prover.constrain(root_con - root.0);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let path = vec![(Commitment(bit_com), Commitment(leaf_com2))];

		let invalid_s_com = RistrettoPoint::random(&mut test_rng).compress();

		assert_err!(
			MerkleGroups::verify_zk_membership_proof(
				Origin::signed(1),
				0,
				Commitment(leaf_com1),
				path,
				Commitment(invalid_s_com),
				Data(nullifier),
				proof.to_bytes(),
			),
			"Invalid proof of membership or leaf creation."
		);
	});
}

#[test]
fn should_not_verify_invalid_commitments_for_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut test_rng = rand::thread_rng();
		let (s, nullifier, leaf) = leaf_data_mimc(&mut test_rng);

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(1),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf));

		let (s_com, leaf_com1, leaf_var1) =
			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier);

		let _ = commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let invalid_path_com = RistrettoPoint::random(&mut test_rng).compress();
		let invalid_bit_com = RistrettoPoint::random(&mut test_rng).compress();
		let path = vec![(Commitment(invalid_bit_com), Commitment(invalid_path_com))];

		assert_err!(
			MerkleGroups::verify_zk_membership_proof(
				Origin::signed(1),
				0,
				Commitment(leaf_com1),
				path,
				Commitment(s_com),
				Data(nullifier),
				proof.to_bytes(),
			),
			"Invalid proof of membership or leaf creation."
		);
	});
}

#[test]
fn should_not_verify_invalid_transcript() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"invalid transcript");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut test_rng = rand::thread_rng();
		let (s, nullifier, leaf) = leaf_data_mimc(&mut test_rng);

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(1),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf));

		let (s_com, leaf_com1, leaf_var1) =
			commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier);

		let root = Data::hash_mimc(leaf, leaf);
		let (bit_com, leaf_com2, root_con) =
			commit_path_level(&mut test_rng, &mut prover, leaf, leaf_var1.into(), 1);
		prover.constrain(root_con - root.0);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let path = vec![(Commitment(bit_com), Commitment(leaf_com2))];

		assert_err!(
			MerkleGroups::verify_zk_membership_proof(
				Origin::signed(1),
				0,
				Commitment(leaf_com1),
				path,
				Commitment(s_com),
				Data(nullifier),
				proof.to_bytes(),
			),
			"Invalid proof of membership or leaf creation."
		);
	});
}

#[test]
fn should_verify_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut test_rng = rand::thread_rng();
		let (_, _, leaf0) = leaf_data_mimc(&mut test_rng);
		let (_, _, leaf1) = leaf_data_mimc(&mut test_rng);
		let (_, _, leaf2) = leaf_data_mimc(&mut test_rng);
		let (_, _, leaf3) = leaf_data_mimc(&mut test_rng);
		let (_, _, leaf4) = leaf_data_mimc(&mut test_rng);
		let (s, nullifier, leaf5) = leaf_data_mimc(&mut test_rng);
		let (_, _, leaf6) = leaf_data_mimc(&mut test_rng);

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(3),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf0));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf1));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf2));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf3));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf4));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf5));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, leaf6));

		let (s_com, leaf_com5, leaf_var5) =
			commit_leaf(&mut test_rng, &mut prover, leaf5, s, nullifier);

		let node0_0 = Data::hash_mimc(leaf0, leaf1);
		let node0_1 = Data::hash_mimc(leaf2, leaf3);
		let node0_2 = Data::hash_mimc(leaf4, leaf5);
		let node0_3 = Data::hash_mimc(leaf6, leaf6);

		let node1_0 = Data::hash_mimc(node0_0, node0_1);
		let node1_1 = Data::hash_mimc(node0_2, node0_3);

		let root = Data::hash_mimc(node1_0, node1_1);

		let (bit_com0, node_com0, node_con0) =
			commit_path_level(&mut test_rng, &mut prover, leaf4, leaf_var5.into(), 0);
		let (bit_com1, node_com1, node_con1) =
			commit_path_level(&mut test_rng, &mut prover, node0_3, node_con0, 1);
		let (bit_com2, node_com2, node_con2) =
			commit_path_level(&mut test_rng, &mut prover, node1_0, node_con1, 0);
		prover.constrain(node_con2 - root.0);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

		let path = vec![
			(Commitment(bit_com0), Commitment(node_com0)),
			(Commitment(bit_com1), Commitment(node_com1)),
			(Commitment(bit_com2), Commitment(node_com2)),
		];

		assert_ok!(MerkleGroups::verify_zk_membership_proof(
			Origin::signed(1),
			0,
			Commitment(leaf_com5),
			path,
			Commitment(s_com),
			Data(nullifier),
			proof.to_bytes(),
		));
	});
}

#[test]
fn should_verify_simple_with_poseidon() {
	new_test_ext().execute_with(|| {
		let poseidon = Poseidon::new(6, 4, 4, 10);
		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(2048, 1);

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
	});
}
