// Tests to be written here

use crate::merkle::keys::Data;
use crate::mock::*;
use bulletproofs::r1cs::{ConstraintSystem, Prover};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use frame_support::{assert_err, assert_ok};
use merlin::Transcript;

fn key_bytes(x: u8) -> [u8; 32] {
	[
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, x,
	]
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
		let key = Data::new(key_bytes(0));

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
		let a = Data::zero();
		println!("{:?}", a);
		// panic!("");
	});
}

#[test]
fn should_not_verify_invalid_commitments() {
	new_test_ext().execute_with(|| {});
}

#[test]
fn should_not_verify_invalid_constraints() {
	new_test_ext().execute_with(|| {});
}

#[test]
fn should_not_verify_invalid_transcript() {
	new_test_ext().execute_with(|| {});
}

#[test]
fn should_verify_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {});
}
