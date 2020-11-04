// Tests to be written here

use crate::mock::*;
use frame_support::{assert_err, assert_ok};

use crate::merkle::keys::PublicKey;

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
		let key = PublicKey::new(&key_bytes(1));

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
fn should_reach_max_depth() {
	new_test_ext().execute_with(|| {
		let key0 = PublicKey::new(&key_bytes(0));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(3),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()));
		assert_err!(
			MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()),
			"Exceeded maximum tree depth."
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
fn should_have_correct_root_hash() {
	new_test_ext().execute_with(|| {
		let key0 = PublicKey::new(&key_bytes(0));
		let key1 = PublicKey::new(&key_bytes(1));
		let key2 = PublicKey::new(&key_bytes(2));
		let key3 = PublicKey::new(&key_bytes(3));

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(3),
		));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key0.clone()));

		let keyh1 = MerkleGroups::hash_leaves(key0, key0);
		let keyh2 = MerkleGroups::hash_leaves(keyh1, keyh1);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleGroups::add_member(Origin::signed(2), 0, key1.clone()));

		let keyh1 = MerkleGroups::hash_leaves(key0, key1);
		let keyh2 = MerkleGroups::hash_leaves(keyh1, keyh1);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleGroups::add_member(Origin::signed(3), 0, key2.clone()));

		let keyh1 = MerkleGroups::hash_leaves(key0, key1);
		let keyh2 = MerkleGroups::hash_leaves(key2, key2);
		let keyh3 = MerkleGroups::hash_leaves(keyh1, keyh2);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh3, "Invalid root hash");

		assert_ok!(MerkleGroups::add_member(Origin::signed(4), 0, key3.clone()));

		let keyh1 = MerkleGroups::hash_leaves(key0, key1);
		let keyh2 = MerkleGroups::hash_leaves(key2, key3);
		let keyh3 = MerkleGroups::hash_leaves(keyh1, keyh2);

		let tree = MerkleGroups::groups(0).unwrap();

		assert_eq!(tree.root_hash, keyh3, "Invalid root hash");
	});
}

#[test]
fn should_have_correct_root_hash2() {
	new_test_ext().execute_with(|| {
		let mut keys = Vec::new();
		for i in 0..16 {
			keys.push(PublicKey::new(&key_bytes(i as u8)))
		}

		assert_ok!(MerkleGroups::create_group(
			Origin::signed(1),
			0,
			Some(10),
			Some(5),
		));

		for i in 0..16 {
			assert_ok!(MerkleGroups::add_member(
				Origin::signed(i),
				0,
				keys[i as usize]
			));
		}

		let key1_1 = MerkleGroups::hash_leaves(keys[0], keys[1]);
		let key1_2 = MerkleGroups::hash_leaves(keys[2], keys[3]);
		let key1_3 = MerkleGroups::hash_leaves(keys[4], keys[5]);
		let key1_4 = MerkleGroups::hash_leaves(keys[6], keys[7]);
		let key1_5 = MerkleGroups::hash_leaves(keys[8], keys[9]);
		let key1_6 = MerkleGroups::hash_leaves(keys[10], keys[11]);
		let key1_7 = MerkleGroups::hash_leaves(keys[12], keys[13]);
		let key1_8 = MerkleGroups::hash_leaves(keys[14], keys[15]);

		let key2_1 = MerkleGroups::hash_leaves(key1_1, key1_2);
		let key2_2 = MerkleGroups::hash_leaves(key1_3, key1_4);
		let key2_3 = MerkleGroups::hash_leaves(key1_5, key1_6);
		let key2_4 = MerkleGroups::hash_leaves(key1_7, key1_8);

		let key3_1 = MerkleGroups::hash_leaves(key2_1, key2_2);
		let key3_2 = MerkleGroups::hash_leaves(key2_3, key2_4);

		let root_hash = MerkleGroups::hash_leaves(key3_1, key3_2);

		let tree = MerkleGroups::groups(0).unwrap();
		assert_eq!(tree.root_hash, root_hash, "Invalid root hash");
	});
}
