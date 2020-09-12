// Tests to be written here

use crate::{mock::*};
use frame_support::{assert_ok};

use crate::merkle::keys::{PublicKey};


#[test]
fn can_create_group() {
	new_test_ext().execute_with(|| {
		assert_ok!(MerkleGroups::create_group(Origin::signed(1), Some(10), Some(3), None));
	});
}

#[test]
fn can_add_member() {
	new_test_ext().execute_with(|| {
		let bytes: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
		let key = PublicKey::new(bytes);

		assert_ok!(MerkleGroups::create_group(Origin::signed(1), Some(10), Some(3), None));
		assert_ok!(MerkleGroups::add_member(Origin::signed(1), 0, key.clone()));
	});	
}