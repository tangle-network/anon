// Tests to be written here

use crate::{mock::*};
use frame_support::{assert_ok};

use crate::keys::RingPublicKey;


#[test]
fn can_add_member_and_get_member() {
	new_test_ext().execute_with(|| {
		let bytes: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
		let key = RingPublicKey::new(bytes);
		// Just a dummy test for the dummy funtion `do_something`
		// calling the `do_something` function with a value 42
		assert_ok!(Groups::add_member(Origin::signed(1), 1, key.clone()));
		// asserting that the stored value is equal to what we stored
		assert_eq!(Groups::get_members(1), Some(vec![key.clone()]));
	});
}

#[test]
fn can_verify_ring_signature() {
	new_test_ext().execute_with(|| {
		let bytes: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
		let key = RingPublicKey::new(bytes);
		// Just a dummy test for the dummy funtion `do_something`
		// calling the `do_something` function with a value 42
		assert_ok!(Groups::add_member(Origin::signed(1), 1, key.clone()));
		// asserting that the stored value is equal to what we stored
		assert_eq!(Groups::get_members(1), Some(vec![key.clone()]));
	});
}
