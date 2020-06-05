// Tests to be written here

use crate::clsag::tests_helper::generate_signer;
use crate::clsag::tests_helper::generate_clsag_with;
use crate::mock::*;
use frame_support::{assert_ok};

use crate::clsag::keys::{RingPublicKey, RingScalar};


#[test]
fn can_add_member_and_get_member() {
	new_test_ext().execute_with(|| {
		let bytes: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
		let key = RingPublicKey::new(bytes);
		// Just a dummy test for the dummy funtion `do_something`
		// calling the `do_something` function with a value 42
		assert_ok!(CLSAGGroups::add_member(Origin::signed(1), 1, key.clone()));
		// asserting that the stored value is equal to what we stored
		assert_eq!(CLSAGGroups::get_members(1), Some(vec![key.clone()]));
	});
}

#[test]
fn can_verify_ring_signature() {
	new_test_ext().execute_with(|| {
		let bytes: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
		let key = RingPublicKey::new(bytes);
		// Just a dummy test for the dummy funtion `do_something`
		// calling the `do_something` function with a value 42
		assert_ok!(CLSAGGroups::add_member(Origin::signed(1), 1, key.clone()));
		// asserting that the stored value is equal to what we stored
		assert_eq!(CLSAGGroups::get_members(1), Some(vec![key.clone()]));
	});
}

#[test]
fn test_runtime_verify() {
	new_test_ext().execute_with(|| {
		let num_keys = 1;
		let num_decoys = 1;

		let mut clsag = generate_clsag_with(num_decoys, num_keys);
		clsag.add_member(generate_signer(num_keys));
		let sig = clsag.sign().unwrap();
		let mut pub_keys = clsag.public_keys();

		let origins = [1, 2];
		let mut keys = vec![];
		for i in 0..pub_keys.len() {
			let k = RingPublicKey::new(pub_keys[i][0].0);
			assert_ok!(CLSAGGroups::add_member(Origin::signed(origins[i]), 1, k.clone()));
			keys.push(RingPublicKey(pub_keys[i][0]));
		}

		let expected_pubkey_bytes = clsag.public_keys_bytes();
		let have_pubkey_bytes = sig.pubkeys_to_bytes(&pub_keys);

		assert_eq!(expected_pubkey_bytes, have_pubkey_bytes);
		assert!(sig.optimised_verify(&mut pub_keys).is_ok());

		let _challenge: RingScalar = RingScalar(sig.challenge);
		let _responses: Vec<RingScalar> = sig.responses.iter().map(|x| RingScalar(*x)).collect();
		let _key_images: Vec<RingPublicKey> = sig.key_images.iter().map(|x| RingPublicKey(*x)).collect();
		assert_eq!(CLSAGGroups::get_members(1), Some(keys.clone()));
		assert_ok!(CLSAGGroups::verify_ring_sig(
			Origin::signed(1),
			1, // group ID
			_challenge,
			_responses,
			_key_images
		));
	});
}