#![cfg_attr(not(feature = "std"), no_std)]

/// A runtime module Groups with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references


/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

pub mod constants;
pub mod keys;
pub mod signature;
pub mod member;
pub mod transcript;
pub mod clsag;

#[cfg(feature="std")]
pub mod tests_helper;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

use sha2::Sha512;
use crate::transcript::TranscriptProtocol;
use crate::constants::BASEPOINT;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use merlin::Transcript;

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, ensure};
use frame_system::{self as system, ensure_signed};
use sp_std::prelude::*;

pub type MerkleLeaf = keys::PublicKey;
// pub type MerkleLeaf = [u8;32];

/// The pallet's configuration trait.
pub trait Trait: frame_system::Trait {
	// Add other types and constants required to configure this pallet.

	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

type GroupId = u32;

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as Groups {
		Groups get(fn groups): map hasher(blake2_256) GroupId => Option<Vec<MerkleLeaf>>;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		NewMember(u32, AccountId, MerkleLeaf),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Value was None
		NoneValue,
		/// 
		IncorrectNumOfPubKeys,
		///
		ChallengeMismatch,
		///
		BadPoint,
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		pub fn add_member(origin, group_id: u32, pub_key: MerkleLeaf) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let who = ensure_signed(origin)?;

			// Code to execute when something calls this.
			// For example: the following line stores the passed in u32 in the storage
			let mut group = {
				match Self::groups(group_id) {
					Some(g) => g,
					None => vec![],
				}
			};
			// add new member
			group.push(pub_key.clone());
			<Groups>::insert(group_id, group);

			// Here we are raising the Something event
			Self::deposit_event(RawEvent::NewMember(group_id, who, pub_key));
			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn get_members(group_id: u32) -> Option<Vec<MerkleLeaf>> {
		return <Groups>::get(group_id);
	}
}
