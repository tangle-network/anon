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
pub mod tests_helper;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch};
use frame_system::{self as system, ensure_signed};
use sp_std::prelude::*;


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
		Groups get(fn groups): map hasher(blake2_256) GroupId => Option<Vec<keys::RingPublicKey>>;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		NewMember(u32, AccountId, keys::RingPublicKey),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Value was None
		NoneValue,
		/// Value reached maximum and cannot be incremented further
		StorageOverflow,
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		pub fn add_member(origin, group_id: u32, pub_key: keys::RingPublicKey) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let who = ensure_signed(origin)?;

			// Code to execute when something calls this.
			// For example: the following line stores the passed in u32 in the storage
			let mut group = <Groups>::get(group_id).unwrap_or(Vec::new());
			group.push(pub_key.clone());
			<Groups>::insert(group_id, group);

			// Here we are raising the Something event
			Self::deposit_event(RawEvent::NewMember(group_id, who, pub_key));
			Ok(())
		}

		pub fn verify_ring_sig(
			origin,
			_challenge: keys::RingScalar,
			_responses: Vec<keys::RingScalar>,
			_key_images: Vec<keys::RingPublicKey>,
		) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let _who = ensure_signed(origin)?;
			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn get_members(group_id: u32) -> Option<Vec<keys::RingPublicKey>> {
		return <Groups>::get(group_id);
	}
}
