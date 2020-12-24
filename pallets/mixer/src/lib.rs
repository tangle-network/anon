#![cfg_attr(not(feature = "std"), no_std)]

/// A runtime module Groups with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references

/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

use pallet_merkle::merkle::keys::Data;
use sp_runtime::traits::One;
use frame_support::traits::Get;
use sp_runtime::traits::AtLeast32Bit;
use frame_support::Parameter;
use codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use sp_std::prelude::*;

/// The pallet's configuration trait.
pub trait Config: pallet_merkle::Config {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
	/// The overarching group ID type
	type MixerId: Self::GroupId;
}


#[derive(Encode, Decode, PartialEq, Debug)]
struct MixerInfo<T: Config> {
	pub minimum_deposit_length_for_reward: T::BlockNumber,
	pub fixed_deposit_size: T::Balance,
	pub leaves: Vec<Data>,
}


impl<T: Config> MixerInfo<T> {
	pub fn new(mgr: T::AccountId, min_dep_length: T::BlockNumber, dep_size: T::Balance, leaves: Vec<Data>) -> Self {
		Self {
			minimum_deposit_length_for_reward: min_dep_length,
			fixed_deposit_size: dep_size,
			leaves: leaves,
		}
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Config> as MerkleGroups {
		pub Initialised: bool;
		/// The map of mixer groups to their metadata
		pub MixerGroups get(fn mixer_groups): map hasher(blake2_128_concat) T::MixerId => MixerInfo<T>;
		/// Map of used nullifiers (Data) for each tree.
		pub UsedNullifiers get(fn used_nullifiers): map hasher(blake2_128_concat) (T::MixerId, Data) => bool;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T>
	where
		AccountId = <T as frame_system::Config>::AccountId,
		MixerId = <T as Config>::MixerId,
		Nullifier = Data,
	{
		Deposit(MixerId, AccountId, Nullifier),
		Withdraw(MixerId, AccountId, Nullifier),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Config> {
		/// Value was None
		NoneValue,
		///
		AlreadyInitialized,
		///
		MixerDoesntExist,
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;


		#[weight = 0]
		pub fn deposit(origin, mixer_id: T::GroupId, data_points: Vec<Data>) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			let mixer = MixerGroups::<T>::get(mixer_id)?;
			Ok(())
		}

		/// Verification stub for testing, these verification functions should
		/// not need to be used directly as extrinsics. Rather, higher-order
		/// modules should use the module functions to verify and execute further
		/// logic.
		#[weight = 0]
		pub fn withdraw(origin, group_id: T::GroupId, leaf: Data, path: Vec<(bool, Data)>) -> dispatch::DispatchResult {

			Ok(())
		}

		#[weight = 0]
		pub fn initialise(origin) -> dispatch::DispatchResult {
			ensure!(!Initialised, Error::<T>::AlreadyInitialized);
			let sender = ensure_signed(origin)?;
			Initialised::set(true);
			// create small mixer
			
			// create medium mixer
			// create large mixer
			// create largest mixer
			Ok(())
		}
	}
}

impl<T: Config> Module<T> {
}
