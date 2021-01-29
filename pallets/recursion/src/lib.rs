#![cfg_attr(not(feature = "std"), no_std)]

/// A runtime module Groups with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references

/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

mod types;

use sp_runtime::traits::One;
use sp_runtime::traits::AccountIdConversion;
use sp_runtime::ModuleId;

use frame_support::traits::{Currency, Get, ExistenceRequirement::{AllowDeath}};

use codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use sp_std::prelude::*;

pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

/// The pallet's configuration trait.
pub trait Config: frame_system::Config {
	type ModuleId: Get<ModuleId>;
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
	/// Currency type for taking deposits
	type Currency: Currency<Self::AccountId>;
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Config> as New {
		pub Initialised get(fn initialised): bool;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Config>::AccountId {
		Deposit(AccountId),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Config> {
		/// Value was None
		NoneValue,
	}
}

decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 0]
		pub fn deposit(origin) -> dispatch::DispatchResult {
			Ok(())
		}
	}
}

impl<T: Config> Module<T> {
	pub fn account_id() -> T::AccountId {
		T::ModuleId::get().into_account()
	}
}
