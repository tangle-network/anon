#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

// #[cfg(feature = "runtime-benchmarks")]
// mod benchmarking;
// pub mod weights;

pub mod traits;

use webb_tokens::traits::ExtendedTokenSystem;
use codec::{Decode, Encode};
use frame_support::{dispatch, ensure, traits::Get, weights::Weight, PalletId};
use frame_system::ensure_signed;
use merkle::{
	utils::{
		keys::{Commitment, ScalarData},
		permissions::ensure_admin,
	},
	Tree as TreeTrait, Pallet as MerklePallet,
};
use webb_traits::MultiCurrency;
use sp_runtime::{
	traits::{AccountIdConversion, Zero},
};
use sp_std::prelude::*;
use sp_runtime::traits::One;
use traits::ExtendedMixer;
// use weights::WeightInfo;

pub use pallet::*;

/// Type alias for the webb_traits::MultiCurrency::Balance type
pub type BalanceOf<T> = <<T as Config>::Currency as MultiCurrency<<T as frame_system::Config>::AccountId>>::Balance;
/// Type alias for the webb_traits::MultiCurrency::CurrencyId type
pub type CurrencyIdOf<T> =
	<<T as pallet::Config>::Currency as MultiCurrency<<T as frame_system::Config>::AccountId>>::CurrencyId;


/// Implementation of Mixer pallet
#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	

	/// The pallet's configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config + webb_currencies::Config {
		#[pallet::constant]
		type PalletId: Get<PalletId>;
		/// The overarching event type.
		type Event: IsType<<Self as frame_system::Config>::Event> + From<Event<Self>>;
		/// Currency type for taking deposits
		type Currency: MultiCurrency<Self::AccountId> + ExtendedTokenSystem<Self::AccountId, CurrencyIdOf<Self>, BalanceOf<Self>>;
		/// Native currency id
		#[pallet::constant]
		type NativeCurrencyId: Get<CurrencyIdOf<Self>>;
		/// Default admin key
		#[pallet::constant]
		type DefaultAdmin: Get<Self::AccountId>;
		// /// Weight information for extrinsics in this pallet
		// type WeightInfo: WeightInfo;
	}

	/// Flag indicating if the mixer is initialized
	#[pallet::storage]
	#[pallet::getter(fn initialised)]
	pub type Initialised<T: Config> = StorageValue<_, bool, ValueQuery>;

	/// Most recent webb wrapped token id
	#[pallet::storage]
	#[pallet::getter(fn last_token_id)]
	pub type LatestTokenId<T: Config> = StorageValue<_, Option<CurrencyIdOf<T>>, ValueQuery>;

	/// Webb wrapped token ids
	#[pallet::storage]
	#[pallet::getter(fn wrapped_token_ids)]
	pub type WrappedTokenIds<T: Config> = StorageValue<_, Option<Vec<CurrencyIdOf<T>>>, ValueQuery>;

	/// Mapping of non-Webb tokens to Webb wrapped token ids
	#[pallet::storage]
	#[pallet::getter(fn wrapped_token_registry)]
	pub type WrappedTokenRegistry<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		CurrencyIdOf<T>,
		CurrencyIdOf<T>,
	>;

	/// Mapping of Webb wrapped tokens to non-Webb token ids
	#[pallet::storage]
	#[pallet::getter(fn is_wrapped_token)]
	pub type ReverseWrappedTokenRegistry<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		CurrencyIdOf<T>,
		Vec<CurrencyIdOf<T>>,
	>;

	/// Administrator of the mixer pallet.
	/// This account that can stop/start operations of the mixer
	#[pallet::storage]
	#[pallet::getter(fn admin)]
	pub type Admin<T: Config> = StorageValue<_, T::AccountId, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	#[pallet::metadata(T::AccountId = "AccountId", BalanceOf<T> = "Balance")]
	pub enum Event<T: Config> {
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Value was None
		NoneValue,
		///
		AlreadyInitialised,
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(5_000_000)]
		pub fn wrap(
			origin: OriginFor<T>,
			currency_id: CurrencyIdOf<T>,
			amount: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(T::Currency::exists(currency_id) || currency_id == T::NativeCurrencyId::get(), Error::<T>::NoneValue);
			if let Some(wrapped_currency_id) = WrappedTokenRegistry::<T>::get(currency_id) {
				// transfer original token to bridge
				<T::Currency as MultiCurrency<_>>::transfer(
					currency_id,
					&sender,
					&Self::account_id(),
					amount
				)?;
				// mint webb wrapped token
				<T::Currency as ExtendedTokenSystem<_,_,_>>::mint(
					wrapped_currency_id,
					sender,
					amount
				)?;
			} else {
				let last_token_id_option = Self::last_token_id();
				if let Some(last_token_id) = last_token_id_option {
					let mut temp_id = <T::Currency as ExtendedTokenSystem<_,_,_>>::increment(last_token_id);
					while <T::Currency as ExtendedTokenSystem<_,_,_>>::exists(temp_id) {
						temp_id = <T::Currency as ExtendedTokenSystem<_,_,_>>::increment(temp_id);
					}
					<T::Currency as ExtendedTokenSystem<_, _, _>>::create(
						temp_id,
						Self::account_id(),
						Self::account_id(),
						One::one(), // min_balance for the token, use smallest value
					)?;

					ReverseWrappedTokenRegistry::<T>::insert(temp_id, currency_id);
				}
			}
			Ok(().into())
		}

		#[pallet::weight(5_000_000)]
		pub fn unwrap(
			origin: OriginFor<T>,
			currency_id: CurrencyIdOf<T>,
			amount: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(T::Currency::exists(currency_id) || currency_id == T::NativeCurrencyId::get(), Error::<T>::NoneValue);
			ensure!(ReverseWrappedTokenRegistry::<T>::contains_key(currency_id), Error::<T>::NoneValue);
			if let Some(unwrapped_currency_id) = ReverseWrappedTokenRegistry::<T>::get(currency_id) {
				// transfer original token from bridge to sender
				<T::Currency as MultiCurrency<_>>::transfer(
					unwrapped_currency_id,
					&Self::account_id(),
					&sender,
					amount
				)?;
				// burn webb wrapped token
				<T::Currency as ExtendedTokenSystem<_,_,_>>::burn(
					wrapped_currency_id,
					sender,
					amount
				)?;
			}
			Ok(().into())
		}

		#[pallet::weight(5_000_000)]
		pub fn deposit(
			origin: OriginFor<T>,
			currency_id: CurrencyIdOf<T>,
			amount: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			// ensure token exists
			ensure!(T::Currency::exists(currency_id), Error::<T>::NoneValue);
			// ensure token is a webb wrapped token
			ensure!(IsWrappedToken::<T>::contains_key(currency_id), Error::<T>::NoneValue);
			Ok(().into())
		}

		/// Transfers the admin from the caller to the specified `to` account.
		/// Can only be called by the current admin or the root origin.
		///
		/// Weights:
		/// - Independent of the arguments.
		///
		/// - Base weight: 7_000_000
		/// - DB weights: 1 read, 1 write
		#[pallet::weight(5_000_000)]
		pub fn transfer_admin(origin: OriginFor<T>, to: T::AccountId) -> DispatchResultWithPostInfo {
			// Ensures that the caller is the root or the current admin
			ensure_admin(origin, &Self::admin())?;
			// Updating the admin
			Admin::<T>::set(to);
			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn account_id() -> T::AccountId {
		T::PalletId::get().into_account()
	}

	pub fn initialize() -> dispatch::DispatchResult {
		ensure!(!Self::initialised(), Error::<T>::AlreadyInitialised);

		// Get default admin from trait params
		let default_admin = T::DefaultAdmin::get();
		// Initialize the admin in storage with default one
		Admin::<T>::set(default_admin);
		Initialised::<T>::set(true);
		Ok(())
	}
}
