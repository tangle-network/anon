#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

pub mod traits;
pub use traits::*;

use webb_tokens::traits::ExtendedTokenSystem;
use codec::{Decode, Encode};
use frame_support::{dispatch, ensure, traits::Get, PalletId};
use frame_system::ensure_signed;
use pallet_merkle::{
	utils::{
		keys::{Commitment, ScalarData},
		permissions::ensure_admin,
	},
	Tree as TreeTrait,
};
use webb_traits::MultiCurrency;
use sp_runtime::{
	traits::{AccountIdConversion, Zero},
};
use sp_std::prelude::*;
use sp_runtime::traits::One;
use sp_runtime::traits::AtLeast32Bit;

// use weights::WeightInfo;
pub mod types;
pub use types::*;
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
	pub trait Config: frame_system::Config + pallet_merkle::Config + webb_currencies::Config {
		#[pallet::constant]
		type PalletId: Get<PalletId>;
		/// The overarching event type.
		type Event: IsType<<Self as frame_system::Config>::Event> + From<Event<Self>>;
		/// Currency type for taking deposits
		type Currency: MultiCurrency<Self::AccountId> + ExtendedTokenSystem<Self::AccountId, CurrencyIdOf<Self>, BalanceOf<Self>>;
		/// The overarching merkle tree trait
		type ChainId: Encode + Decode + Parameter + AtLeast32Bit + Default + Copy;
		/// Scalar type for elements of trees
		type Scalar: Parameter + Member + Default + Copy + MaybeSerializeDeserialize;
		/// Signature type for threshold signatures
		type ThresholdSignature: Parameter + Member + Default + Copy + MaybeSerializeDeserialize;
		/// Native currency id
		#[pallet::constant]
		type NativeCurrencyId: Get<CurrencyIdOf<Self>>;
		/// Default admin key
		#[pallet::constant]
		type DefaultAdmin: Get<Self::AccountId>;
		/// The overarching merkle tree trait
		type Tree: TreeTrait<Self::AccountId, Self::BlockNumber, Self::TreeId>;
	}

	/// The map of mixer trees to their metadata
	#[pallet::storage]
	#[pallet::getter(fn anchors)]
	pub type Anchors<T: Config> = StorageMap<_, Blake2_128Concat, T::TreeId, AnchorInfo<T>, ValueQuery>;

	/// The map of mixer trees to their metadata
	#[pallet::storage]
	#[pallet::getter(fn anchor_edges)]
	pub type AnchorEdges<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::TreeId,
		Blake2_128Concat,
		T::ChainId,
		T::Scalar,
		ValueQuery>;

	/// The vector of tree ids on the bridge ids
	#[pallet::storage]
	#[pallet::getter(fn bridge_tree_ids)]
	pub type BridgeTreeIds<T: Config> = StorageValue<_, Vec<T::TreeId>, ValueQuery>;

	/// Flag indicating if the mixer is initialized
	#[pallet::storage]
	#[pallet::getter(fn initialised)]
	pub type Initialised<T: Config> = StorageValue<_, bool, ValueQuery>;

	/// Most recent webb wrapped token id
	#[pallet::storage]
	#[pallet::getter(fn last_token_id)]
	pub type LatestTokenId<T: Config> = StorageValue<_, Option<CurrencyIdOf<T>>, ValueQuery>;

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
	#[pallet::metadata(T::AccountId = "AccountId", T::TreeId = "TreeId", BalanceOf<T> = "Balance")]
	pub enum Event<T: Config> {
		/// New deposit added to the specific mixer
		Deposit(
			/// Id of the tree
			T::TreeId,
			/// Account id of the sender
			T::AccountId,
			/// Deposit size
			BalanceOf<T>,
		),
		/// Withdrawal from the specific mixer
		Withdraw(
			/// Id of the tree
			T::TreeId,
			/// Account id of the sender
			T::AccountId,
			/// Account id of the recipient
			T::AccountId,
			/// Account id of the relayer
			T::AccountId,
			/// Merkle root
			ScalarData,
		),
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Value was None
		NoneValue,
		/// Mixer not found for specified id
		NoMixerForId,
		/// Mixer is not initialized
		NotInitialised,
		/// Mixer is already initialized
		AlreadyInitialised,
		/// User doesn't have enough balance for the deposit
		InsufficientBalance,
		/// Caller doesn't have permission to make a call
		UnauthorizedCall,
		/// Mixer is stopped
		MixerStopped,
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
			match WrappedTokenRegistry::<T>::get(currency_id) {
				Some(wrapped_currency_id) => {
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
				},
				None => {
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

						let mut unwrapping_targets: Vec<CurrencyIdOf<T>> = ReverseWrappedTokenRegistry::<T>::get(temp_id)
							.unwrap_or_else(|| vec![]);
						unwrapping_targets.push(currency_id);
						ReverseWrappedTokenRegistry::<T>::insert(temp_id, unwrapping_targets);
					}
				}
			}

			Ok(().into())
		}

		#[pallet::weight(5_000_000)]
		pub fn unwrap(
			origin: OriginFor<T>,
			currency_id: CurrencyIdOf<T>,
			into_currency_id: CurrencyIdOf<T>,
			amount: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			// ensure token exists
			ensure!(T::Currency::exists(currency_id) || currency_id == T::NativeCurrencyId::get(), Error::<T>::NoneValue);
			// ensure token is a wrapped token
			ensure!(ReverseWrappedTokenRegistry::<T>::contains_key(currency_id), Error::<T>::NoneValue);
			if let Some(unwrapped_currency_ids) = ReverseWrappedTokenRegistry::<T>::get(currency_id) {
				ensure!(unwrapped_currency_ids.iter().any(|elt| *elt == into_currency_id), Error::<T>::NoneValue);
				// transfer original token from bridge to sender
				<T::Currency as MultiCurrency<_>>::transfer(
					into_currency_id,
					&Self::account_id(),
					&sender,
					amount
				)?;
				// burn webb wrapped token
				<T::Currency as ExtendedTokenSystem<_,_,_>>::burn(
					currency_id,
					sender,
					amount
				)?;
			}
			Ok(().into())
		}

		#[pallet::weight(5_000_000)]
		pub fn deposit(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			leaf: T::Scalar,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;

			ensure!(Self::initialised(), Error::<T>::NotInitialised);
			ensure!(!T::Tree::is_stopped(tree_id), Error::<T>::MixerStopped);

			<Self as PrivacyBridgeSystem>::deposit(sender, tree_id, leaf)?;

			Ok(().into())
		}

		/// Stops the operation of all the mixers managed by the pallet.
		/// Can only be called by the admin or the root origin.
		///
		/// Weights:
		/// - Independent of the arguments.
		///
		/// - Base weight: 36_000_000
		/// - DB weights: 6 reads, 4 writes
		#[pallet::weight(5_000_000)]
		pub fn set_stopped(origin: OriginFor<T>, stopped: bool) -> DispatchResultWithPostInfo {
			// Ensure the caller is admin or root
			ensure_admin(origin, &Self::admin())?;
			// Set the mixer state, `stopped` can be true or false
			let tree_ids = BridgeTreeIds::<T>::get();
			for i in 0..tree_ids.len() {
				T::Tree::set_stopped(Self::account_id(), tree_ids[i], stopped)?;
			}
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

		#[pallet::weight(5_000_000)]
		pub fn wrap_and_deposit(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			leaf: T::Scalar,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as PrivacyBridgeSystem>::wrap_and_deposit(sender, tree_id, leaf)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn withdraw_zk(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			proof: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as PrivacyBridgeSystem>::withdraw_zk(sender, tree_id, proof)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn withdraw_public(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			proof: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as PrivacyBridgeSystem>::withdraw_public(sender, tree_id, proof)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn withdraw_zk_and_unwrap(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			proof: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as PrivacyBridgeSystem>::withdraw_zk_and_unwrap(sender, tree_id, proof)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn withdraw_public_and_unwrap(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			proof: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as PrivacyBridgeSystem>::withdraw_public_and_unwrap(sender, tree_id, proof)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn remix_zk(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			proof: Vec<u8>,
			leaf: T::Scalar,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as PrivacyBridgeSystem>::remix_zk(
				sender,
				tree_id,
				proof,
				leaf,
			)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn remix_public(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			proof: Vec<u8>,
			leaf: T::Scalar,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as PrivacyBridgeSystem>::remix_public(
				sender,
				tree_id,
				proof,
				leaf,
			)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn create_new(
			origin: OriginFor<T>,
			currency_id: CurrencyIdOf<T>,
			size: BalanceOf<T>,
			sig: T::ThresholdSignature,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as GovernableBridgeSystem>::create_new(
				sender,
				currency_id,
				size,
				sig,
			)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn add_anchor_root(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			chain_id: T::ChainId,
			root: T::Scalar,
			sig: T::ThresholdSignature,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as GovernableBridgeSystem>::add_anchor_root(
				tree_id,
				chain_id,
				root,
				sig,
			)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn remove_anchor_root(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			chain_id: T::ChainId,
			sig: T::ThresholdSignature,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as GovernableBridgeSystem>::remove_anchor_root(
				tree_id,
				chain_id,
				sig,
			)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn set_fee(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			new_fee: BalanceOf<T>,
			sig: T::ThresholdSignature,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as GovernableBridgeSystem>::set_fee(tree_id, new_fee, sig)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn set_multi_party_key(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			new_key: T::Scalar,
			sig: T::ThresholdSignature
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as GovernableBridgeSystem>::set_multi_party_key(tree_id, new_key, sig)?;

			Ok(().into())
		}
		#[pallet::weight(5_000_000)]
		pub fn register(origin: OriginFor<T>, threshold_key_share: T::Scalar) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);

			<Self as GovernableBridgeSystem>::register(sender, threshold_key_share)?;

			Ok(().into())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn account_id() -> T::AccountId {
		T::PalletId::get().into_account()
	}

	pub fn get_anchor_info(tree_id: T::TreeId) -> Result<AnchorInfo<T>, dispatch::DispatchError> {
		let anchor_info = Anchors::<T>::get(tree_id);
		// ensure anchor_info has a non-zero deposit, otherwise, the mixer doesn't
		// exist for this id
		ensure!(anchor_info.size > Zero::zero(), Error::<T>::NoMixerForId); // return the mixer info
		Ok(anchor_info)
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

impl<T: Config> PrivacyBridgeSystem for Pallet<T> {
	type AccountId = T::AccountId;
	type CurrencyId = CurrencyIdOf<T>;
	type Balance = BalanceOf<T>;
	type TreeId = T::TreeId;
	type Scalar = T::Scalar;

	fn wrap(account_id: Self::AccountId, currency_id: Self::CurrencyId, amount: Self::Balance)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn unwrap(account_id: Self::AccountId, currency_id: Self::CurrencyId, amount: Self::Balance)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn deposit(account_id: Self::AccountId, tree_id: Self::TreeId, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError> {
			let anchor = Self::get_anchor_info(tree_id)?;
			let currency_id = anchor.currency_id;
			// ensure token exists
			ensure!(T::Currency::exists(currency_id), Error::<T>::NoneValue);
			// ensure token has a webb-wrapped token (it is not a webb-wrapped token)
			ensure!(WrappedTokenRegistry::<T>::contains_key(currency_id), Error::<T>::NoneValue);
			// ensure the account_id has enough balance to cover anchor size
			let balance = T::Currency::free_balance(anchor.currency_id, &account_id);
			ensure!(balance >= anchor.size, Error::<T>::InsufficientBalance);
			// transfer the anchor size to the module
			T::Currency::transfer(anchor.currency_id, &account_id, &Self::account_id(), anchor.size)?;
			// add elements to the mixer group's merkle tree and save the leaves
			T::Tree::add_members(Self::account_id(), tree_id.into(), vec![pallet_merkle::utils::keys::ScalarData::zero()])?;
			Self::deposit_event(Event::Deposit(tree_id, account_id, anchor.size));
			Ok(())
		}
	fn wrap_and_deposit(account_id: Self::AccountId, tree_id: Self::TreeId, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn withdraw_zk(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn withdraw_public(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn withdraw_zk_and_unwrap(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn withdraw_public_and_unwrap(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn remix_zk(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn remix_public(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
}

impl<T: Config> GovernableBridgeSystem for Pallet<T> {
	type AccountId = T::AccountId;
	type CurrencyId = CurrencyIdOf<T>;
	type Balance = BalanceOf<T>;
	type TreeId = T::TreeId;
	type ChainId = T::ChainId;
	type Scalar = T::Scalar;
	type IndividualKeyShare = T::Scalar;
	type DistributedPublicKey = T::Scalar;
	type Signature = T::ThresholdSignature;

	fn create_new(account_id: Self::AccountId, currency_id: Self::CurrencyId, size: Self::Balance, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn add_anchor_root(anchor_id: Self::TreeId, chain_id: Self::ChainId, root: Self::Scalar, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn remove_anchor_root(anchor_id: Self::TreeId, chain_id: Self::ChainId, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn set_fee(anchor_id: Self::TreeId, fee: Self::Balance, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn set_multi_party_key(anchor_id: Self::TreeId, new_key: Self::DistributedPublicKey, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
	fn register(account_id: Self::AccountId, share: Self::IndividualKeyShare)
		-> Result<(), dispatch::DispatchError> { Ok(()) }
}