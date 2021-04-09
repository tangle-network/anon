// A runtime module Groups with necessary imports

// Feel free to remove or edit this file as needed.
// If you change the name of this file, make sure to update its references in
// runtime/src/lib.rs If you remove this file, you can remove those references

// For more guidance on Substrate modules, see the example module
// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

#![cfg_attr(not(feature = "std"), no_std)]

pub mod traits;
// pub mod weights;
// #[cfg(feature = "runtime-benchmarks")]
// mod benchmarking;
#[cfg(test)]
pub mod mock;
#[cfg(test)]
mod tests;

// mod extra_mutator;
// pub use extra_mutator::*;
// mod impl_stored_map;
// mod impl_fungibles;
// mod functions;
mod types;
pub use types::*;

use sp_std::{prelude::*, borrow::Borrow};
use sp_runtime::{
	RuntimeDebug, TokenError, traits::{
		AtLeast32BitUnsigned, Zero, StaticLookup, Saturating, CheckedSub, CheckedAdd, Bounded,
		StoredMapError,
	}
};
use codec::{Encode, Decode, HasCompact};
use frame_support::{ensure, dispatch::{DispatchError, DispatchResult}};
use frame_support::traits::{Currency, ReservableCurrency, BalanceStatus::Reserved, StoredMap};
use frame_support::traits::tokens::{WithdrawConsequence, DepositConsequence, fungibles};
use frame_system::Config as SystemConfig;
use orml_traits::MultiCurrency;

/// Type alias for the orml_traits::MultiCurrency::Balance type
pub type BalanceOf<T> = <<T as Config>::Currency as MultiCurrency<<T as frame_system::Config>::AccountId>>::Balance;
/// Type alias for the orml_traits::MultiCurrency::CurrencyId type
pub type CurrencyIdOf<T> =
	<<T as pallet::Config>::Currency as MultiCurrency<<T as frame_system::Config>::AccountId>>::CurrencyId;

pub use sp_std::convert::TryInto;

// pub use weights::WeightInfo;
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::DispatchResultWithInfo;


	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	/// The module configuration trait.
	pub trait Config: frame_system::Config + orml_currencies::Config {
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// The balance type
		type Balance: Parameter + Member + AtLeast32BitUnsigned + Default + Copy + MaybeSerializeDeserialize;

		/// The amount type, should be signed version of `Balance`
		type Amount: Signed
			+ TryInto<Self::Balance>
			+ TryFrom<Self::Balance>
			+ Parameter
			+ Member
			+ arithmetic::SimpleArithmetic
			+ Default
			+ Copy
			+ MaybeSerializeDeserialize;

		/// The currency ID type
		type CurrencyId: Parameter + Member + Copy + MaybeSerializeDeserialize + Ord;

		/// The currency mechanism.
		type Currency: MultiCurrency<Self::AccountId>;

		/// The origin which may forcibly create or destroy an asset or otherwise alter privileged
		/// attributes.
		type ForceOrigin: EnsureOrigin<Self::Origin>;

		/// The basic amount of funds that must be reserved for an asset.
		type CurrencyDeposit: Get<DepositBalanceOf<Self>>;

		/// The basic amount of funds that must be reserved when adding metadata to your asset.
		type MetadataDepositBase: Get<DepositBalanceOf<Self>>;

		/// The additional funds that must be reserved for the number of bytes you store in your
		/// metadata.
		type MetadataDepositPerByte: Get<DepositBalanceOf<Self>>;

		/// The amount of funds that must be reserved when creating a new approval.
		type ApprovalDeposit: Get<DepositBalanceOf<Self>>;

		/// The maximum length of a name or symbol stored on-chain.
		type StringLimit: Get<u32>;

		/// Additional data to be stored with an account's asset balance.
		type Extra: Member + Parameter + Default;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	#[pallet::metadata(T::AccountId = "AccountId", T::Balance = "Balance", T::CurrencyId = "CurrencyId")]
	pub enum Event<T: Config> {
		/// Some asset class was created. \[asset_id, creator, owner\]
		Created(T::CurrencyId, T::AccountId, T::AccountId),
		/// Some assets were issued. \[asset_id, owner, total_supply\]
		Issued(T::CurrencyId, T::AccountId, T::Balance),
		/// Some assets were destroyed. \[asset_id, owner, balance\]
		Burned(T::CurrencyId, T::AccountId, T::Balance),
		/// The management team changed \[asset_id, issuer, admin, freezer\]
		TeamChanged(T::CurrencyId, T::AccountId, T::AccountId, T::AccountId),
		/// The owner changed \[asset_id, owner\]
		OwnerChanged(T::CurrencyId, T::AccountId),
		/// An asset class was destroyed.
		Destroyed(T::CurrencyId),
		/// Some asset class was force-created. \[asset_id, owner\]
		ForceCreated(T::CurrencyId, T::AccountId),
		/// New metadata has been set for an asset. \[asset_id, name, symbol, decimals, is_frozen\]
		MetadataSet(T::CurrencyId, Vec<u8>, Vec<u8>, u8, bool),
		/// Metadata has been cleared for an asset. \[asset_id\]
		MetadataCleared(T::CurrencyId),
		/// (Additional) funds have been approved for transfer to a destination account.
		/// \[asset_id, source, delegate, amount\]
		ApprovedTransfer(T::CurrencyId, T::AccountId, T::AccountId, T::Balance),
		/// An approval for account `delegate` was cancelled by `owner`.
		/// \[id, owner, delegate\]
		ApprovalCancelled(T::CurrencyId, T::AccountId, T::AccountId),
		/// An `amount` was transferred in its entirety from `owner` to `destination` by
		/// the approved `delegate`.
		/// \[id, owner, delegate, destination\]
		TransferredApproved(T::CurrencyId, T::AccountId, T::AccountId, T::AccountId, T::Balance),
		/// An asset has had its attributes changed by the `Force` origin.
		/// \[id\]
		CurrencyStatusChanged(T::CurrencyId),
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Account balance must be greater than or equal to the transfer amount.
		BalanceLow,
		/// Balance should be non-zero.
		BalanceZero,
		/// The signing account has no permission to do the operation.
		NoPermission,
		/// The given currency ID is unknown.
		Unknown,
		/// The origin account is frozen.
		Frozen,
		/// The currency ID is already taken.
		InUse,
		/// Invalid witness data given.
		BadWitness,
		/// Minimum balance should be non-zero.
		MinBalanceZero,
		/// A mint operation lead to an overflow.
		Overflow,
		/// No provider reference exists to allow a non-zero balance of a non-self-sufficient currency.
		NoProvider,
		/// Invalid metadata given.
		BadMetadata,
		/// No approval exists that would allow the transfer.
		Unapproved,
		/// The source account would not survive the transfer and it needs to stay alive.
		WouldDie,
	}

	#[pallet::storage]
	/// Details of an asset.
	pub(super) type Currency<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::CurrencyId,
		CurrencyDetails<T::Balance, T::AccountId, DepositBalanceOf<T>>,
	>;

	#[pallet::storage]
	/// Approved balance transfers. First balance is the amount approved for transfer. Second
	/// is the amount of `T::Currency` reserved for storing this.
	pub(super) type Approvals<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::CurrencyId,
		Blake2_128Concat,
		ApprovalKey<T::AccountId>,
		Approval<T::Balance, DepositBalanceOf<T>>,
		OptionQuery,
	>;

	#[pallet::storage]
	/// Metadata of an currency.
	pub(super) type Metadata<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::CurrencyId,
		CurrencyMetadata<DepositBalanceOf<T>>,
		ValueQuery,
	>;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Issue a new class of fungible assets from a public origin.
		///
		/// This new asset class has no assets initially and its owner is the origin.
		///
		/// The origin must be Signed and the sender must have sufficient funds free.
		///
		/// Funds of sender are reserved by `CurrencyDeposit`.
		///
		/// Parameters:
		/// - `id`: The identifier of the new asset. This must not be currently in use to identify
		/// an existing asset.
		/// - `admin`: The admin of this class of assets. The admin is the initial address of each
		/// member of the asset class's admin team.
		/// - `min_balance`: The minimum balance of this new asset that any single account must
		/// have. If an account's balance is reduced below this, then it collapses to zero.
		///
		/// Emits `Created` event when successful.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn create(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			admin: <T::Lookup as StaticLookup>::Source,
			min_balance: T::Balance,
		) -> DispatchResultWithPostInfo {
			let owner = ensure_signed(origin)?;
			let admin = T::Lookup::lookup(admin)?;

			ensure!(!Currency::<T>::contains_key(id), Error::<T>::InUse);
			ensure!(!min_balance.is_zero(), Error::<T>::MinBalanceZero);

			let deposit = T::CurrencyDeposit::get();
			T::Currency::reserve(&owner, deposit)?;

			Currency::<T>::insert(id, CurrencyDetails {
				owner: owner.clone(),
				issuer: admin.clone(),
				admin: admin.clone(),
				freezer: admin.clone(),
				supply: Zero::zero(),
				deposit,
				min_balance,
				is_sufficient: false,
				accounts: 0,
				sufficients: 0,
				approvals: 0,
				is_frozen: false,
			});
			Self::deposit_event(Event::Created(id, owner, admin));
			Ok(())
		}

		/// Issue a new class of fungible assets from a privileged origin.
		///
		/// This new asset class has no assets initially.
		///
		/// The origin must conform to `ForceOrigin`.
		///
		/// Unlike `create`, no funds are reserved.
		///
		/// - `id`: The identifier of the new asset. This must not be currently in use to identify
		/// an existing asset.
		/// - `owner`: The owner of this class of assets. The owner has full superuser permissions
		/// over this asset, but may later change and configure the permissions using `transfer_ownership`
		/// and `set_team`.
		/// - `max_zombies`: The total number of accounts which may hold assets in this class yet
		/// have no existential deposit.
		/// - `min_balance`: The minimum balance of this new asset that any single account must
		/// have. If an account's balance is reduced below this, then it collapses to zero.
		///
		/// Emits `ForceCreated` event when successful.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn force_create(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			is_sufficient: bool,
			#[pallet::compact] min_balance: T::Balance,
		) -> DispatchResultWithPostInfo {
			T::ForceOrigin::ensure_origin(origin)?;
			let owner = T::Lookup::lookup(owner)?;

			ensure!(!Currency::<T>::contains_key(id), Error::<T>::InUse);
			ensure!(!min_balance.is_zero(), Error::<T>::MinBalanceZero);

			Currency::<T>::insert(id, CurrencyDetails {
				owner: owner.clone(),
				issuer: owner.clone(),
				admin: owner.clone(),
				freezer: owner.clone(),
				supply: Zero::zero(),
				deposit: Zero::zero(),
				min_balance,
				is_sufficient,
				accounts: 0,
				sufficients: 0,
				approvals: 0,
				is_frozen: false,
			});
			Self::deposit_event(Event::ForceCreated(id, owner));
			Ok(())
		}

		/// Destroy a class of fungible assets.
		///
		/// The origin must conform to `ForceOrigin` or must be Signed and the sender must be the
		/// owner of the asset `id`.
		///
		/// - `id`: The identifier of the asset to be destroyed. This must identify an existing
		/// asset.
		///
		/// Emits `Destroyed` event when successful.
		///
		/// Weight: `O(c + p + a)` where:
		/// - `c = (witness.accounts - witness.sufficients)`
		/// - `s = witness.sufficients`
		/// - `a = witness.approvals`
		#[pallet::weight(5_000_000)]
		pub(super) fn destroy(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			witness: DestroyWitness,
		) -> DispatchResultWithPostInfo {
			let maybe_check_owner = match T::ForceOrigin::try_origin(origin) {
				Ok(_) => None,
				Err(origin) => Some(ensure_signed(origin)?),
			};
			Currency::<T>::try_mutate_exists(id, |maybe_details| {
				let mut details = maybe_details.take().ok_or(Error::<T>::Unknown)?;
				if let Some(check_owner) = maybe_check_owner {
					ensure!(details.owner == check_owner, Error::<T>::NoPermission);
				}
				ensure!(details.accounts == witness.accounts, Error::<T>::BadWitness);
				ensure!(details.sufficients == witness.sufficients, Error::<T>::BadWitness);
				ensure!(details.approvals == witness.approvals, Error::<T>::BadWitness);

				for (who, v) in Account::<T>::drain_prefix(id) {
					Self::dead_account(id, &who, &mut details, v.sufficient);
				}
				debug_assert_eq!(details.accounts, 0);
				debug_assert_eq!(details.sufficients, 0);

				let metadata = Metadata::<T>::take(&id);
				T::Currency::unreserve(&details.owner, details.deposit.saturating_add(metadata.deposit));

				Approvals::<T>::remove_prefix(&id);
				Self::deposit_event(Event::Destroyed(id));

				// NOTE: could use postinfo to reflect the actual number of accounts/sufficient/approvals
				Ok(())
			})
		}

		/// Mint assets of a particular class.
		///
		/// The origin must be Signed and the sender must be the Issuer of the asset `id`.
		///
		/// - `id`: The identifier of the asset to have some amount minted.
		/// - `beneficiary`: The account to be credited with the minted assets.
		/// - `amount`: The amount of the asset to be minted.
		///
		/// Emits `Destroyed` event when successful.
		///
		/// Weight: `O(1)`
		/// Modes: Pre-existing balance of `beneficiary`; Account pre-existence of `beneficiary`.
		#[pallet::weight(5_000_000)]
		pub(super) fn mint(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			beneficiary: <T::Lookup as StaticLookup>::Source,
			#[pallet::compact] amount: T::Balance
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let beneficiary = T::Lookup::lookup(beneficiary)?;
			Self::do_mint(id, &beneficiary, amount, Some(origin))?;
			Self::deposit_event(Event::Issued(id, beneficiary, amount));
			Ok(())
		}

		/// Reduce the balance of `who` by as much as possible up to `amount` assets of `id`.
		///
		/// Origin must be Signed and the sender should be the Manager of the asset `id`.
		///
		/// Bails with `BalanceZero` if the `who` is already dead.
		///
		/// - `id`: The identifier of the asset to have some amount burned.
		/// - `who`: The account to be debited from.
		/// - `amount`: The maximum amount by which `who`'s balance should be reduced.
		///
		/// Emits `Burned` with the actual amount burned. If this takes the balance to below the
		/// minimum for the asset, then the amount burned is increased to take it to zero.
		///
		/// Weight: `O(1)`
		/// Modes: Post-existence of `who`; Pre & post Zombie-status of `who`.
		#[pallet::weight(5_000_000)]
		pub(super) fn burn(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			who: <T::Lookup as StaticLookup>::Source,
			#[pallet::compact] amount: T::Balance
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let who = T::Lookup::lookup(who)?;

			let f = DebitFlags { keep_alive: false, best_effort: true };
			let burned = Self::do_burn(id, &who, amount, Some(origin), f)?;
			Self::deposit_event(Event::Burned(id, who, burned));
			Ok(())
		}

		/// Change the Owner of an asset.
		///
		/// Origin must be Signed and the sender should be the Owner of the asset `id`.
		///
		/// - `id`: The identifier of the asset.
		/// - `owner`: The new Owner of this asset.
		///
		/// Emits `OwnerChanged`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn transfer_ownership(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let owner = T::Lookup::lookup(owner)?;

			Currency::<T>::try_mutate(id, |maybe_details| {
				let details = maybe_details.as_mut().ok_or(Error::<T>::Unknown)?;
				ensure!(&origin == &details.owner, Error::<T>::NoPermission);
				if details.owner == owner { return Ok(()) }

				let metadata_deposit = Metadata::<T>::get(id).deposit;
				let deposit = details.deposit + metadata_deposit;

				// Move the deposit to the new owner.
				T::Currency::repatriate_reserved(&details.owner, &owner, deposit, Reserved)?;

				details.owner = owner.clone();

				Self::deposit_event(Event::OwnerChanged(id, owner));
				Ok(())
			})
		}

		/// Change the Issuer, Admin and Freezer of an asset.
		///
		/// Origin must be Signed and the sender should be the Owner of the asset `id`.
		///
		/// - `id`: The identifier of the asset to be frozen.
		/// - `issuer`: The new Issuer of this asset.
		/// - `admin`: The new Admin of this asset.
		/// - `freezer`: The new Freezer of this asset.
		///
		/// Emits `TeamChanged`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn set_team(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			issuer: <T::Lookup as StaticLookup>::Source,
			admin: <T::Lookup as StaticLookup>::Source,
			freezer: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;
			let issuer = T::Lookup::lookup(issuer)?;
			let admin = T::Lookup::lookup(admin)?;
			let freezer = T::Lookup::lookup(freezer)?;

			Currency::<T>::try_mutate(id, |maybe_details| {
				let details = maybe_details.as_mut().ok_or(Error::<T>::Unknown)?;
				ensure!(&origin == &details.owner, Error::<T>::NoPermission);

				details.issuer = issuer.clone();
				details.admin = admin.clone();
				details.freezer = freezer.clone();

				Self::deposit_event(Event::TeamChanged(id, issuer, admin, freezer));
				Ok(())
			})
		}

		/// Set the metadata for an asset.
		///
		/// Origin must be Signed and the sender should be the Owner of the asset `id`.
		///
		/// Funds of sender are reserved according to the formula:
		/// `MetadataDepositBase + MetadataDepositPerByte * (name.len + symbol.len)` taking into
		/// account any already reserved funds.
		///
		/// - `id`: The identifier of the asset to update.
		/// - `name`: The user friendly name of this asset. Limited in length by `StringLimit`.
		/// - `symbol`: The exchange symbol for this asset. Limited in length by `StringLimit`.
		/// - `decimals`: The number of decimals this asset uses to represent one unit.
		///
		/// Emits `MetadataSet`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn set_metadata(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			name: Vec<u8>,
			symbol: Vec<u8>,
			decimals: u8,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;

			ensure!(name.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);
			ensure!(symbol.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);

			let d = Currency::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(&origin == &d.owner, Error::<T>::NoPermission);

			Metadata::<T>::try_mutate_exists(id, |metadata| {
				ensure!(metadata.as_ref().map_or(true, |m| !m.is_frozen), Error::<T>::NoPermission);

				let old_deposit = metadata.take().map_or(Zero::zero(), |m| m.deposit);
				let new_deposit = T::MetadataDepositPerByte::get()
					.saturating_mul(((name.len() + symbol.len()) as u32).into())
					.saturating_add(T::MetadataDepositBase::get());

				if new_deposit > old_deposit {
					T::Currency::reserve(&origin, new_deposit - old_deposit)?;
				} else {
					T::Currency::unreserve(&origin, old_deposit - new_deposit);
				}

				*metadata = Some(CurrencyMetadata {
					deposit: new_deposit,
					name: name.clone(),
					symbol: symbol.clone(),
					decimals,
					is_frozen: false,
				});

				Self::deposit_event(Event::MetadataSet(id, name, symbol, decimals, false));
				Ok(())
			})
		}

		/// Clear the metadata for an asset.
		///
		/// Origin must be Signed and the sender should be the Owner of the asset `id`.
		///
		/// Any deposit is freed for the asset owner.
		///
		/// - `id`: The identifier of the asset to clear.
		///
		/// Emits `MetadataCleared`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn clear_metadata(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
		) -> DispatchResultWithPostInfo {
			let origin = ensure_signed(origin)?;

			let d = Currency::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(&origin == &d.owner, Error::<T>::NoPermission);

			Metadata::<T>::try_mutate_exists(id, |metadata| {
				let deposit = metadata.take().ok_or(Error::<T>::Unknown)?.deposit;
				T::Currency::unreserve(&d.owner, deposit);
				Self::deposit_event(Event::MetadataCleared(id));
				Ok(())
			})
		}

		/// Force the metadata for an asset to some value.
		///
		/// Origin must be ForceOrigin.
		///
		/// Any deposit is left alone.
		///
		/// - `id`: The identifier of the asset to update.
		/// - `name`: The user friendly name of this asset. Limited in length by `StringLimit`.
		/// - `symbol`: The exchange symbol for this asset. Limited in length by `StringLimit`.
		/// - `decimals`: The number of decimals this asset uses to represent one unit.
		///
		/// Emits `MetadataSet`.
		///
		/// Weight: `O(N + S)` where N and S are the length of the name and symbol respectively.
		#[pallet::weight(5_000_000)]
		pub(super) fn force_set_metadata(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			name: Vec<u8>,
			symbol: Vec<u8>,
			decimals: u8,
			is_frozen: bool,
		) -> DispatchResultWithPostInfo {
			T::ForceOrigin::ensure_origin(origin)?;

			ensure!(name.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);
			ensure!(symbol.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);

			ensure!(Currency::<T>::contains_key(id), Error::<T>::Unknown);
			Metadata::<T>::try_mutate_exists(id, |metadata| {
				let deposit = metadata.take().map_or(Zero::zero(), |m| m.deposit);
				*metadata = Some(CurrencyMetadata {
					deposit,
					name: name.clone(),
					symbol: symbol.clone(),
					decimals,
					is_frozen,
				});

				Self::deposit_event(Event::MetadataSet(id, name, symbol, decimals, is_frozen));
				Ok(())
			})
		}

		/// Clear the metadata for an asset.
		///
		/// Origin must be ForceOrigin.
		///
		/// Any deposit is returned.
		///
		/// - `id`: The identifier of the asset to clear.
		///
		/// Emits `MetadataCleared`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn force_clear_metadata(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
		) -> DispatchResultWithPostInfo {
			T::ForceOrigin::ensure_origin(origin)?;

			let d = Currency::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			Metadata::<T>::try_mutate_exists(id, |metadata| {
				let deposit = metadata.take().ok_or(Error::<T>::Unknown)?.deposit;
				T::Currency::unreserve(&d.owner, deposit);
				Self::deposit_event(Event::MetadataCleared(id));
				Ok(())
			})
		}

		/// Alter the attributes of a given asset.
		///
		/// Origin must be `ForceOrigin`.
		///
		/// - `id`: The identifier of the asset.
		/// - `owner`: The new Owner of this asset.
		/// - `issuer`: The new Issuer of this asset.
		/// - `admin`: The new Admin of this asset.
		/// - `freezer`: The new Freezer of this asset.
		/// - `min_balance`: The minimum balance of this new asset that any single account must
		/// have. If an account's balance is reduced below this, then it collapses to zero.
		/// - `is_sufficient`: Whether a non-zero balance of this asset is deposit of sufficient
		/// value to account for the state bloat associated with its balance storage. If set to
		/// `true`, then non-zero balances may be stored without a `consumer` reference (and thus
		/// an ED in the Balances pallet or whatever else is used to control user-account state
		/// growth).
		/// - `is_frozen`: Whether this asset class is frozen except for permissioned/admin
		/// instructions.
		///
		/// Emits `CurrencyStatusChanged` with the identity of the asset.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn force_asset_status(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			issuer: <T::Lookup as StaticLookup>::Source,
			admin: <T::Lookup as StaticLookup>::Source,
			freezer: <T::Lookup as StaticLookup>::Source,
			#[pallet::compact] min_balance: T::Balance,
			is_sufficient: bool,
			is_frozen: bool,
		) -> DispatchResultWithPostInfo {
			T::ForceOrigin::ensure_origin(origin)?;

			Currency::<T>::try_mutate(id, |maybe_asset| {
				let mut asset = maybe_asset.take().ok_or(Error::<T>::Unknown)?;
				asset.owner = T::Lookup::lookup(owner)?;
				asset.issuer = T::Lookup::lookup(issuer)?;
				asset.admin = T::Lookup::lookup(admin)?;
				asset.freezer = T::Lookup::lookup(freezer)?;
				asset.min_balance = min_balance;
				asset.is_sufficient = is_sufficient;
				asset.is_frozen = is_frozen;
				*maybe_asset = Some(asset);

				Self::deposit_event(Event::CurrencyStatusChanged(id));
				Ok(())
			})
		}

		/// Approve an amount of asset for transfer by a delegated third-party account.
		///
		/// Origin must be Signed.
		///
		/// Ensures that `ApprovalDeposit` worth of `Currency` is reserved from signing account
		/// for the purpose of holding the approval. If some non-zero amount of assets is already
		/// approved from signing account to `delegate`, then it is topped up or unreserved to
		/// meet the right value.
		///
		/// NOTE: The signing account does not need to own `amount` of assets at the point of
		/// making this call.
		///
		/// - `id`: The identifier of the asset.
		/// - `delegate`: The account to delegate permission to transfer asset.
		/// - `amount`: The amount of asset that may be transferred by `delegate`. If there is
		/// already an approval in place, then this acts additively.
		///
		/// Emits `ApprovedTransfer` on success.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn approve_transfer(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			delegate: <T::Lookup as StaticLookup>::Source,
			#[pallet::compact] amount: T::Balance,
		) -> DispatchResultWithPostInfo {
			let owner = ensure_signed(origin)?;
			let delegate = T::Lookup::lookup(delegate)?;

			let key = ApprovalKey { owner, delegate };
			Approvals::<T>::try_mutate(id, &key, |maybe_approved| -> DispatchResultWithPostInfo {
				let mut approved = maybe_approved.take().unwrap_or_default();
				let deposit_required = T::ApprovalDeposit::get();
				if approved.deposit < deposit_required {
					T::Currency::reserve(&key.owner, deposit_required - approved.deposit)?;
					approved.deposit = deposit_required;
				}
				approved.amount = approved.amount.saturating_add(amount);
				*maybe_approved = Some(approved);
				Ok(())
			})?;
			Self::deposit_event(Event::ApprovedTransfer(id, key.owner, key.delegate, amount));

			Ok(())
		}

		/// Cancel all of some asset approved for delegated transfer by a third-party account.
		///
		/// Origin must be Signed and there must be an approval in place between signer and
		/// `delegate`.
		///
		/// Unreserves any deposit previously reserved by `approve_transfer` for the approval.
		///
		/// - `id`: The identifier of the asset.
		/// - `delegate`: The account delegated permission to transfer asset.
		///
		/// Emits `ApprovalCancelled` on success.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn cancel_approval(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			delegate: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResultWithPostInfo {
			let owner = ensure_signed(origin)?;
			let delegate = T::Lookup::lookup(delegate)?;
			let key = ApprovalKey { owner, delegate };
			let approval = Approvals::<T>::take(id, &key).ok_or(Error::<T>::Unknown)?;
			T::Currency::unreserve(&key.owner, approval.deposit);

			Self::deposit_event(Event::ApprovalCancelled(id, key.owner, key.delegate));
			Ok(())
		}

		/// Cancel all of some asset approved for delegated transfer by a third-party account.
		///
		/// Origin must be either ForceOrigin or Signed origin with the signer being the Admin
		/// account of the asset `id`.
		///
		/// Unreserves any deposit previously reserved by `approve_transfer` for the approval.
		///
		/// - `id`: The identifier of the asset.
		/// - `delegate`: The account delegated permission to transfer asset.
		///
		/// Emits `ApprovalCancelled` on success.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn force_cancel_approval(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			delegate: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResultWithPostInfo {
			T::ForceOrigin::try_origin(origin)
				.map(|_| ())
				.or_else(|origin| -> DispatchResultWithPostInfo {
					let origin = ensure_signed(origin)?;
					let d = Currency::<T>::get(id).ok_or(Error::<T>::Unknown)?;
					ensure!(&origin == &d.admin, Error::<T>::NoPermission);
					Ok(())
				})?;

			let owner = T::Lookup::lookup(owner)?;
			let delegate = T::Lookup::lookup(delegate)?;

			let key = ApprovalKey { owner, delegate };
			let approval = Approvals::<T>::take(id, &key).ok_or(Error::<T>::Unknown)?;
			T::Currency::unreserve(&key.owner, approval.deposit);

			Self::deposit_event(Event::ApprovalCancelled(id, key.owner, key.delegate));
			Ok(())
		}

		/// Transfer some asset balance from a previously delegated account to some third-party
		/// account.
		///
		/// Origin must be Signed and there must be an approval in place by the `owner` to the
		/// signer.
		///
		/// If the entire amount approved for transfer is transferred, then any deposit previously
		/// reserved by `approve_transfer` is unreserved.
		///
		/// - `id`: The identifier of the asset.
		/// - `owner`: The account which previously approved for a transfer of at least `amount` and
		/// from which the asset balance will be withdrawn.
		/// - `destination`: The account to which the asset balance of `amount` will be transferred.
		/// - `amount`: The amount of assets to transfer.
		///
		/// Emits `TransferredApproved` on success.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn transfer_approved(
			origin: OriginFor<T>,
			#[pallet::compact] id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			destination: <T::Lookup as StaticLookup>::Source,
			#[pallet::compact] amount: T::Balance,
		) -> DispatchResultWithPostInfo {
			let delegate = ensure_signed(origin)?;
			let owner = T::Lookup::lookup(owner)?;
			let destination = T::Lookup::lookup(destination)?;

			let key = ApprovalKey { owner, delegate };
			Approvals::<T>::try_mutate_exists(id, &key, |maybe_approved| -> DispatchResultWithPostInfo {
				let mut approved = maybe_approved.take().ok_or(Error::<T>::Unapproved)?;
				let remaining = approved.amount.checked_sub(&amount).ok_or(Error::<T>::Unapproved)?;

				let f = TransferFlags {
					keep_alive: false,
					best_effort: false,
					burn_dust: false
				};
				Self::do_transfer(id, &key.owner, &destination, amount, None, f)?;

				if remaining.is_zero() {
					T::Currency::unreserve(&key.owner, approved.deposit);
				} else {
					approved.amount = remaining;
					*maybe_approved = Some(approved);
				}
				Ok(())
			})?;
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn account_id() -> T::AccountId {
		T::ModuleId::get().into_account()
	}
}
