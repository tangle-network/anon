// A runtime module Groups with necessary imports

// Feel free to remove or edit this file as needed.
// If you change the name of this file, make sure to update its references in
// runtime/src/lib.rs If you remove this file, you can remove those references

// For more guidance on Substrate modules, see the example module
// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

#![cfg_attr(not(feature = "std"), no_std)]

pub mod weights;
// #[cfg(feature = "runtime-benchmarks")]
// mod benchmarking;
#[cfg(test)]
pub mod mock;
#[cfg(test)]
mod tests;

mod basic_currency;
mod traits;
pub use traits::*;
mod types;
pub use types::*;
mod imbalance;
pub use imbalance::*;

use sp_std::{
	convert::{Infallible, TryFrom, TryInto},
	marker,
	prelude::*,
	vec::Vec,
};

use codec::{Decode, Encode};
use frame_support::{
	dispatch::{DispatchError, DispatchResult},
	ensure, log,
	traits::{
		Currency as PalletCurrency, ExistenceRequirement, Get, Imbalance, LockableCurrency as PalletLockableCurrency,
		MaxEncodedLen, ReservableCurrency as PalletReservableCurrency, SignedImbalance, WithdrawReasons,
	},
	transactional, PalletId,
};
use sp_runtime::{
	traits::{
		AccountIdConversion, AtLeast32BitUnsigned, Bounded, CheckedAdd, CheckedSub, MaybeSerializeDeserialize, Member,
		Saturating, StaticLookup, Zero,
	},
	RuntimeDebug,
};

pub use pallet::*;
use sp_std::collections::btree_map::BTreeMap;
use webb_traits::{
	account::MergeAccount,
	arithmetic::{self, Signed},
	BalanceStatus, BasicCurrencyExtended, BasicLockableCurrency, BasicReservableCurrency, LockIdentifier,
	MultiCurrency, MultiCurrencyExtended, MultiLockableCurrency, MultiReservableCurrency,
};
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		// tokens to create + min_balance for that token
		pub tokens: Vec<(T::CurrencyId, T::Balance)>,
		// endowed accounts for a token + their balances
		pub endowed_accounts: Vec<(T::AccountId, T::CurrencyId, T::Balance)>,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			GenesisConfig {
				tokens: vec![],
				endowed_accounts: vec![],
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			// ensure no duplicates exist.
			let unique_endowed_accounts = self
				.endowed_accounts
				.iter()
				.map(|(account_id, currency_id, _)| (account_id, currency_id))
				.collect::<std::collections::BTreeSet<_>>();
			assert!(
				unique_endowed_accounts.len() == self.endowed_accounts.len(),
				"duplicate endowed accounts in genesis."
			);

			// ensure no duplicates exist.
			let unique_tokens = self
				.tokens
				.iter()
				.map(|(currency_id, min_balance)| (currency_id, min_balance))
				.collect::<std::collections::BTreeSet<_>>();

			assert!(unique_tokens.len() == self.tokens.len(), "duplicate tokens in genesis.");

			let mut token_min_balance_map: BTreeMap<T::CurrencyId, T::Balance> = BTreeMap::new();
			for i in 0..self.tokens.len() {
				token_min_balance_map.insert(self.tokens[i].0, self.tokens[i].1);
			}
			for (account_id, currency_id, initial_balance) in &self.endowed_accounts {
				// create a token with the currency_id.
				<Pallet<T> as ExtendedTokenSystem<_, _, _>>::create(
					*currency_id,
					account_id.clone(),
					account_id.clone(),
					Zero::zero(),
				)
				.unwrap();
				assert!(
					initial_balance >= token_min_balance_map.get(&currency_id).unwrap(),
					"the balance of any account should always be more than existential deposit.",
				);
				Pallet::<T>::set_free_balance(*currency_id, &account_id, *initial_balance);
				assert!(
					Pallet::<T>::free_balance(*currency_id, &account_id) == *initial_balance,
					"the balance is wrong"
				);
				TotalIssuance::<T>::mutate(&currency_id, |total_issuance| {
					*total_issuance = total_issuance
						.checked_add(&initial_balance)
						.expect("total issuance cannot overflow when building genesis")
				});
			}
		}
	}

	#[pallet::config]
	/// The module configuration trait.
	pub trait Config: frame_system::Config {
		#[pallet::constant]
		type PalletId: Get<PalletId>;
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// The balance type
		type Balance: Parameter
			+ Member
			+ AtLeast32BitUnsigned
			+ Default
			+ Copy
			+ MaybeSerializeDeserialize
			+ MaxEncodedLen;

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

		/// The native currency system
		type NativeCurrency: BasicCurrencyExtended<Self::AccountId, Balance = Self::Balance, Amount = Self::Amount>
			+ BasicLockableCurrency<Self::AccountId, Balance = Self::Balance>
			+ BasicReservableCurrency<Self::AccountId, Balance = Self::Balance>;

		/// The origin which may forcibly create or destroy an asset or
		/// otherwise alter privileged attributes.
		type ForceOrigin: EnsureOrigin<Self::Origin>;

		/// The basic amount of funds that must be reserved for an asset.
		type CurrencyDeposit: Get<Self::Balance>;

		/// The basic amount of funds that must be reserved when adding metadata
		/// to your asset.
		type MetadataDepositBase: Get<Self::Balance>;

		/// The additional funds that must be reserved for the number of bytes
		/// you store in your metadata.
		type MetadataDepositPerByte: Get<Self::Balance>;

		/// The amount of funds that must be reserved when creating a new
		/// approval.
		type ApprovalDeposit: Get<Self::Balance>;

		/// The maximum length of a name or symbol stored on-chain.
		type StringLimit: Get<u32>;

		/// Additional data to be stored with an account's asset balance.
		type Extra: Member + Parameter + Default;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;

		/// The default account to send dust to.
		type DustAccount: Get<Self::AccountId>;
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
		/// Some account `who` was frozen. \[asset_id, who\]
		Frozen(T::CurrencyId, T::AccountId),
		/// Some account `who` was thawed. \[asset_id, who\]
		Thawed(T::CurrencyId, T::AccountId),
		/// Some asset `asset_id` was frozen. \[asset_id\]
		TokenFrozen(T::CurrencyId),
		/// Some asset `asset_id` was thawed. \[asset_id\]
		TokenThawed(T::CurrencyId),
		/// The management team changed \[asset_id, issuer, admin, freezer\]
		TeamChanged(T::CurrencyId, T::AccountId, T::AccountId, T::AccountId),
		/// The owner changed \[asset_id, owner\]
		OwnerChanged(T::CurrencyId, T::AccountId),
		/// An asset class was destroyed.
		Destroyed(T::CurrencyId),
		/// Some asset class was force-created. \[asset_id, owner\]
		ForceCreated(T::CurrencyId, T::AccountId),
		/// New metadata has been set for an asset. \[asset_id, name, symbol,
		/// decimals, is_frozen\]
		MetadataSet(T::CurrencyId, Vec<u8>, Vec<u8>, u8, bool),
		/// Metadata has been cleared for an asset. \[asset_id\]
		MetadataCleared(T::CurrencyId),
		/// (Additional) funds have been approved for transfer to a destination
		/// account. \[asset_id, source, delegate, amount\]
		ApprovedTransfer(T::CurrencyId, T::AccountId, T::AccountId, T::Balance),
		/// An approval for account `delegate` was cancelled by `owner`.
		/// \[id, owner, delegate\]
		ApprovalCancelled(T::CurrencyId, T::AccountId, T::AccountId),
		/// An `amount` was transferred in its entirety from `owner` to
		/// `destination` by the approved `delegate`.
		/// \[id, owner, delegate, destination\]
		TransferredApproved(T::CurrencyId, T::AccountId, T::AccountId, T::AccountId, T::Balance),
		/// An asset has had its attributes changed by the `Force` origin.
		/// \[id\]
		CurrencyStatusChanged(T::CurrencyId),
		/// Token transfer success. \[currency_id, from, to, amount\]
		Transferred(T::CurrencyId, T::AccountId, T::AccountId, T::Balance),
		/// An account was removed whose balance was non-zero but below
		/// ExistentialDeposit, resulting in an outright loss. \[account,
		/// currency_id, amount\]
		DustLost(T::AccountId, T::CurrencyId, T::Balance),
		/// Dust handler change success. \[currency_id, dust_type\]
		DustHandlerChange(T::CurrencyId, DustHandlerType<T::AccountId>),
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The token doesn't exist
		TokenDoesntExist,
		/// This operation will cause balance to overflow
		BalanceOverflow,
		/// This operation will cause total issuance to overflow
		TotalIssuanceOverflow,
		/// Cannot convert Amount into Balance type
		AmountIntoBalanceFailed,
		/// Failed because liquidity restrictions due to locking
		LiquidityRestrictions,
		/// Account still has active reserved
		StillHasActiveReserved,
		/// Account balance must be greater than or equal to the transfer
		/// amount.
		BalanceLow,
		/// Balance should be non-zero.
		BalanceZero,
		/// Amount to be transferred is below minimum existential deposit
		BelowMinimum,
		/// The signing account has no permission to do the operation.
		NoPermission,
		/// The given currency ID is unknown.
		Unknown,
		/// The origin account is frozen.
		Frozen,
		/// The token is frozen
		TokenIsFrozen,
		/// The currency ID is already taken.
		InUse,
		/// Invalid witness data given.
		BadWitness,
		/// Minimum balance should be non-zero.
		MinBalanceZero,
		/// A mint operation lead to an overflow.
		Overflow,
		/// No provider reference exists to allow a non-zero balance of a
		/// non-self-sufficient currency.
		NoProvider,
		/// Invalid metadata given.
		BadMetadata,
		/// No approval exists that would allow the transfer.
		Unapproved,
		/// The source account would not survive the transfer and it needs to
		/// stay alive.
		WouldDie,
		/// Invalid amount,
		InvalidAmount,
	}

	#[pallet::storage]
	#[pallet::getter(fn currency)]
	/// Details of an asset.
	pub(super) type Token<T: Config> =
		StorageMap<_, Blake2_128Concat, T::CurrencyId, TokenDetails<T::Balance, T::AccountId>>;

	#[pallet::storage]
	#[pallet::getter(fn approvals)]
	/// Approved balance transfers. First balance is the amount approved for
	/// transfer. Second is the amount of `T::Currency` reserved for storing
	/// this.
	pub(super) type Approvals<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::CurrencyId,
		Blake2_128Concat,
		ApprovalKey<T::AccountId>,
		Approval<T::Balance>,
		OptionQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn metadata)]
	/// Metadata of an currency.
	pub(super) type Metadata<T: Config> =
		StorageMap<_, Blake2_128Concat, T::CurrencyId, TokenMetadata<T::Balance>, ValueQuery>;

	/// The total issuance of a token type.
	#[pallet::storage]
	#[pallet::getter(fn total_issuance)]
	pub type TotalIssuance<T: Config> = StorageMap<_, Twox64Concat, T::CurrencyId, T::Balance, ValueQuery>;

	/// Any liquidity locks of a token type under an account.
	/// NOTE: Should only be accessed when setting, changing and freeing a lock.
	#[pallet::storage]
	#[pallet::getter(fn locks)]
	pub type Locks<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Twox64Concat,
		T::CurrencyId,
		Vec<BalanceLock<T::Balance>>,
		ValueQuery,
	>;

	/// The balance of an account under a token type.
	///
	/// NOTE: If the total is ever zero, decrease account ref account.
	///
	/// NOTE: This is only used in the case that this module is used to store
	/// balances.
	#[pallet::storage]
	#[pallet::getter(fn accounts)]
	pub type Accounts<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::CurrencyId,
		Twox64Concat,
		T::AccountId,
		AccountData<T::Balance>,
		ValueQuery,
	>;

	/// The balance of an account under a token type.
	///
	/// NOTE: If the total is ever zero, decrease account ref account.
	///
	/// NOTE: This is only used in the case that this module is used to store
	/// balances.
	#[pallet::storage]
	#[pallet::getter(fn account_currencies)]
	pub type AccountCurrencies<T: Config> =
		StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Twox64Concat, T::CurrencyId, bool, ValueQuery>;

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Issue a new class of fungible assets from a public origin.
		///
		/// This new asset class has no assets initially and its owner is the
		/// origin.
		///
		/// The origin must be Signed and the sender must have sufficient funds
		/// free.
		///
		/// Funds of sender are reserved by `CurrencyDeposit`.
		///
		/// Parameters:
		/// - `id`: The identifier of the new asset. This must not be currently
		///   in use to identify
		/// an existing asset.
		/// - `admin`: The admin of this class of assets. The admin is the
		///   initial address of each
		/// member of the asset class's admin team.
		/// - `min_balance`: The minimum balance of this new asset that any
		///   single account must
		/// have. If an account's balance is reduced below this, then it
		/// collapses to zero.
		///
		/// Emits `Created` event when successful.
		///
		/// Weight: `O(5_000_000)`
		#[pallet::weight(5_000_000)]
		pub(super) fn create(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			admin: <T::Lookup as StaticLookup>::Source,
			min_balance: T::Balance,
		) -> DispatchResult {
			let owner = ensure_signed(origin)?;
			let admin = T::Lookup::lookup(admin)?;

			ensure!(!Token::<T>::contains_key(id), Error::<T>::InUse);
			ensure!(!min_balance.is_zero(), Error::<T>::MinBalanceZero);

			let deposit = T::CurrencyDeposit::get();
			T::NativeCurrency::reserve(&owner, deposit)?;

			<Self as ExtendedTokenSystem<_, _, _>>::create(id, owner.clone(), admin.clone(), min_balance)?;
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
		/// - `id`: The identifier of the new asset. This must not be currently
		///   in use to identify
		/// an existing asset.
		/// - `owner`: The owner of this class of assets. The owner has full
		///   superuser permissions
		/// over this asset, but may later change and configure the permissions
		/// using `transfer_ownership` and `set_team`.
		/// - `max_zombies`: The total number of accounts which may hold assets
		///   in this class yet
		/// have no existential deposit.
		/// - `min_balance`: The minimum balance of this new asset that any
		///   single account must
		/// have. If an account's balance is reduced below this, then it
		/// collapses to zero.
		///
		/// Emits `ForceCreated` event when successful.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn force_create(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			min_balance: T::Balance,
		) -> DispatchResult {
			T::ForceOrigin::ensure_origin(origin)?;
			let owner = T::Lookup::lookup(owner)?;

			ensure!(!Token::<T>::contains_key(id), Error::<T>::InUse);
			ensure!(!min_balance.is_zero(), Error::<T>::MinBalanceZero);

			Token::<T>::insert(id, TokenDetails {
				owner: owner.clone(),
				issuer: owner.clone(),
				admin: owner.clone(),
				freezer: owner.clone(),
				supply: Zero::zero(),
				deposit: Zero::zero(),
				min_balance,
				approvals: 0,
				is_frozen: false,
				dust_type: DustHandlerType::Transfer(T::DustAccount::get()),
			});
			Self::deposit_event(Event::ForceCreated(id, owner));
			Ok(())
		}

		/// Destroy a class of fungible assets.
		///
		/// The origin must conform to `ForceOrigin` or must be Signed and the
		/// sender must be the owner of the asset `id`.
		///
		/// - `id`: The identifier of the asset to be destroyed. This must
		///   identify an existing
		/// asset.
		///
		/// Emits `Destroyed` event when successful.
		///
		/// Weight: `O(c + p + a)` where:
		/// - `c = (witness.accounts - witness.sufficients)`
		/// - `s = witness.sufficients`
		/// - `a = witness.approvals`
		#[pallet::weight(5_000_000)]
		pub(super) fn destroy(origin: OriginFor<T>, id: T::CurrencyId) -> DispatchResult {
			let maybe_check_owner = match T::ForceOrigin::try_origin(origin) {
				Ok(_) => None,
				Err(origin) => Some(ensure_signed(origin)?),
			};
			// TODO: Ensure we clean up everything
			Token::<T>::try_mutate_exists(id, |maybe_details| {
				let details = maybe_details.take().ok_or(Error::<T>::Unknown)?;
				if let Some(check_owner) = maybe_check_owner {
					ensure!(details.owner == check_owner, Error::<T>::NoPermission);
				}

				for (who, _v) in Accounts::<T>::drain_prefix(id) {
					Self::dead_account(id, &who);
				}

				let metadata = Metadata::<T>::take(&id);
				T::NativeCurrency::unreserve(&details.owner, details.deposit.saturating_add(metadata.deposit));

				Approvals::<T>::remove_prefix(&id);
				Self::deposit_event(Event::Destroyed(id));

				// NOTE: could use postinfo to reflect the actual number of
				// accounts/sufficient/approvals
				Ok(())
			})
		}

		/// Mint assets of a particular class.
		///
		/// The origin must be Signed and the sender must be the Issuer of the
		/// asset `id`.
		///
		/// - `id`: The identifier of the asset to have some amount minted.
		/// - `beneficiary`: The account to be credited with the minted assets.
		/// - `amount`: The amount of the asset to be minted.
		///
		/// Emits `Destroyed` event when successful.
		///
		/// Weight: `O(1)`
		/// Modes: Pre-existing balance of `beneficiary`; Account pre-existence
		/// of `beneficiary`.
		#[pallet::weight(5_000_000)]
		pub(super) fn mint(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			beneficiary: <T::Lookup as StaticLookup>::Source,
			amount: T::Balance,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let beneficiary = T::Lookup::lookup(beneficiary)?;
			let details = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(sender == details.issuer, Error::<T>::NoPermission);
			ensure!(
				Self::total_balance(id, &beneficiary).saturating_add(amount) >= details.min_balance,
				Error::<T>::BelowMinimum
			);
			<Self as ExtendedTokenSystem<_, _, _>>::mint(id, beneficiary.clone(), amount)?;
			Self::deposit_event(Event::Issued(id, beneficiary, amount));
			Ok(())
		}

		/// Reduce the balance of `who` by as much as possible up to `amount`
		/// assets of `id`.
		///
		/// Origin must be Signed and the sender should be the Manager of the
		/// asset `id`.
		///
		/// Bails with `BalanceZero` if the `who` is already dead.
		///
		/// - `id`: The identifier of the asset to have some amount burned.
		/// - `who`: The account to be debited from.
		/// - `amount`: The maximum amount by which `who`'s balance should be
		///   reduced.
		///
		/// Emits `Burned` with the actual amount burned. If this takes the
		/// balance to below the minimum for the asset, then the amount burned
		/// is increased to take it to zero.
		///
		/// Weight: `O(1)`
		/// Modes: Post-existence of `who`; Pre & post Zombie-status of `who`.
		#[pallet::weight(5_000_000)]
		pub(super) fn burn(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			who: <T::Lookup as StaticLookup>::Source,
			amount: T::Balance,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			let details = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(sender == details.admin, Error::<T>::NoPermission);
			let who = T::Lookup::lookup(who)?;
			<Self as ExtendedTokenSystem<_, _, _>>::burn(id, who.clone(), amount)?;
			Self::deposit_event(Event::Burned(id, who, amount));
			Ok(())
		}

		/// Disallow further unprivileged transfers from an account.
		///
		/// Origin must be Signed and the sender should be the Freezer of the
		/// asset `id`.
		///
		/// - `id`: The identifier of the asset to be frozen.
		/// - `who`: The account to be frozen.
		///
		/// Emits `Frozen`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn freeze(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			who: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;

			let d = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(&origin == &d.freezer, Error::<T>::NoPermission);
			let who = T::Lookup::lookup(who)?;
			ensure!(Accounts::<T>::contains_key(id, &who), Error::<T>::BalanceZero);

			Accounts::<T>::mutate(id, &who, |a| a.is_frozen = true);

			Self::deposit_event(Event::<T>::Frozen(id, who));
			Ok(())
		}

		/// Allow unprivileged transfers from an account again.
		///
		/// Origin must be Signed and the sender should be the Admin of the
		/// asset `id`.
		///
		/// - `id`: The identifier of the asset to be frozen.
		/// - `who`: The account to be unfrozen.
		///
		/// Emits `Thawed`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn thaw(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			who: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;

			let details = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(&origin == &details.admin, Error::<T>::NoPermission);
			let who = T::Lookup::lookup(who)?;
			ensure!(Accounts::<T>::contains_key(id, &who), Error::<T>::BalanceZero);

			Accounts::<T>::mutate(id, &who, |a| a.is_frozen = false);

			Self::deposit_event(Event::<T>::Thawed(id, who));
			Ok(())
		}

		/// Disallow further unprivileged transfers for the asset class.
		///
		/// Origin must be Signed and the sender should be the Freezer of the
		/// asset `id`.
		///
		/// - `id`: The identifier of the asset to be frozen.
		///
		/// Emits `Frozen`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn freeze_asset(origin: OriginFor<T>, id: T::CurrencyId) -> DispatchResult {
			let origin = ensure_signed(origin)?;

			Token::<T>::try_mutate(id, |maybe_details| {
				let d = maybe_details.as_mut().ok_or(Error::<T>::Unknown)?;
				ensure!(&origin == &d.freezer, Error::<T>::NoPermission);

				d.is_frozen = true;

				Self::deposit_event(Event::<T>::TokenFrozen(id));
				Ok(())
			})
		}

		/// Allow unprivileged transfers for the asset again.
		///
		/// Origin must be Signed and the sender should be the Admin of the
		/// asset `id`.
		///
		/// - `id`: The identifier of the asset to be frozen.
		///
		/// Emits `Thawed`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn thaw_asset(origin: OriginFor<T>, id: T::CurrencyId) -> DispatchResult {
			let origin = ensure_signed(origin)?;

			Token::<T>::try_mutate(id, |maybe_details| {
				let d = maybe_details.as_mut().ok_or(Error::<T>::Unknown)?;
				ensure!(&origin == &d.admin, Error::<T>::NoPermission);

				d.is_frozen = false;

				Self::deposit_event(Event::<T>::TokenThawed(id));
				Ok(())
			})
		}

		/// Change the Owner of an asset.
		///
		/// Origin must be Signed and the sender should be the Owner of the
		/// asset `id`.
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
			id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let owner = T::Lookup::lookup(owner)?;

			Token::<T>::try_mutate(id, |maybe_details| {
				let details = maybe_details.as_mut().ok_or(Error::<T>::Unknown)?;
				ensure!(&origin == &details.owner, Error::<T>::NoPermission);
				if details.owner == owner {
					return Ok(());
				}

				let metadata_deposit = Metadata::<T>::get(id).deposit;
				let deposit = details.deposit + metadata_deposit;

				// Move the deposit to the new owner.
				T::NativeCurrency::repatriate_reserved(&details.owner, &owner, deposit, BalanceStatus::Reserved)?;

				details.owner = owner.clone();

				Self::deposit_event(Event::OwnerChanged(id, owner));
				Ok(())
			})
		}

		/// Change the Issuer, Admin and Freezer of an asset.
		///
		/// Origin must be Signed and the sender should be the Owner of the
		/// asset `id`.
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
			id: T::CurrencyId,
			issuer: <T::Lookup as StaticLookup>::Source,
			admin: <T::Lookup as StaticLookup>::Source,
			freezer: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let issuer = T::Lookup::lookup(issuer)?;
			let admin = T::Lookup::lookup(admin)?;
			let freezer = T::Lookup::lookup(freezer)?;

			Token::<T>::try_mutate(id, |maybe_details| {
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
		/// Origin must be Signed and the sender should be the Owner of the
		/// asset `id`.
		///
		/// Funds of sender are reserved according to the formula:
		/// `MetadataDepositBase + MetadataDepositPerByte * (name.len +
		/// symbol.len)` taking into account any already reserved funds.
		///
		/// - `id`: The identifier of the asset to update.
		/// - `name`: The user friendly name of this asset. Limited in length by
		///   `StringLimit`.
		/// - `symbol`: The exchange symbol for this asset. Limited in length by
		///   `StringLimit`.
		/// - `decimals`: The number of decimals this asset uses to represent
		///   one unit.
		///
		/// Emits `MetadataSet`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn set_metadata(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			name: Vec<u8>,
			symbol: Vec<u8>,
			decimals: u8,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;

			ensure!(name.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);
			ensure!(symbol.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);

			let d = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(&origin == &d.owner, Error::<T>::NoPermission);

			Metadata::<T>::try_mutate_exists(id, |metadata| {
				ensure!(
					metadata.as_ref().map_or(true, |m| !m.is_frozen),
					Error::<T>::NoPermission
				);

				let old_deposit = metadata.take().map_or(Zero::zero(), |m| m.deposit);
				let new_deposit = T::MetadataDepositPerByte::get()
					.saturating_mul(((name.len() + symbol.len()) as u32).into())
					.saturating_add(T::MetadataDepositBase::get());

				if new_deposit > old_deposit {
					T::NativeCurrency::reserve(&origin, new_deposit - old_deposit)?;
				} else {
					T::NativeCurrency::unreserve(&origin, old_deposit - new_deposit);
				}

				*metadata = Some(TokenMetadata {
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
		/// Origin must be Signed and the sender should be the Owner of the
		/// asset `id`.
		///
		/// Any deposit is freed for the asset owner.
		///
		/// - `id`: The identifier of the asset to clear.
		///
		/// Emits `MetadataCleared`.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn clear_metadata(origin: OriginFor<T>, id: T::CurrencyId) -> DispatchResult {
			let origin = ensure_signed(origin)?;

			let d = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(&origin == &d.owner, Error::<T>::NoPermission);

			Metadata::<T>::try_mutate_exists(id, |metadata| {
				let deposit = metadata.take().ok_or(Error::<T>::Unknown)?.deposit;
				T::NativeCurrency::unreserve(&d.owner, deposit);
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
		/// - `name`: The user friendly name of this asset. Limited in length by
		///   `StringLimit`.
		/// - `symbol`: The exchange symbol for this asset. Limited in length by
		///   `StringLimit`.
		/// - `decimals`: The number of decimals this asset uses to represent
		///   one unit.
		///
		/// Emits `MetadataSet`.
		///
		/// Weight: `O(N + S)` where N and S are the length of the name and
		/// symbol respectively.
		#[pallet::weight(5_000_000)]
		pub(super) fn force_set_metadata(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			name: Vec<u8>,
			symbol: Vec<u8>,
			decimals: u8,
			is_frozen: bool,
		) -> DispatchResult {
			T::ForceOrigin::ensure_origin(origin)?;

			ensure!(name.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);
			ensure!(symbol.len() <= T::StringLimit::get() as usize, Error::<T>::BadMetadata);

			ensure!(Token::<T>::contains_key(id), Error::<T>::Unknown);
			Metadata::<T>::try_mutate_exists(id, |metadata| {
				let deposit = metadata.take().map_or(Zero::zero(), |m| m.deposit);
				*metadata = Some(TokenMetadata {
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
		pub(super) fn force_clear_metadata(origin: OriginFor<T>, id: T::CurrencyId) -> DispatchResult {
			T::ForceOrigin::ensure_origin(origin)?;

			let d = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			Metadata::<T>::try_mutate_exists(id, |metadata| {
				let deposit = metadata.take().ok_or(Error::<T>::Unknown)?.deposit;
				T::NativeCurrency::unreserve(&d.owner, deposit);
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
		/// - `min_balance`: The minimum balance of this new asset that any
		///   single account must
		/// have. If an account's balance is reduced below this, then it
		/// collapses to zero.
		/// - `is_frozen`: Whether this asset class is frozen except for
		///   permissioned/admin
		/// instructions.
		///
		/// Emits `CurrencyStatusChanged` with the identity of the asset.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn force_asset_status(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			issuer: <T::Lookup as StaticLookup>::Source,
			admin: <T::Lookup as StaticLookup>::Source,
			freezer: <T::Lookup as StaticLookup>::Source,
			min_balance: T::Balance,
			is_frozen: bool,
		) -> DispatchResult {
			T::ForceOrigin::ensure_origin(origin)?;

			Token::<T>::try_mutate(id, |maybe_asset| {
				let mut asset = maybe_asset.take().ok_or(Error::<T>::Unknown)?;
				asset.owner = T::Lookup::lookup(owner)?;
				asset.issuer = T::Lookup::lookup(issuer)?;
				asset.admin = T::Lookup::lookup(admin)?;
				asset.freezer = T::Lookup::lookup(freezer)?;
				asset.min_balance = min_balance;
				asset.is_frozen = is_frozen;
				*maybe_asset = Some(asset);

				Self::deposit_event(Event::CurrencyStatusChanged(id));
				Ok(())
			})
		}

		/// Approve an amount of asset for transfer by a delegated third-party
		/// account.
		///
		/// Origin must be Signed.
		///
		/// Ensures that `ApprovalDeposit` worth of `Currency` is reserved from
		/// signing account for the purpose of holding the approval. If some
		/// non-zero amount of assets is already approved from signing account
		/// to `delegate`, then it is topped up or unreserved to meet the right
		/// value.
		///
		/// NOTE: The signing account does not need to own `amount` of assets at
		/// the point of making this call.
		///
		/// - `id`: The identifier of the asset.
		/// - `delegate`: The account to delegate permission to transfer asset.
		/// - `amount`: The amount of asset that may be transferred by
		///   `delegate`. If there is
		/// already an approval in place, then this acts additively.
		///
		/// Emits `ApprovedTransfer` on success.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn approve_transfer(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			delegate: <T::Lookup as StaticLookup>::Source,
			amount: T::Balance,
		) -> DispatchResult {
			let owner = ensure_signed(origin)?;
			let delegate = T::Lookup::lookup(delegate)?;

			let key = ApprovalKey { owner, delegate };
			Approvals::<T>::try_mutate(id, &key, |maybe_approved| -> DispatchResult {
				let mut approved = maybe_approved.take().unwrap_or_default();
				let deposit_required = T::ApprovalDeposit::get();
				if approved.deposit < deposit_required {
					T::NativeCurrency::reserve(&key.owner, deposit_required - approved.deposit)?;
					approved.deposit = deposit_required;
				}
				approved.amount = approved.amount.saturating_add(amount);
				*maybe_approved = Some(approved);
				Ok(())
			})?;
			Self::deposit_event(Event::ApprovedTransfer(id, key.owner, key.delegate, amount));

			Ok(())
		}

		/// Cancel all of some asset approved for delegated transfer by a
		/// third-party account.
		///
		/// Origin must be Signed and there must be an approval in place between
		/// signer and `delegate`.
		///
		/// Unreserves any deposit previously reserved by `approve_transfer` for
		/// the approval.
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
			id: T::CurrencyId,
			delegate: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			let owner = ensure_signed(origin)?;
			let delegate = T::Lookup::lookup(delegate)?;
			let key = ApprovalKey { owner, delegate };
			let approval = Approvals::<T>::take(id, &key).ok_or(Error::<T>::Unknown)?;
			T::NativeCurrency::unreserve(&key.owner, approval.deposit);

			Self::deposit_event(Event::ApprovalCancelled(id, key.owner, key.delegate));
			Ok(())
		}

		/// Cancel all of some asset approved for delegated transfer by a
		/// third-party account.
		///
		/// Origin must be either ForceOrigin or Signed origin with the signer
		/// being the Admin account of the asset `id`.
		///
		/// Unreserves any deposit previously reserved by `approve_transfer` for
		/// the approval.
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
			id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			delegate: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			T::ForceOrigin::try_origin(origin)
				.map(|_| ())
				.or_else(|origin| -> DispatchResult {
					let origin = ensure_signed(origin)?;
					let d = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
					ensure!(&origin == &d.admin, Error::<T>::NoPermission);
					Ok(())
				})?;

			let owner = T::Lookup::lookup(owner)?;
			let delegate = T::Lookup::lookup(delegate)?;

			let key = ApprovalKey { owner, delegate };
			let approval = Approvals::<T>::take(id, &key).ok_or(Error::<T>::Unknown)?;
			T::NativeCurrency::unreserve(&key.owner, approval.deposit);

			Self::deposit_event(Event::ApprovalCancelled(id, key.owner, key.delegate));
			Ok(())
		}

		/// Transfer some asset balance from a previously delegated account to
		/// some third-party account.
		///
		/// Origin must be Signed and there must be an approval in place by the
		/// `owner` to the signer.
		///
		/// If the entire amount approved for transfer is transferred, then any
		/// deposit previously reserved by `approve_transfer` is unreserved.
		///
		/// - `id`: The identifier of the asset.
		/// - `owner`: The account which previously approved for a transfer of
		///   at least `amount` and
		/// from which the asset balance will be withdrawn.
		/// - `destination`: The account to which the asset balance of `amount`
		///   will be transferred.
		/// - `amount`: The amount of assets to transfer.
		///
		/// Emits `TransferredApproved` on success.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn transfer_approved(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			owner: <T::Lookup as StaticLookup>::Source,
			destination: <T::Lookup as StaticLookup>::Source,
			amount: T::Balance,
		) -> DispatchResult {
			let delegate = ensure_signed(origin)?;
			let owner = T::Lookup::lookup(owner)?;
			let destination = T::Lookup::lookup(destination)?;

			let key = ApprovalKey { owner, delegate };
			Approvals::<T>::try_mutate_exists(id, &key, |maybe_approved| -> DispatchResult {
				let mut approved = maybe_approved.take().ok_or(Error::<T>::Unapproved)?;
				let remaining = approved.amount.checked_sub(&amount).ok_or(Error::<T>::Unapproved)?;

				<Self as MultiCurrency<_>>::transfer(id, &key.owner, &destination, amount)?;

				if remaining.is_zero() {
					T::NativeCurrency::unreserve(&key.owner, approved.deposit);
				} else {
					approved.amount = remaining;
					*maybe_approved = Some(approved);
				}
				Ok(())
			})?;
			Ok(())
		}

		/// Transfer some balance to another account.
		///
		/// The dispatch origin for this call must be `Signed` by the
		/// transactor.
		#[pallet::weight(5_000_000)]
		pub fn transfer(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			dest: <T::Lookup as StaticLookup>::Source,
			amount: T::Balance,
		) -> DispatchResult {
			let from = ensure_signed(origin)?;
			let to = T::Lookup::lookup(dest)?;
			let details = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(!details.is_frozen, Error::<T>::TokenIsFrozen);
			let account_details = Accounts::<T>::get(id, from.clone());
			ensure!(!account_details.is_frozen, Error::<T>::Frozen);

			<Self as MultiCurrency<_>>::transfer(id, &from, &to, amount)?;
			Self::deposit_event(Event::Transferred(id, from, to, amount));
			Ok(().into())
		}

		/// Transfer all remaining balance to the given account.
		///
		/// The dispatch origin for this call must be `Signed` by the
		/// transactor.
		#[pallet::weight(5_000_000)]
		pub fn transfer_all(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			dest: <T::Lookup as StaticLookup>::Source,
		) -> DispatchResult {
			let from = ensure_signed(origin)?;
			let to = T::Lookup::lookup(dest)?;
			let details = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(!details.is_frozen, Error::<T>::TokenIsFrozen);
			let account_details = Accounts::<T>::get(id, from.clone());
			ensure!(!account_details.is_frozen, Error::<T>::Frozen);

			let balance = <Self as MultiCurrency<T::AccountId>>::free_balance(id, &from);
			<Self as MultiCurrency<T::AccountId>>::transfer(id, &from, &to, balance)?;

			Self::deposit_event(Event::Transferred(id, from, to, balance));
			Ok(().into())
		}

		/// Move some assets from the sender account to another, keeping the
		/// sender account alive.
		///
		/// Origin must be Signed.
		///
		/// - `id`: The identifier of the asset to have some amount transferred.
		/// - `target`: The account to be credited.
		/// - `amount`: The amount by which the sender's balance of assets
		///   should be reduced and
		/// `target`'s balance increased. The amount actually transferred may be
		/// slightly greater in the case that the transfer would otherwise take
		/// the sender balance above zero but below the minimum balance. Must be
		/// greater than zero.
		///
		/// Emits `Transferred` with the actual amount transferred. If this
		/// takes the source balance to below the minimum for the asset, then
		/// the amount transferred is increased to take it to zero.
		///
		/// Weight: `O(1)`
		/// Modes: Pre-existence of `target`; Post-existence of sender; Prior &
		/// post zombie-status of sender; Account pre-existence of `target`.
		#[pallet::weight(5_000_000)]
		pub(super) fn transfer_keep_alive(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			target: <T::Lookup as StaticLookup>::Source,
			amount: T::Balance,
		) -> DispatchResult {
			let from = ensure_signed(origin)?;
			let to = T::Lookup::lookup(target)?;
			let balance = <Self as MultiCurrency<T::AccountId>>::free_balance(id, &from);
			let details = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			ensure!(!details.is_frozen, Error::<T>::TokenIsFrozen);
			let account_details = Accounts::<T>::get(id, from.clone());
			ensure!(!account_details.is_frozen, Error::<T>::Frozen);
			// Check balance to ensure account is kept alive
			ensure!(balance - amount >= details.min_balance, Error::<T>::WouldDie);
			<Self as MultiCurrency<T::AccountId>>::transfer(id, &from, &to, amount)?;
			Self::deposit_event(Event::Transferred(id, from, to, amount));

			Ok(().into())
		}

		/// Move some assets from one account to another.
		///
		/// Origin must be Signed and the sender should be the Admin of the
		/// asset `id`.
		///
		/// - `id`: The identifier of the asset to have some amount transferred.
		/// - `source`: The account to be debited.
		/// - `dest`: The account to be credited.
		/// - `amount`: The amount by which the `source`'s balance of assets
		///   should be reduced and
		/// `dest`'s balance increased. The amount actually transferred may be
		/// slightly greater in the case that the transfer would otherwise take
		/// the `source` balance above zero but below the minimum balance. Must
		/// be greater than zero.
		///
		/// Emits `Transferred` with the actual amount transferred. If this
		/// takes the source balance to below the minimum for the asset, then
		/// the amount transferred is increased to take it to zero.
		///
		/// Weight: `O(1)`
		/// Modes: Pre-existence of `dest`; Post-existence of `source`; Prior &
		/// post zombie-status of `source`; Account pre-existence of `dest`.
		#[pallet::weight(T::WeightInfo::force_transfer())]
		pub(super) fn force_transfer(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			source: <T::Lookup as StaticLookup>::Source,
			dest: <T::Lookup as StaticLookup>::Source,
			amount: T::Balance,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let from = T::Lookup::lookup(source)?;
			let to = T::Lookup::lookup(dest)?;

			let details = Token::<T>::get(id).ok_or(Error::<T>::Unknown)?;
			// Check admin rights.
			ensure!(&origin == &details.admin, Error::<T>::NoPermission);
			<Self as MultiCurrency<T::AccountId>>::transfer(id, &from, &to, amount)?;
			Self::deposit_event(Event::Transferred(id, from, to, amount));
			Ok(())
		}

		/// Set the dust handler type.
		///
		/// Origin must be Signed and the sender should be the Admin of the
		/// asset `id`.
		///
		/// - `id`: The identifier of the asset to have some amount transferred.
		/// - `source`: The account to be debited.
		/// - `dest`: The account to be credited.
		/// - `amount`: The amount by which the `source`'s balance of assets
		///   should be reduced and
		/// `dest`'s balance increased. The amount actually transferred may be
		/// slightly greater in the case that the transfer would otherwise take
		/// the `source` balance above zero but below the minimum balance. Must
		/// be greater than zero.
		///
		/// Emits `DustHandlerChange` with the currency_id and new handler type.
		///
		/// Weight: `O(1)`
		#[pallet::weight(5_000_000)]
		pub(super) fn set_dust_type(
			origin: OriginFor<T>,
			id: T::CurrencyId,
			dust_type: DustHandlerType<T::AccountId>,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;

			Token::<T>::try_mutate(id, |maybe_details| {
				let details = maybe_details.as_mut().ok_or(Error::<T>::Unknown)?;
				ensure!(&origin == &details.admin, Error::<T>::NoPermission);

				details.dust_type = dust_type.clone();
				Self::deposit_event(Event::DustHandlerChange(id, dust_type));
				Ok(())
			})
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Check whether account_id is a module account
	pub(crate) fn is_module_account_id(account_id: &T::AccountId) -> bool {
		PalletId::try_from_account(account_id).is_some()
	}

	pub(crate) fn try_mutate_account<R, E>(
		who: &T::AccountId,
		currency_id: T::CurrencyId,
		f: impl FnOnce(&mut AccountData<T::Balance>, bool) -> sp_std::result::Result<R, E>,
	) -> sp_std::result::Result<R, E> {
		Accounts::<T>::try_mutate_exists(currency_id, who, |maybe_account| {
			let existed = maybe_account.is_some();
			let mut account = maybe_account.take().unwrap_or_default();
			f(&mut account, existed).map(move |result| {
				let mut handle_dust: Option<T::Balance> = None;
				let total = account.total();
				*maybe_account = if total.is_zero() {
					None
				} else {
					// if non_zero total is below existential deposit and the account is not a
					// module account, should handle the dust.
					let token = Token::<T>::get(currency_id);
					match token {
						Some(token_data) => {
							if total < token_data.min_balance && !Self::is_module_account_id(who) {
								handle_dust = Some(total);
							}
							Some(account)
						}
						None => None,
					}
				};

				(existed, maybe_account.is_some(), handle_dust, result)
			})
		})
		.map(|(existed, exists, handle_dust, result)| {
			if existed && !exists {
				// If existed before, decrease account provider.
				// Ignore the result, because if it failed means that these’s remain consumers,
				// and the account storage in frame_system shouldn't be repeaded.
				let _ = frame_system::Pallet::<T>::dec_providers(who);
			} else if !existed && exists {
				// Add existential currency identifier to this account
				AccountCurrencies::<T>::insert(who, currency_id, true);
				// if new, increase account provider
				frame_system::Pallet::<T>::inc_providers(who);
			}

			if let Some(dust_amount) = handle_dust {
				// Remove existential currency identifier to this account
				AccountCurrencies::<T>::remove(who, currency_id);
				// `OnDust` maybe get/set storage `Accounts` of `who`, trigger handler here
				// to avoid some unexpected errors.
				<Self as ExtendedTokenSystem<_, _, _>>::handle_dust(currency_id, who, dust_amount);
				Self::deposit_event(Event::DustLost(who.clone(), currency_id, dust_amount));
			}

			result
		})
	}

	pub(crate) fn mutate_account<R>(
		who: &T::AccountId,
		currency_id: T::CurrencyId,
		f: impl FnOnce(&mut AccountData<T::Balance>, bool) -> R,
	) -> R {
		Self::try_mutate_account(who, currency_id, |account, existed| -> Result<R, Infallible> {
			Ok(f(account, existed))
		})
		.expect("Error is infallible; qed")
	}

	/// Set free balance of `who` to a new value.
	///
	/// Note this will not maintain total issuance, and the caller is
	/// expected to do it.
	pub(crate) fn set_free_balance(currency_id: T::CurrencyId, who: &T::AccountId, amount: T::Balance) {
		Self::mutate_account(who, currency_id, |account, _| {
			account.free = amount;
		});
	}

	/// Set reserved balance of `who` to a new value.
	///
	/// Note this will not maintain total issuance, and the caller is
	/// expected to do it.
	pub(crate) fn set_reserved_balance(currency_id: T::CurrencyId, who: &T::AccountId, amount: T::Balance) {
		Self::mutate_account(who, currency_id, |account, _| {
			account.reserved = amount;
		});
	}

	/// Update the account entry for `who` under `currency_id`, given the
	/// locks.
	pub(crate) fn update_locks(currency_id: T::CurrencyId, who: &T::AccountId, locks: &[BalanceLock<T::Balance>]) {
		// update account data
		Self::mutate_account(who, currency_id, |account, _| {
			account.frozen = Zero::zero();
			for lock in locks.iter() {
				account.frozen = account.frozen.max(lock.amount);
			}
		});

		// update locks
		let existed = <Locks<T>>::contains_key(who, currency_id);
		if locks.is_empty() {
			<Locks<T>>::remove(who, currency_id);
			if existed {
				// decrease account ref count when destruct lock
				frame_system::Pallet::<T>::dec_consumers(who);
			}
		} else {
			<Locks<T>>::insert(who, currency_id, locks);
			if !existed {
				// increase account ref count when initialize lock
				if frame_system::Pallet::<T>::inc_consumers(who).is_err() {
					// No providers for the locks. This is impossible under normal circumstances
					// since the funds that are under the lock will themselves be stored in the
					// account and therefore will need a reference.
					log::warn!(
						"Warning: Attempt to introduce lock consumer reference, yet no providers. \
						This is unexpected but should be safe."
					);
				}
			}
		}
	}

	pub(crate) fn dead_account(id: T::CurrencyId, who: &T::AccountId) {
		frame_system::Pallet::<T>::dec_consumers(who);
		AccountCurrencies::<T>::remove(who, id)
	}
}

impl<T: Config> MultiCurrency<T::AccountId> for Pallet<T> {
	type Balance = T::Balance;
	type CurrencyId = T::CurrencyId;

	fn minimum_balance(currency_id: Self::CurrencyId) -> Self::Balance {
		match Token::<T>::get(currency_id) {
			Some(token_data) => token_data.min_balance,
			None => u32::max_value().into(),
		}
	}

	fn total_issuance(currency_id: Self::CurrencyId) -> Self::Balance {
		<TotalIssuance<T>>::get(currency_id)
	}

	fn total_balance(currency_id: Self::CurrencyId, who: &T::AccountId) -> Self::Balance {
		Self::accounts(currency_id, who).total()
	}

	fn free_balance(currency_id: Self::CurrencyId, who: &T::AccountId) -> Self::Balance {
		Self::accounts(currency_id, who).free
	}

	// Ensure that an account can withdraw from their free balance given any
	// existing withdrawal restrictions like locks and vesting balance.
	// Is a no-op if amount to be withdrawn is zero.
	fn ensure_can_withdraw(currency_id: Self::CurrencyId, who: &T::AccountId, amount: Self::Balance) -> DispatchResult {
		if amount.is_zero() {
			return Ok(());
		}

		let new_balance = Self::free_balance(currency_id, who)
			.checked_sub(&amount)
			.ok_or(Error::<T>::BalanceLow)?;
		ensure!(
			new_balance >= Self::accounts(currency_id, who).frozen(),
			Error::<T>::LiquidityRestrictions
		);
		Ok(())
	}

	/// Transfer some free balance from `from` to `to`.
	/// Is a no-op if value to be transferred is zero or the `from` is the
	/// same as `to`.
	fn transfer(
		currency_id: Self::CurrencyId,
		from: &T::AccountId,
		to: &T::AccountId,
		amount: Self::Balance,
	) -> DispatchResult {
		if amount.is_zero() || from == to {
			return Ok(());
		}

		Self::ensure_can_withdraw(currency_id, from, amount)?;

		let from_balance = Self::free_balance(currency_id, from);
		let to_balance = Self::free_balance(currency_id, to)
			.checked_add(&amount)
			.ok_or(Error::<T>::BalanceOverflow)?;

		let details = Token::<T>::get(currency_id).ok_or(Error::<T>::Unknown)?;
		if !Self::is_module_account_id(to) {
			ensure!(to_balance >= details.min_balance, Error::<T>::BelowMinimum);
		}

		// check if sender goes below min balance and send remaining to recipient
		let dust = if from_balance - amount < details.min_balance {
			from_balance - amount
		} else {
			T::Balance::zero()
		};

		// update the sender's balance in the event there is dust being reaped
		let new_from_balance = if dust > T::Balance::zero() {
			T::Balance::zero()
		} else {
			from_balance - amount
		};

		// Cannot underflow because ensure_can_withdraw check
		Self::set_free_balance(currency_id, from, new_from_balance);
		Self::set_free_balance(currency_id, to, to_balance + dust);

		Ok(())
	}

	/// Deposit some `amount` into the free balance of account `who`.
	///
	/// Is a no-op if the `amount` to be deposited is zero.
	fn deposit(currency_id: Self::CurrencyId, who: &T::AccountId, amount: Self::Balance) -> DispatchResult {
		if amount.is_zero() {
			return Ok(());
		}

		TotalIssuance::<T>::try_mutate(currency_id, |total_issuance| -> DispatchResult {
			*total_issuance = total_issuance
				.checked_add(&amount)
				.ok_or(Error::<T>::TotalIssuanceOverflow)?;

			Self::set_free_balance(currency_id, who, Self::free_balance(currency_id, who) + amount);

			Ok(())
		})
	}

	fn withdraw(currency_id: Self::CurrencyId, who: &T::AccountId, amount: Self::Balance) -> DispatchResult {
		if amount.is_zero() {
			return Ok(());
		}
		Self::ensure_can_withdraw(currency_id, who, amount)?;
		// Cannot underflow because ensure_can_withdraw check
		<TotalIssuance<T>>::mutate(currency_id, |v| *v -= amount);
		Self::set_free_balance(currency_id, who, Self::free_balance(currency_id, who) - amount);
		Ok(())
	}

	// Check if `value` amount of free balance can be slashed from `who`.
	fn can_slash(currency_id: Self::CurrencyId, who: &T::AccountId, value: Self::Balance) -> bool {
		if value.is_zero() {
			return true;
		}
		Self::free_balance(currency_id, who) >= value
	}

	/// Is a no-op if `value` to be slashed is zero.
	///
	/// NOTE: `slash()` prefers free balance, but assumes that reserve
	/// balance can be drawn from in extreme circumstances. `can_slash()`
	/// should be used prior to `slash()` to avoid having to draw from
	/// reserved funds, however we err on the side of punishment if things
	/// are inconsistent or `can_slash` wasn't used appropriately.
	fn slash(currency_id: Self::CurrencyId, who: &T::AccountId, amount: Self::Balance) -> Self::Balance {
		if amount.is_zero() {
			return amount;
		}

		let account = Self::accounts(currency_id, who);
		let free_slashed_amount = account.free.min(amount);
		// Cannot underflow becuase free_slashed_amount can never be greater than amount
		let mut remaining_slash = amount - free_slashed_amount;

		// slash free balance
		if !free_slashed_amount.is_zero() {
			// Cannot underflow becuase free_slashed_amount can never be greater than
			// account.free
			Self::set_free_balance(currency_id, who, account.free - free_slashed_amount);
		}

		// slash reserved balance
		if !remaining_slash.is_zero() {
			let reserved_slashed_amount = account.reserved.min(remaining_slash);
			// Cannot underflow due to above line
			remaining_slash -= reserved_slashed_amount;
			Self::set_reserved_balance(currency_id, who, account.reserved - reserved_slashed_amount);
		}

		// Cannot underflow because the slashed value cannot be greater than total
		// issuance
		<TotalIssuance<T>>::mutate(currency_id, |v| *v -= amount - remaining_slash);
		remaining_slash
	}
}

impl<T: Config> MultiCurrencyExtended<T::AccountId> for Pallet<T> {
	type Amount = T::Amount;

	fn update_balance(currency_id: Self::CurrencyId, who: &T::AccountId, by_amount: Self::Amount) -> DispatchResult {
		if by_amount.is_zero() {
			return Ok(());
		}

		// Ensure this doesn't overflow. There isn't any traits that exposes
		// `saturating_abs` so we need to do it manually.
		let by_amount_abs = if by_amount == Self::Amount::min_value() {
			Self::Amount::max_value()
		} else {
			by_amount.abs()
		};

		let by_balance =
			TryInto::<Self::Balance>::try_into(by_amount_abs).map_err(|_| Error::<T>::AmountIntoBalanceFailed)?;
		if by_amount.is_positive() {
			Self::deposit(currency_id, who, by_balance)
		} else {
			Self::withdraw(currency_id, who, by_balance).map(|_| ())
		}
	}
}

impl<T: Config> MultiLockableCurrency<T::AccountId> for Pallet<T> {
	type Moment = T::BlockNumber;

	// Set a lock on the balance of `who` under `currency_id`.
	// Is a no-op if lock amount is zero.
	fn set_lock(
		lock_id: LockIdentifier,
		currency_id: Self::CurrencyId,
		who: &T::AccountId,
		amount: Self::Balance,
	) -> DispatchResult {
		if amount.is_zero() {
			return Ok(());
		}
		let mut new_lock = Some(BalanceLock { id: lock_id, amount });
		let mut locks = Self::locks(who, currency_id)
			.into_iter()
			.filter_map(|lock| {
				if lock.id == lock_id {
					new_lock.take()
				} else {
					Some(lock)
				}
			})
			.collect::<Vec<_>>();
		if let Some(lock) = new_lock {
			locks.push(lock)
		}
		Self::update_locks(currency_id, who, &locks[..]);
		Ok(())
	}

	// Extend a lock on the balance of `who` under `currency_id`.
	// Is a no-op if lock amount is zero
	fn extend_lock(
		lock_id: LockIdentifier,
		currency_id: Self::CurrencyId,
		who: &T::AccountId,
		amount: Self::Balance,
	) -> DispatchResult {
		if amount.is_zero() {
			return Ok(());
		}
		let mut new_lock = Some(BalanceLock { id: lock_id, amount });
		let mut locks = Self::locks(who, currency_id)
			.into_iter()
			.filter_map(|lock| {
				if lock.id == lock_id {
					new_lock.take().map(|nl| BalanceLock {
						id: lock.id,
						amount: lock.amount.max(nl.amount),
					})
				} else {
					Some(lock)
				}
			})
			.collect::<Vec<_>>();
		if let Some(lock) = new_lock {
			locks.push(lock)
		}
		Self::update_locks(currency_id, who, &locks[..]);
		Ok(())
	}

	fn remove_lock(lock_id: LockIdentifier, currency_id: Self::CurrencyId, who: &T::AccountId) -> DispatchResult {
		let mut locks = Self::locks(who, currency_id);
		locks.retain(|lock| lock.id != lock_id);
		Self::update_locks(currency_id, who, &locks[..]);
		Ok(())
	}
}

impl<T: Config> MultiReservableCurrency<T::AccountId> for Pallet<T> {
	/// Check if `who` can reserve `value` from their free balance.
	///
	/// Always `true` if value to be reserved is zero.
	fn can_reserve(currency_id: Self::CurrencyId, who: &T::AccountId, value: Self::Balance) -> bool {
		if value.is_zero() {
			return true;
		}
		Self::ensure_can_withdraw(currency_id, who, value).is_ok()
	}

	/// Slash from reserved balance, returning any amount that was unable to
	/// be slashed.
	///
	/// Is a no-op if the value to be slashed is zero.
	fn slash_reserved(currency_id: Self::CurrencyId, who: &T::AccountId, value: Self::Balance) -> Self::Balance {
		if value.is_zero() {
			return value;
		}

		let reserved_balance = Self::reserved_balance(currency_id, who);
		let actual = reserved_balance.min(value);
		Self::set_reserved_balance(currency_id, who, reserved_balance - actual);
		<TotalIssuance<T>>::mutate(currency_id, |v| *v -= actual);
		value - actual
	}

	fn reserved_balance(currency_id: Self::CurrencyId, who: &T::AccountId) -> Self::Balance {
		Self::accounts(currency_id, who).reserved
	}

	/// Move `value` from the free balance from `who` to their reserved
	/// balance.
	///
	/// Is a no-op if value to be reserved is zero.
	fn reserve(currency_id: Self::CurrencyId, who: &T::AccountId, value: Self::Balance) -> DispatchResult {
		if value.is_zero() {
			return Ok(());
		}
		Self::ensure_can_withdraw(currency_id, who, value)?;

		let account = Self::accounts(currency_id, who);
		Self::set_free_balance(currency_id, who, account.free - value);
		// Cannot overflow becuase total issuance is using the same balance type and
		// this doesn't increase total issuance
		Self::set_reserved_balance(currency_id, who, account.reserved + value);
		Ok(())
	}

	/// Unreserve some funds, returning any amount that was unable to be
	/// unreserved.
	///
	/// Is a no-op if the value to be unreserved is zero.
	fn unreserve(currency_id: Self::CurrencyId, who: &T::AccountId, value: Self::Balance) -> Self::Balance {
		if value.is_zero() {
			return value;
		}

		let account = Self::accounts(currency_id, who);
		let actual = account.reserved.min(value);
		Self::set_reserved_balance(currency_id, who, account.reserved - actual);
		Self::set_free_balance(currency_id, who, account.free + actual);

		value - actual
	}

	/// Move the reserved balance of one account into the balance of
	/// another, according to `status`.
	///
	/// Is a no-op if:
	/// - the value to be moved is zero; or
	/// - the `slashed` id equal to `beneficiary` and the `status` is
	///   `Reserved`.
	fn repatriate_reserved(
		currency_id: Self::CurrencyId,
		slashed: &T::AccountId,
		beneficiary: &T::AccountId,
		value: Self::Balance,
		status: BalanceStatus,
	) -> sp_std::result::Result<Self::Balance, DispatchError> {
		if value.is_zero() {
			return Ok(value);
		}

		if slashed == beneficiary {
			return match status {
				BalanceStatus::Free => Ok(Self::unreserve(currency_id, slashed, value)),
				BalanceStatus::Reserved => Ok(value.saturating_sub(Self::reserved_balance(currency_id, slashed))),
			};
		}

		let from_account = Self::accounts(currency_id, slashed);
		let to_account = Self::accounts(currency_id, beneficiary);
		let actual = from_account.reserved.min(value);
		match status {
			BalanceStatus::Free => {
				Self::set_free_balance(currency_id, beneficiary, to_account.free + actual);
			}
			BalanceStatus::Reserved => {
				Self::set_reserved_balance(currency_id, beneficiary, to_account.reserved + actual);
			}
		}
		Self::set_reserved_balance(currency_id, slashed, from_account.reserved - actual);
		Ok(value - actual)
	}
}

pub struct CurrencyAdapter<T, GetCurrencyId>(marker::PhantomData<(T, GetCurrencyId)>);

impl<T, GetCurrencyId> PalletCurrency<T::AccountId> for CurrencyAdapter<T, GetCurrencyId>
where
	T: Config,
	GetCurrencyId: Get<T::CurrencyId>,
{
	type Balance = T::Balance;
	type NegativeImbalance = NegativeImbalance<T, GetCurrencyId>;
	type PositiveImbalance = PositiveImbalance<T, GetCurrencyId>;

	fn total_balance(who: &T::AccountId) -> Self::Balance {
		Pallet::<T>::total_balance(GetCurrencyId::get(), who)
	}

	fn can_slash(who: &T::AccountId, value: Self::Balance) -> bool {
		Pallet::<T>::can_slash(GetCurrencyId::get(), who, value)
	}

	fn total_issuance() -> Self::Balance {
		Pallet::<T>::total_issuance(GetCurrencyId::get())
	}

	fn minimum_balance() -> Self::Balance {
		Pallet::<T>::minimum_balance(GetCurrencyId::get())
	}

	fn burn(mut amount: Self::Balance) -> Self::PositiveImbalance {
		if amount.is_zero() {
			return PositiveImbalance::zero();
		}
		<TotalIssuance<T>>::mutate(GetCurrencyId::get(), |issued| {
			*issued = issued.checked_sub(&amount).unwrap_or_else(|| {
				amount = *issued;
				Zero::zero()
			});
		});
		PositiveImbalance::new(amount)
	}

	fn issue(mut amount: Self::Balance) -> Self::NegativeImbalance {
		if amount.is_zero() {
			return NegativeImbalance::zero();
		}
		<TotalIssuance<T>>::mutate(GetCurrencyId::get(), |issued| {
			*issued = issued.checked_add(&amount).unwrap_or_else(|| {
				amount = Self::Balance::max_value() - *issued;
				Self::Balance::max_value()
			})
		});
		NegativeImbalance::new(amount)
	}

	fn free_balance(who: &T::AccountId) -> Self::Balance {
		Pallet::<T>::free_balance(GetCurrencyId::get(), who)
	}

	fn ensure_can_withdraw(
		who: &T::AccountId,
		amount: Self::Balance,
		_reasons: WithdrawReasons,
		_new_balance: Self::Balance,
	) -> DispatchResult {
		Pallet::<T>::ensure_can_withdraw(GetCurrencyId::get(), who, amount)
	}

	fn transfer(
		source: &T::AccountId,
		dest: &T::AccountId,
		value: Self::Balance,
		_existence_requirement: ExistenceRequirement,
	) -> DispatchResult {
		<Pallet<T> as MultiCurrency<T::AccountId>>::transfer(GetCurrencyId::get(), &source, &dest, value)
	}

	fn slash(who: &T::AccountId, value: Self::Balance) -> (Self::NegativeImbalance, Self::Balance) {
		if value.is_zero() {
			return (Self::NegativeImbalance::zero(), value);
		}

		let currency_id = GetCurrencyId::get();
		let account = Pallet::<T>::accounts(currency_id, who);
		let free_slashed_amount = account.free.min(value);
		let mut remaining_slash = value - free_slashed_amount;

		// slash free balance
		if !free_slashed_amount.is_zero() {
			Pallet::<T>::set_free_balance(currency_id, who, account.free - free_slashed_amount);
		}

		// slash reserved balance
		if !remaining_slash.is_zero() {
			let reserved_slashed_amount = account.reserved.min(remaining_slash);
			remaining_slash -= reserved_slashed_amount;
			Pallet::<T>::set_reserved_balance(currency_id, who, account.reserved - reserved_slashed_amount);
			(
				Self::NegativeImbalance::new(free_slashed_amount + reserved_slashed_amount),
				remaining_slash,
			)
		} else {
			(Self::NegativeImbalance::new(value), remaining_slash)
		}
	}

	fn deposit_into_existing(
		who: &T::AccountId,
		value: Self::Balance,
	) -> sp_std::result::Result<Self::PositiveImbalance, DispatchError> {
		if value.is_zero() {
			return Ok(Self::PositiveImbalance::zero());
		}
		let currency_id = GetCurrencyId::get();
		let new_total = Pallet::<T>::free_balance(currency_id, who)
			.checked_add(&value)
			.ok_or(Error::<T>::TotalIssuanceOverflow)?;
		Pallet::<T>::set_free_balance(currency_id, who, new_total);

		Ok(Self::PositiveImbalance::new(value))
	}

	fn deposit_creating(who: &T::AccountId, value: Self::Balance) -> Self::PositiveImbalance {
		Self::deposit_into_existing(who, value).unwrap_or_else(|_| Self::PositiveImbalance::zero())
	}

	fn withdraw(
		who: &T::AccountId,
		value: Self::Balance,
		_reasons: WithdrawReasons,
		_liveness: ExistenceRequirement,
	) -> sp_std::result::Result<Self::NegativeImbalance, DispatchError> {
		if value.is_zero() {
			return Ok(Self::NegativeImbalance::zero());
		}
		let currency_id = GetCurrencyId::get();
		Pallet::<T>::ensure_can_withdraw(currency_id, who, value)?;
		Pallet::<T>::set_free_balance(currency_id, who, Pallet::<T>::free_balance(currency_id, who) - value);
		Ok(Self::NegativeImbalance::new(value))
	}

	fn make_free_balance_be(
		who: &T::AccountId,
		value: Self::Balance,
	) -> SignedImbalance<Self::Balance, Self::PositiveImbalance> {
		let currency_id = GetCurrencyId::get();
		Pallet::<T>::try_mutate_account(
			who,
			currency_id,
			|account, existed| -> Result<SignedImbalance<Self::Balance, Self::PositiveImbalance>, ()> {
				// If we're attempting to set an existing account to less than ED, then
				// bypass the entire operation. It's a no-op if you follow it through, but
				// since this is an instance where we might account for a negative imbalance
				// (in the dust cleaner of set_account) before we account for its actual
				// equal and opposite cause (returned as an Imbalance), then in the
				// instance that there's no other accounts on the system at all, we might
				// underflow the issuance and our arithmetic will be off.
				match Token::<T>::get(currency_id) {
					Some(token_data) => {
						let ed = token_data.min_balance;
						ensure!(value.saturating_add(account.reserved) >= ed || existed, ());

						let imbalance = if account.free <= value {
							SignedImbalance::Positive(PositiveImbalance::new(value - account.free))
						} else {
							SignedImbalance::Negative(NegativeImbalance::new(account.free - value))
						};
						account.free = value;
						Ok(imbalance)
					}
					None => Err(()),
				}
			},
		)
		.unwrap_or_else(|_| SignedImbalance::Positive(Self::PositiveImbalance::zero()))
	}
}

impl<T, GetCurrencyId> PalletReservableCurrency<T::AccountId> for CurrencyAdapter<T, GetCurrencyId>
where
	T: Config,
	GetCurrencyId: Get<T::CurrencyId>,
{
	fn can_reserve(who: &T::AccountId, value: Self::Balance) -> bool {
		Pallet::<T>::can_reserve(GetCurrencyId::get(), who, value)
	}

	fn slash_reserved(who: &T::AccountId, value: Self::Balance) -> (Self::NegativeImbalance, Self::Balance) {
		let actual = Pallet::<T>::slash_reserved(GetCurrencyId::get(), who, value);
		(Self::NegativeImbalance::zero(), actual)
	}

	fn reserved_balance(who: &T::AccountId) -> Self::Balance {
		Pallet::<T>::reserved_balance(GetCurrencyId::get(), who)
	}

	fn reserve(who: &T::AccountId, value: Self::Balance) -> DispatchResult {
		Pallet::<T>::reserve(GetCurrencyId::get(), who, value)
	}

	fn unreserve(who: &T::AccountId, value: Self::Balance) -> Self::Balance {
		Pallet::<T>::unreserve(GetCurrencyId::get(), who, value)
	}

	fn repatriate_reserved(
		slashed: &T::AccountId,
		beneficiary: &T::AccountId,
		value: Self::Balance,
		status: BalanceStatus,
	) -> sp_std::result::Result<Self::Balance, DispatchError> {
		Pallet::<T>::repatriate_reserved(GetCurrencyId::get(), slashed, beneficiary, value, status)
	}
}

impl<T, GetCurrencyId> PalletLockableCurrency<T::AccountId> for CurrencyAdapter<T, GetCurrencyId>
where
	T: Config,
	GetCurrencyId: Get<T::CurrencyId>,
{
	type MaxLocks = ();
	type Moment = T::BlockNumber;

	fn set_lock(id: LockIdentifier, who: &T::AccountId, amount: Self::Balance, _reasons: WithdrawReasons) {
		let _ = Pallet::<T>::set_lock(id, GetCurrencyId::get(), who, amount);
	}

	fn extend_lock(id: LockIdentifier, who: &T::AccountId, amount: Self::Balance, _reasons: WithdrawReasons) {
		let _ = Pallet::<T>::extend_lock(id, GetCurrencyId::get(), who, amount);
	}

	fn remove_lock(id: LockIdentifier, who: &T::AccountId) {
		let _ = Pallet::<T>::remove_lock(id, GetCurrencyId::get(), who);
	}
}

impl<T: Config> MergeAccount<T::AccountId> for Pallet<T> {
	#[transactional]
	fn merge_account(source: &T::AccountId, dest: &T::AccountId) -> DispatchResult {
		AccountCurrencies::<T>::iter_prefix(source).try_for_each(|(currency_id, exists)| -> DispatchResult {
			if exists {
				let account_data = Accounts::<T>::get(currency_id, source);
				// ensure the account has no active reserved of non-native token
				ensure!(account_data.reserved.is_zero(), Error::<T>::StillHasActiveReserved);

				// transfer all free to recipient
				<Self as MultiCurrency<T::AccountId>>::transfer(currency_id, source, dest, account_data.free)?;
			}
			Ok(())
		})
	}
}

impl<T: Config> ExtendedTokenSystem<T::AccountId, T::CurrencyId, T::Balance> for Pallet<T> {
	fn create(
		currency_id: T::CurrencyId,
		owner: T::AccountId,
		admin: T::AccountId,
		min_balance: T::Balance,
	) -> Result<(), DispatchError> {
		Token::<T>::insert(currency_id, TokenDetails {
			owner: owner.clone(),
			issuer: admin.clone(),
			admin: admin.clone(),
			freezer: admin.clone(),
			supply: Zero::zero(),
			deposit: T::CurrencyDeposit::get(),
			min_balance,
			approvals: 0,
			is_frozen: false,
			dust_type: DustHandlerType::Transfer(T::DustAccount::get()),
		});

		Ok(())
	}

	fn mint(currency_id: T::CurrencyId, account_id: T::AccountId, amount: T::Balance) -> Result<(), DispatchError> {
		Self::deposit(currency_id, &account_id, amount)?;
		Ok(())
	}

	/// Burns a balance from an account. Will burn into reserved balance as
	/// well. Deducts total burned amount from the token supply. Note, the total
	/// burned amount might be less than the target burn amount if the user has
	/// less balance than what is being burnt.
	fn burn(currency_id: T::CurrencyId, account_id: T::AccountId, amount: T::Balance) -> Result<(), DispatchError> {
		ensure!(!amount.is_zero(), Error::<T>::InvalidAmount);

		let account = Self::accounts(currency_id, account_id.clone());
		let free_burn_amount = account.free.min(amount);
		// Cannot underflow becuase free_burn_amount can never be greater than amount
		let mut remaining_burn = amount - free_burn_amount;

		// slash free balance
		if !free_burn_amount.is_zero() {
			// Cannot underflow becuase free_burn_amount can never be greater than
			// account.free
			Self::set_free_balance(currency_id, &account_id, account.free - free_burn_amount);
		}

		// burn reserved balance
		if !remaining_burn.is_zero() {
			let reserved_burn_amount = account.reserved.min(remaining_burn);
			// Cannot underflow due to above line
			remaining_burn -= reserved_burn_amount;
			Self::set_reserved_balance(currency_id, &account_id, account.reserved - reserved_burn_amount);
		}

		// Cannot underflow because the burn value cannot be greater than total
		// issuance
		<TotalIssuance<T>>::mutate(currency_id, |v| *v -= amount - remaining_burn);
		Ok(())
	}

	fn handle_dust(currency_id: T::CurrencyId, who: &T::AccountId, amount: T::Balance) {
		if let Some(token) = Token::<T>::get(currency_id) {
			match token.dust_type {
				DustHandlerType::Burn => {
					let _ = Pallet::<T>::withdraw(currency_id, who, amount);
				}
				DustHandlerType::Transfer(acc) => {
					let _ = <Pallet<T> as MultiCurrency<T::AccountId>>::transfer(currency_id, who, &acc, amount);
				}
			}
		}
	}
}
