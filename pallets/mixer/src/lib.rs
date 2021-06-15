// A runtime module Groups with necessary imports

// Feel free to remove or edit this file as needed.
// If you change the name of this file, make sure to update its references in
// runtime/src/lib.rs If you remove this file, you can remove those references

// For more guidance on Substrate modules, see the example module
// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

//! # Mixer Pallet
//!
//! The Mixer pallet provides functionality for doing deposits and withdrawals
//! from the mixer.
//!
//! - [`Config`]
//! - [`Call`]
//! - [`Pallet`]
//!
//! ## Overview
//!
//! The Mixer pallet provides functions for:
//!
//! - Depositing some currency into the mixer.
//! - Withdrawing the deposit from the mixer.
//! - Stopping mixer operations.
//! - Transfering the admin of the mixer.
//!
//! ### Terminology
//!
//! - **Mixer**: Cryptocurrency tumbler or mixer is a service offered to mix
//!   potentially identifiable or 'tainted' cryptocurrency funds with others, so
//!   as to obscure the trail back to the fund's source.
//!
//! ## Interface
//!
//! ### Dispatchable Functions
//!
//! - `deposit` - Deposit a fixed amount of cryptocurrency into the mixer.
//! - `withdraw` - Provide a zero-knowladge proof of the deposit and withdraw
//!   from the mixer.
//! - `set_stopped` - Stops the operation of all mixers.
//! - `transfer_admin` - Transfers the admin role from sender to specified
//!   account.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;

pub mod traits;

use bulletproofs::BulletproofGens;
use codec::{Decode, Encode};
use frame_support::{dispatch, ensure, traits::Get, weights::Weight, PalletId};
use frame_system::ensure_signed;
use merkle::{
	utils::{
		keys::{get_bp_gen_bytes, Commitment, ScalarData},
		permissions::ensure_admin,
	},
	Pallet as MerklePallet, Tree as TreeTrait,
};
use sp_runtime::traits::{AccountIdConversion, Zero};
use sp_std::prelude::*;
use traits::ExtendedMixer;
use webb_traits::MultiCurrency;
use weights::WeightInfo;

pub use pallet::*;

/// Implementation of Mixer pallet
#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// The pallet's configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config + merkle::Config + webb_currencies::Config {
		#[pallet::constant]
		type PalletId: Get<PalletId>;
		/// The overarching event type.
		type Event: IsType<<Self as frame_system::Config>::Event> + From<Event<Self>>;
		/// Currency type for taking deposits
		type Currency: MultiCurrency<Self::AccountId>;
		/// Native currency id
		#[pallet::constant]
		type NativeCurrencyId: Get<CurrencyIdOf<Self>>;
		/// The overarching merkle tree trait
		type Tree: TreeTrait<Self>;
		/// The small deposit length
		#[pallet::constant]
		type DepositLength: Get<Self::BlockNumber>;
		/// Default admin key
		#[pallet::constant]
		type DefaultAdmin: Get<Self::AccountId>;
		/// Weight information for extrinsics in this pallet
		type WeightInfo: WeightInfo;
		// Available mixes sizes (Size is determend by the deposit amount)
		type MixerSizes: Get<Vec<BalanceOf<Self>>>;
	}

	/// Flag indicating if the mixer trees are created
	#[pallet::storage]
	#[pallet::getter(fn first_stage_initialized)]
	pub type FirstStageInitialized<T: Config> = StorageValue<_, bool, ValueQuery>;

	/// Flag indicating if the mixers are initialized
	#[pallet::storage]
	#[pallet::getter(fn second_stage_initialized)]
	pub type SecondStageInitialized<T: Config> = StorageValue<_, bool, ValueQuery>;

	/// The map of mixer trees to their metadata
	#[pallet::storage]
	#[pallet::getter(fn mixer_trees)]
	pub type MixerTrees<T: Config> = StorageMap<_, Blake2_128Concat, T::TreeId, MixerInfo<T>, ValueQuery>;

	/// The vector of group ids
	#[pallet::storage]
	#[pallet::getter(fn mixer_group_ids)]
	pub type MixerTreeIds<T: Config> = StorageValue<_, Vec<T::TreeId>, ValueQuery>;

	/// Administrator of the mixer pallet.
	/// This account that can stop/start operations of the mixer
	#[pallet::storage]
	#[pallet::getter(fn admin)]
	pub type Admin<T: Config> = StorageValue<_, T::AccountId, ValueQuery>;

	/// The TVL per group
	#[pallet::storage]
	#[pallet::getter(fn total_value_locked)]
	pub type TotalValueLocked<T: Config> = StorageMap<_, Blake2_128Concat, T::TreeId, BalanceOf<T>, ValueQuery>;

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
		NotInitialized,
		/// Mixer is already initialized
		AlreadyInitialized,
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
		fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
			// We make sure that we return the correct weight for the block according to
			// on_finalize
			if Self::second_stage_initialized() {
				// In case mixer is initialized, we expect the weights for merkle cache update
				<T as Config>::WeightInfo::on_finalize_initialized()
			} else {
				// In case mixer is not initialized, we expect the weights for initialization
				<T as Config>::WeightInfo::on_finalize_uninitialized()
			}
		}

		fn on_finalize(_n: BlockNumberFor<T>) {
			if Self::first_stage_initialized() && !Self::second_stage_initialized() {
				let mixer_ids = MixerTreeIds::<T>::get();
				// check if first tree has been initialized, otherwise intialize the parameters
				for i in 0..mixer_ids.len() {
					if let Ok(initialized) = T::Tree::is_initialized(mixer_ids[i]) {
						if !initialized {
							match Self::initialize_mixer_trees() {
								Ok(_) => {}
								Err(e) => {
									log::error!("Error initialising trees: {:?}", e);
								}
							}
						}
					}

					break;
				}
			}

			if Self::first_stage_initialized() && Self::second_stage_initialized() {
				// check if any deposits happened (by checking the size of the collection at
				// this block) if none happened, carry over previous Merkle roots for the cache.
				let mixer_ids = MixerTreeIds::<T>::get();

				for i in 0..mixer_ids.len() {
					let cached_roots = <merkle::Pallet<T>>::cached_roots(_n, mixer_ids[i]);
					// if there are no cached roots, carry forward the current root
					if cached_roots.len() == 0 {
						let _ = <merkle::Pallet<T>>::add_root_to_cache(mixer_ids[i], _n);
					}
				}
			}

			if !Self::first_stage_initialized() {
				match Self::initialize() {
					Ok(_) => {}
					Err(e) => {
						log::error!("Error initialising: {:?}", e);
					}
				}
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Deposits the fixed amount into the mixer with id of `mixer_id`
		/// Multiple deposits can be inserted together since `data_points` is an
		/// array.
		///
		/// Fails in case the mixer is stopped or not initialized.
		///
		/// Weights:
		/// - Dependent on argument: `data_points`
		///
		/// - Base weight: 417_168_400_000
		/// - DB weights: 8 reads, 5 writes
		/// - Additional weights: 21_400_442_000 * data_points.len()
		#[pallet::weight(<T as Config>::WeightInfo::deposit(data_points.len() as u32))]
		pub fn deposit(
			origin: OriginFor<T>,
			mixer_id: T::TreeId,
			data_points: Vec<ScalarData>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::second_stage_initialized(), Error::<T>::NotInitialized);
			ensure!(!<MerklePallet<T>>::stopped(mixer_id), Error::<T>::MixerStopped);
			// get mixer info, should always exist if the module is initialized
			let mixer_info = Self::get_mixer(mixer_id)?;
			// ensure the sender has enough balance to cover deposit
			let balance = T::Currency::free_balance(mixer_info.currency_id, &sender);
			// TODO: Multiplication by usize should be possible
			// using this hack for now, though we should optimise with regular
			// multiplication `data_points.len() * mixer_info.fixed_deposit_size`
			let deposit: BalanceOf<T> = data_points
				.iter()
				.map(|_| mixer_info.fixed_deposit_size)
				.fold(Zero::zero(), |acc, elt| acc + elt);
			ensure!(balance >= deposit, Error::<T>::InsufficientBalance);
			// transfer the deposit to the module
			T::Currency::transfer(mixer_info.currency_id, &sender, &Self::account_id(), deposit)?;
			// update the total value locked
			let tvl = Self::total_value_locked(mixer_id);
			<TotalValueLocked<T>>::insert(mixer_id, tvl + deposit);
			// add elements to the mixer group's merkle tree and save the leaves
			T::Tree::add_members(Self::account_id(), mixer_id.into(), data_points.clone())?;

			let deposit_size = mixer_info.fixed_deposit_size;

			Self::deposit_event(Event::Deposit(mixer_id, sender, deposit_size));

			Ok(().into())
		}

		/// Withdraws a deposited amount from the mixer. Can only withdraw one
		/// deposit. Accepts proof of membership along with the mixer id.
		///
		/// Fails if the mixer is stopped or not initialized.
		///
		/// Weights:
		/// - Independent of the arguments.
		///
		/// - Base weight: 1_078_562_000_000
		/// - DB weights: 9 reads, 3 writes
		#[pallet::weight(<T as Config>::WeightInfo::withdraw())]
		pub fn withdraw(origin: OriginFor<T>, withdraw_proof: WithdrawProof<T>) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			ensure!(Self::second_stage_initialized(), Error::<T>::NotInitialized);
			ensure!(
				!<MerklePallet<T>>::stopped(withdraw_proof.mixer_id),
				Error::<T>::MixerStopped
			);
			let recipient = withdraw_proof.recipient.unwrap_or(sender.clone());
			let relayer = withdraw_proof.relayer.unwrap_or(sender.clone());
			// get mixer info, should fail if tree isn't initialized
			let mixer_info = Self::get_mixer(withdraw_proof.mixer_id)?;
			// check if the nullifier has been used
			T::Tree::has_used_nullifier(withdraw_proof.mixer_id.into(), withdraw_proof.nullifier_hash)?;
			// Verify the zero-knowledge proof of membership provided
			T::Tree::verify_zk_membership_proof(
				withdraw_proof.mixer_id.into(),
				withdraw_proof.cached_block,
				withdraw_proof.cached_root,
				withdraw_proof.comms,
				withdraw_proof.nullifier_hash,
				withdraw_proof.proof_bytes,
				withdraw_proof.leaf_index_commitments,
				withdraw_proof.proof_commitments,
				ScalarData::from_slice(&recipient.encode()),
				ScalarData::from_slice(&relayer.encode()),
			)?;
			// transfer the fixed deposit size to the sender
			T::Currency::transfer(
				mixer_info.currency_id,
				&Self::account_id(),
				&recipient,
				mixer_info.fixed_deposit_size,
			)?;
			// update the total value locked
			let tvl = Self::total_value_locked(withdraw_proof.mixer_id);
			<TotalValueLocked<T>>::insert(withdraw_proof.mixer_id, tvl - mixer_info.fixed_deposit_size);
			// Add the nullifier on behalf of the module
			T::Tree::add_nullifier(
				Self::account_id(),
				withdraw_proof.mixer_id.into(),
				withdraw_proof.nullifier_hash,
			)?;

			Self::deposit_event(Event::Withdraw(
				withdraw_proof.mixer_id,
				sender,
				recipient,
				relayer,
				withdraw_proof.cached_root,
			));
			Ok(().into())
		}

		#[pallet::weight(5_000_000)]
		pub fn create_new(
			origin: OriginFor<T>,
			currency_id: CurrencyIdOf<T>,
			size: BalanceOf<T>,
		) -> DispatchResultWithPostInfo {
			ensure_admin(origin, &Self::admin())?;

			<Self as ExtendedMixer<_>>::create_new(Self::account_id(), currency_id, size)?;
			Ok(().into())
		}

		#[pallet::weight(5_000_000)]
		pub fn create_new_and_initialize(
			origin: OriginFor<T>,
			currency_id: CurrencyIdOf<T>,
			size: BalanceOf<T>,
			key_id: T::KeyId,
		) -> DispatchResultWithPostInfo {
			ensure_admin(origin, &Self::admin())?;

			let tree_id = <Self as ExtendedMixer<_>>::create_new(Self::account_id(), currency_id, size)?;
			T::Tree::initialize_tree(tree_id, key_id)?;
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
		#[pallet::weight(<T as Config>::WeightInfo::set_stopped())]
		pub fn set_stopped(origin: OriginFor<T>, stopped: bool) -> DispatchResultWithPostInfo {
			// Ensure the caller is admin or root
			ensure_admin(origin, &Self::admin())?;
			// Set the mixer state, `stopped` can be true or false
			let mixer_ids = MixerTreeIds::<T>::get();
			for i in 0..mixer_ids.len() {
				T::Tree::set_stopped(Self::account_id(), mixer_ids[i], stopped)?;
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
		#[pallet::weight(<T as Config>::WeightInfo::transfer_admin())]
		pub fn transfer_admin(origin: OriginFor<T>, to: T::AccountId) -> DispatchResultWithPostInfo {
			// Ensures that the caller is the root or the current admin
			ensure_admin(origin, &Self::admin())?;
			// Updating the admin
			Admin::<T>::set(to);
			Ok(().into())
		}
	}
}

/// Proof data for withdrawal
#[derive(Encode, Decode, PartialEq, Clone)]
pub struct WithdrawProof<T: Config> {
	/// The mixer id this withdraw proof corresponds to
	mixer_id: T::TreeId,
	/// The cached block for the cached root being proven against
	cached_block: T::BlockNumber,
	/// The cached root being proven against
	cached_root: ScalarData,
	/// The individual scalar commitments (to the randomness and nullifier)
	comms: Vec<Commitment>,
	/// The nullifier hash with itself
	nullifier_hash: ScalarData,
	/// The proof in bytes representation
	proof_bytes: Vec<u8>,
	/// The leaf index scalar commitments to decide on which side to hash
	leaf_index_commitments: Vec<Commitment>,
	/// The scalar commitments to merkle proof path elements
	proof_commitments: Vec<Commitment>,
	/// The recipient to withdraw amount of currency to
	recipient: Option<T::AccountId>,
	/// The recipient to withdraw amount of currency to
	relayer: Option<T::AccountId>,
}

impl<T: Config> WithdrawProof<T> {
	pub fn new(
		mixer_id: T::TreeId,
		cached_block: T::BlockNumber,
		cached_root: ScalarData,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
		recipient: Option<T::AccountId>,
		relayer: Option<T::AccountId>,
	) -> Self {
		Self {
			mixer_id,
			cached_block,
			cached_root,
			comms,
			nullifier_hash,
			proof_bytes,
			leaf_index_commitments,
			proof_commitments,
			recipient,
			relayer,
		}
	}
}

// TODO: Not sure why compiler is complaining without this since it implements
// Debug
#[cfg(feature = "std")]
impl<T: Config> std::fmt::Debug for WithdrawProof<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

/// Type alias for the webb_traits::MultiCurrency::Balance type
pub type BalanceOf<T> = <<T as Config>::Currency as MultiCurrency<<T as frame_system::Config>::AccountId>>::Balance;
/// Type alias for the webb_traits::MultiCurrency::CurrencyId type
pub type CurrencyIdOf<T> =
	<<T as pallet::Config>::Currency as MultiCurrency<<T as frame_system::Config>::AccountId>>::CurrencyId;

/// Info about the mixer and it's leaf data
#[derive(Encode, Decode, PartialEq)]
pub struct MixerInfo<T: Config> {
	/// Minimum duration the deposit has stayed in the mixer for a user
	/// to be eligible for reward
	///
	/// NOTE: Currently not used
	pub minimum_deposit_length_for_reward: T::BlockNumber,
	/// Deposit size for the mixer
	pub fixed_deposit_size: BalanceOf<T>,
	/// Id of the currency in the mixer
	pub currency_id: CurrencyIdOf<T>,
}

impl<T: Config> core::default::Default for MixerInfo<T> {
	fn default() -> Self {
		Self {
			minimum_deposit_length_for_reward: Zero::zero(),
			fixed_deposit_size: Zero::zero(),
			currency_id: T::NativeCurrencyId::get(),
		}
	}
}

impl<T: Config> MixerInfo<T> {
	pub fn new(min_dep_length: T::BlockNumber, dep_size: BalanceOf<T>, currency_id: CurrencyIdOf<T>) -> Self {
		Self {
			minimum_deposit_length_for_reward: min_dep_length,
			fixed_deposit_size: dep_size,
			currency_id,
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn account_id() -> T::AccountId {
		T::PalletId::get().into_account()
	}

	pub fn get_mixer(mixer_id: T::TreeId) -> Result<MixerInfo<T>, dispatch::DispatchError> {
		let mixer_info = MixerTrees::<T>::get(mixer_id);
		// ensure mixer_info has a non-zero deposit, otherwise, the mixer doesn't exist
		// for this id
		ensure!(mixer_info.fixed_deposit_size > Zero::zero(), Error::<T>::NoMixerForId);
		// ensure the mixer's tree is intialized
		let initialized = T::Tree::is_initialized(mixer_id)?;
		ensure!(initialized, Error::<T>::NotInitialized);
		// return the mixer info
		Ok(mixer_info)
	}

	pub fn initialize() -> dispatch::DispatchResult {
		ensure!(!Self::first_stage_initialized(), Error::<T>::AlreadyInitialized);

		let mixer_ids = MixerTreeIds::<T>::get();
		if mixer_ids.len() == 0 {
			// Get default admin from trait params
			let default_admin = T::DefaultAdmin::get();
			// Initialize the admin in storage with default one
			Admin::<T>::set(default_admin);
			let depth: u8 = <T as merkle::Config>::MaxTreeDepth::get();

			// Getting the sizes from the config
			let sizes = T::MixerSizes::get();
			let mut mixer_ids = Vec::new();

			// Iterating over configured sizes and initializing the mixers
			for size in sizes.into_iter() {
				// Creating a new merkle group and getting the id back
				let mixer_id: T::TreeId = T::Tree::create_tree(Self::account_id(), true, depth)?;
				// Creating mixer info data
				let mixer_info = MixerInfo::<T>::new(T::DepositLength::get(), size, T::NativeCurrencyId::get());
				// Saving the mixer group to storage
				MixerTrees::<T>::insert(mixer_id, mixer_info);
				mixer_ids.push(mixer_id);
			}

			// Setting the mixer ids
			MixerTreeIds::<T>::set(mixer_ids);
		}

		FirstStageInitialized::<T>::set(true);
		Ok(())
	}

	pub fn initialize_mixer_trees() -> dispatch::DispatchResult {
		ensure!(Self::first_stage_initialized(), Error::<T>::AlreadyInitialized);

		let key_data = get_bp_gen_bytes(&BulletproofGens::new(16400, 1));
		let key_id = T::Tree::add_verifying_key(key_data)?;
		let mixer_ids = MixerTreeIds::<T>::get();
		for i in 0..mixer_ids.len() {
			let tree_id = mixer_ids[i];
			T::Tree::initialize_tree(tree_id, key_id)?;
		}

		SecondStageInitialized::<T>::set(true);
		Ok(())
	}
}

impl<T: Config> ExtendedMixer<T> for Pallet<T> {
	fn create_new(
		account_id: T::AccountId,
		currency_id: CurrencyIdOf<T>,
		size: BalanceOf<T>,
	) -> Result<T::TreeId, dispatch::DispatchError> {
		let depth: u8 = <T as merkle::Config>::MaxTreeDepth::get();
		let mixer_id: T::TreeId = T::Tree::create_tree(account_id, true, depth)?;
		let mixer_info = MixerInfo::<T>::new(T::DepositLength::get(), size, currency_id);
		MixerTrees::<T>::insert(mixer_id, mixer_info);
		Ok(mixer_id)
	}
}
