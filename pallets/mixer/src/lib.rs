#![cfg_attr(not(feature = "std"), no_std)]

/// A runtime module Groups with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in
/// runtime/src/lib.rs If you remove this file, you can remove those references

/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

use codec::{Decode, Encode};
use frame_support::{
	decl_error, decl_event, decl_module, decl_storage, dispatch, ensure,
	traits::{Currency, ExistenceRequirement::AllowDeath, Get},
};
use frame_system::{ensure_signed, RawOrigin};
use merkle::{
	merkle::{
		keys::{Commitment, Data},
		permissions::ensure_admin,
	},
	Group as GroupTrait, Module as MerkleModule,
};
use sp_runtime::{
	traits::{AccountIdConversion, One, Zero},
	ModuleId,
};
use sp_std::prelude::*;

pub type BalanceOf<T> = <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

/// The pallet's configuration trait.
pub trait Config: frame_system::Config + merkle::Config {
	type ModuleId: Get<ModuleId>;
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
	/// Currency type for taking deposits
	type Currency: Currency<Self::AccountId>;
	/// The overarching group trait
	type Group: GroupTrait<Self::AccountId, Self::BlockNumber, Self::GroupId>;
	/// The max depth of the mixers
	type MaxTreeDepth: Get<u8>;
	/// The small deposit length
	type DepositLength: Get<Self::BlockNumber>;
	/// Default admin key
	type DefaultAdmin: Get<Self::AccountId>;
}

#[derive(Encode, Decode, PartialEq)]
pub struct MixerInfo<T: Config> {
	pub minimum_deposit_length_for_reward: T::BlockNumber,
	pub fixed_deposit_size: BalanceOf<T>,
	pub leaves: Vec<Data>,
}

impl<T: Config> core::default::Default for MixerInfo<T> {
	fn default() -> Self {
		Self {
			minimum_deposit_length_for_reward: Zero::zero(),
			fixed_deposit_size: Zero::zero(),
			leaves: Vec::new(),
		}
	}
}

impl<T: Config> MixerInfo<T> {
	pub fn new(min_dep_length: T::BlockNumber, dep_size: BalanceOf<T>, leaves: Vec<Data>) -> Self {
		Self {
			minimum_deposit_length_for_reward: min_dep_length,
			fixed_deposit_size: dep_size,
			leaves,
		}
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Config> as Mixer {
		pub Initialised get(fn initialised): bool;
		/// The map of mixer groups to their metadata
		pub MixerGroups get(fn mixer_groups): map hasher(blake2_128_concat) T::GroupId => MixerInfo<T>;
		/// The vec of group ids
		pub MixerGroupIds get(fn mixer_group_ids): Vec<T::GroupId>;
		/// Administrator of the mixer pallet.
		/// This account that can stop/start operations of the mixer
		pub Admin get(fn admin): T::AccountId;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T>
	where
		AccountId = <T as frame_system::Config>::AccountId,
		GroupId = <T as merkle::Config>::GroupId,
		Nullifier = Data,
	{
		Deposit(GroupId, AccountId, Nullifier),
		Withdraw(GroupId, AccountId, Nullifier),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Config> {
		/// Value was None
		NoneValue,
		///
		NoMixerForId,
		///
		NotInitialised,
		///
		AlreadyInitialised,
		///
		InsufficientBalance,
		///
		UnauthorizedCall,
		///
		MixerStopped,
	}
}

decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 0]
		pub fn deposit(origin, mixer_id: T::GroupId, data_points: Vec<Data>) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);
			ensure!(!<MerkleModule<T>>::stopped(mixer_id), Error::<T>::MixerStopped);
			// get mixer info, should always exist if module is initialised
			let mut mixer_info = Self::get_mixer(mixer_id)?;
			// ensure the sender has enough balance to cover deposit
			let balance = T::Currency::free_balance(&sender);
			// TODO: Multiplication by usize should be possible
			// using this hack for now, though we should optimise with regular multiplication
			// `data_points.len() * mixer_info.fixed_deposit_size`
			let deposit: BalanceOf<T> = data_points.iter()
				.map(|_| mixer_info.fixed_deposit_size)
				.fold(Zero::zero(), |acc, elt| acc + elt);
			ensure!(balance >= deposit, Error::<T>::InsufficientBalance);
			// transfer the deposit to the module
			T::Currency::transfer(&sender, &Self::account_id(), deposit, AllowDeath)?;
			// add elements to the mixer group's merkle tree and save the leaves
			T::Group::add_members(Self::account_id(), mixer_id.into(), data_points.clone())?;
			for i in 0..data_points.len() {
				mixer_info.leaves.push(data_points[i]);
			}
			MixerGroups::<T>::insert(mixer_id, mixer_info);

			Ok(())
		}

		#[weight = 0]
		pub fn withdraw(
			origin,
			mixer_id: T::GroupId,
			cached_block: T::BlockNumber,
			cached_root: Data,
			comms: Vec<Commitment>,
			nullifier_hash: Data,
			proof_bytes: Vec<u8>,
			leaf_index_commitments: Vec<Commitment>,
			proof_commitments: Vec<Commitment>,
		) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);
			ensure!(!<MerkleModule<T>>::stopped(mixer_id), Error::<T>::MixerStopped);
			let mixer_info = MixerGroups::<T>::get(mixer_id);
			// check if the nullifier has been used
			T::Group::has_used_nullifier(mixer_id.into(), nullifier_hash)?;
			// Verify the zero-knowledge proof of membership provided
			T::Group::verify_zk_membership_proof(
				mixer_id.into(),
				cached_block,
				cached_root,
				comms,
				nullifier_hash,
				proof_bytes,
				leaf_index_commitments,
				proof_commitments
			)?;
			// transfer the fixed deposit size to the sender
			T::Currency::transfer(&Self::account_id(), &sender, mixer_info.fixed_deposit_size, AllowDeath)?;
			// Add the nullifier on behalf of the module
			T::Group::add_nullifier(Self::account_id(), mixer_id.into(), nullifier_hash)
		}

		#[weight = 0]
		pub fn initialize(origin) -> dispatch::DispatchResult {
			ensure!(!Self::initialised(), Error::<T>::AlreadyInitialised);
			let _ = ensure_signed(origin)?;

			// Taking a default account from pallets config trait
			let default_admin = T::DefaultAdmin::get();
			// Moving the default admin from config to the storage
			Admin::<T>::set(default_admin);

			Initialised::set(true);
			let one: BalanceOf<T> = One::one();
			let depth: u8 = <T as Config>::MaxTreeDepth::get();
			// create small mixer and assign the module as the manager
			let small_mixer_id: T::GroupId = T::Group::create_group(Self::account_id(), true, depth)?;
			let small_mixer_info = MixerInfo::<T> {
				fixed_deposit_size: one * 1_000.into(),
				minimum_deposit_length_for_reward: T::DepositLength::get(),
				leaves: Vec::new(),
			};
			MixerGroups::<T>::insert(small_mixer_id, small_mixer_info);
			// create medium mixer and assign the module as the manager
			let med_mixer_id: T::GroupId = T::Group::create_group(Self::account_id(), true, depth)?;
			let med_mixer_info = MixerInfo::<T> {
				fixed_deposit_size: one * 10_000.into(),
				minimum_deposit_length_for_reward: T::DepositLength::get(),
				leaves: Vec::new(),
			};
			MixerGroups::<T>::insert(med_mixer_id, med_mixer_info);
			// create large mixer and assign the module as the manager
			let large_mixer_id: T::GroupId = T::Group::create_group(Self::account_id(), true, depth)?;
			let large_mixer_info = MixerInfo::<T> {
				fixed_deposit_size: one * 100_000.into(),
				minimum_deposit_length_for_reward: T::DepositLength::get(),
				leaves: Vec::new(),
			};
			MixerGroups::<T>::insert(large_mixer_id, large_mixer_info);
			// create larger mixer and assign the module as the manager
			let huge_mixer_id: T::GroupId = T::Group::create_group(Self::account_id(), true, depth)?;
			let huge_mixer_info = MixerInfo::<T> {
				fixed_deposit_size: one * 1_000_000.into(),
				minimum_deposit_length_for_reward: T::DepositLength::get(),
				leaves: Vec::new(),
			};
			MixerGroups::<T>::insert(huge_mixer_id, huge_mixer_info);
			MixerGroupIds::<T>::set(vec![
				small_mixer_id,
				med_mixer_id,
				large_mixer_id,
				huge_mixer_id,
			]);
			Ok(())
		}

		#[weight = 0]
		fn set_stopped(origin, stopped: bool) -> dispatch::DispatchResult {
			// Ensure the caller is admin or root
			ensure_admin(origin, &Self::admin())?;
			// Set the mixer state, `stopped` can be true or false
			let mixer_ids = MixerGroupIds::<T>::get();
			for i in 0..mixer_ids.len() {
				<MerkleModule<T>>::set_stopped(RawOrigin::Signed(Self::account_id()).into(), mixer_ids[i], stopped)?;
			}
			Ok(())
		}

		#[weight = 0]
		fn transfer_admin(origin, to: T::AccountId) -> dispatch::DispatchResult {
			// Ensures that the caller is the root or the current admin
			ensure_admin(origin, &Self::admin())?;
			// Updating the admin
			Admin::<T>::set(to);
			Ok(())
		}

		fn on_finalize(_n: T::BlockNumber) {
			// check if any deposits happened (by checked the size of collection at this block)
			// if none happened, carry over previous merkle roots for the cache.
			let mixer_ids = MixerGroupIds::<T>::get();
			for i in 0..mixer_ids.len() {
				let cached_roots = <MerkleModule<T>>::cached_roots(_n, mixer_ids[i]);
				// if there are no cached roots, carry forward the current root
				if cached_roots.len() == 0 {
					let _ = <MerkleModule<T>>::add_root_to_cache(mixer_ids[i], _n);
				}
			}
		}
	}
}

impl<T: Config> Module<T> {
	pub fn account_id() -> T::AccountId {
		T::ModuleId::get().into_account()
	}

	pub fn get_mixer(mixer_id: T::GroupId) -> Result<MixerInfo<T>, dispatch::DispatchError> {
		let mixer_info = MixerGroups::<T>::get(mixer_id);
		// ensure mixer_info has non-zero deposit, otherwise mixer doesn't
		// really exist for this id
		ensure!(mixer_info.fixed_deposit_size > Zero::zero(), Error::<T>::NoMixerForId);
		// return the mixer info
		Ok(mixer_info)
	}
}
