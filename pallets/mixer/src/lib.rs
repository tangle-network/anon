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

use sp_runtime::traits::One;
use sp_runtime::traits::AccountIdConversion;
use sp_runtime::ModuleId;
use merkle::merkle::keys::Commitment;
use sp_runtime::traits::{Zero};
use merkle::merkle::keys::Data;

use frame_support::traits::{Currency, Get, ExistenceRequirement::{AllowDeath}};

use codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use sp_std::prelude::*;
use merkle::{Group as GroupTrait};

pub type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

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
			leaves: leaves,
		}
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Config> as Mixer {
		pub Initialised get(fn initialised): bool;
		/// The map of mixer groups to their metadata
		pub MixerGroups get(fn mixer_groups): map hasher(blake2_128_concat) T::GroupId => MixerInfo<T>;
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
			leaf_com: Commitment,
			path: Vec<(Commitment, Commitment)>,
			r_com: Commitment,
			nullifier: Data,
			proof_bytes: Vec<u8>
		) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			ensure!(Self::initialised(), Error::<T>::NotInitialised);
			let mixer_info = MixerGroups::<T>::get(mixer_id);
			// check if the nullifier has been used
			// Returns `()` if the nullifier has not been used
			// otherwise returns `Err` from merkle groups pallet
			T::Group::has_used_nullifier(mixer_id.into(), nullifier)?;
			// Verify the zero-knowledge proof of membership provided
			// Returns `()` if verification is successful
			// Otherwise returns `Err` for failed verification / bad proof from merkle groups pallet
			T::Group::verify_zk_membership_proof(
				mixer_id.into(),
				cached_block,
				cached_root,
				leaf_com,
				path,
				r_com,
				nullifier,
				proof_bytes,
			)?;
			// transfer the fixed deposit size to the sender
			T::Currency::transfer(&Self::account_id(), &sender, mixer_info.fixed_deposit_size, AllowDeath)?;
			// Add the nullifier on behalf of the module
			T::Group::add_nullifier(Self::account_id(), mixer_id.into(), nullifier)
		}

		#[weight = 0]
		pub fn initialize(origin) -> dispatch::DispatchResult {
			ensure!(!Self::initialised(), Error::<T>::AlreadyInitialised);
			let _ = ensure_signed(origin)?;
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
			Ok(())
		}
	}
}

impl<T: Config> Module<T> {
	pub fn account_id() -> T::AccountId {
		T::ModuleId::get().into_account()
	}

	pub fn get_mixer(mixer_id: T::GroupId) -> Result<MixerInfo<T>, dispatch::DispatchError> {
		let mixer_info = MixerGroups::<T>::get(mixer_id);
		// ensure mixer_info has non-zero deposit, otherwise mixer doesn't really exist for this id
		ensure!(mixer_info.fixed_deposit_size > Zero::zero(), Error::<T>::NoMixerForId);
		// return the mixer info
		Ok(mixer_info)
	}
}
