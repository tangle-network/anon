// A runtime module trees with necessary imports

// Feel free to remove or edit this file as needed.
// If you change the name of this file, make sure to update its references in
// runtime/src/lib.rs If you remove this file, you can remove those references

// For more guidance on Substrate modules, see the example module
// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

//! # Merkle Pallet
//!
//! The Merkle pallet provides functionality for making and managing the Merkle
//! trees.
//!
//! - [`Config`]
//! - [`Call`]
//! - [`Pallet`]
//!
//! ## Overview
//!
//! The Merkle pallet provides functions for:
//!
//! - Creating Merkle trees.
//! - Adding the manager and setting whether the manager is required.
//! - Adding leaf data to the Merkle tree.
//! - Adding nullifiers to the storage.
//! - Managing start/stop flags.
//! - Caching Merkle tree states.
//! - Verifying regular and zero-knowledge membership proofs
//!
//! ### Terminology
//!
//! - **Membership proof in zero-knowledge:** Proving that leaf is inside the
//!   tree without revealing which leaf you are proving over.
//!
//! - **Proof of creation in zero-knowledge:** Each leaf is made with an
//!   arithmetic circuit which includes hashing several values. Proving to know
//!   all these values are called proof of creation.
//!
//! - **Nullifier:** Nullifier is a part of this leaf circuit and is revealed
//!   when proving membership in zero-knowledge. The nullifier's role is to
//!   prevent double-spending.
//!
//! ### Implementations
//!
//! The Merkle pallet provides implementations for the following traits:
//!
//! - [`Group`](crate::traits::Group) Functions for creating and managing the
//!   group.
//!
//! ## Interface
//!
//! ### Dispatchable functions
//!
//! - `create_tree` - Create Merkle tree and their respective manager account.
//! - `set_manager_required` - Set whether manager is required to add members
//!   and nullifiers.
//! - `set_manager` - Set manager account id. Can only be called by the root or
//!   the current manager.
//! - `set_stopped` - Sets stopped storage flag. This flag by itself doesn't do
//!   anything. It's up to higher-level pallets to make appropriate use of it.
//!   Can only be called by the root or the manager;
//! - `add_members` Adds an array of leaves to the tree. Can only be called by
//!   the manager if the manager is required.
//! - `verify` - Verifies the membership proof.
//!
//! ## Usage
//!
//! The following examples show how to use the Merkle pallet in your custom
//! pallet.
//!
//! ```
//! use pallet_merkle::traits::Tree;
//! pub trait Config: frame_system::Config + pallet_merkle::Config {
//! 	type Tree: Tree<Self>;
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod traits;
pub mod utils;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;

use codec::{Decode, Encode};
use frame_support::{
	dispatch::DispatchError,
	ensure,
	traits::{Get, Randomness},
	weights::Weight,
	Parameter,
};
use frame_system::ensure_signed;
use sp_runtime::traits::{AtLeast32Bit, One};
use sp_std::prelude::*;
pub use traits::Tree;
use utils::{
	keys::ScalarBytes,
	permissions::ensure_admin,
	setup::{Curve, Setup},
};
use weights::WeightInfo;

pub use pallet::*;

/// Implementation of Merkle pallet
#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// The pallet's configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type Event: IsType<<Self as frame_system::Config>::Event> + From<Event<Self>>;
		/// The overarching tree ID type
		type TreeId: Encode + Decode + Parameter + AtLeast32Bit + Default + Copy;
		/// The overarching tree ID type
		type KeyId: Encode + Decode + Parameter + AtLeast32Bit + Default + Copy;
		/// The max depth of trees
		type MaxTreeDepth: Get<u8>;
		/// The amount of blocks to cache roots over
		type CacheBlockLength: Get<Self::BlockNumber>;
		/// The generator used to supply randomness to contracts through
		/// `seal_random`.
		type Randomness: Randomness<Self::Hash, Self::BlockNumber>;
		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Value was None
		NoneValue,
		/// Tree is full
		ExceedsMaxLeaves,
		/// Tree is already initialized when it shouldn't be
		AlreadyInitialized,
		/// Tree isn't initialized
		NotInitialized,
		/// Tree doesnt exist
		TreeDoesntExist,
		/// Key doesnt exist
		KeyDoesntExist,
		/// Invalid membership proof
		InvalidMembershipProof,
		/// Invalid merkle path length
		InvalidPathLength,
		/// Invalid commitments (private inputs) specified for the zk proof
		InvalidPrivateInputs,
		/// Invalid public inputs specified for the zk proof
		InvalidPublicInputs,
		/// Nullifier is already used
		AlreadyUsedNullifier,
		/// Failed to generate zero (empty) tree
		ZeroTreeGenFailed,
		/// Failed to hash two values
		HashingFailed,
		/// Failed to verify zero-knowladge proof
		ZkVerificationFailed,
		/// Invalid verifier key
		InvalidVerifierKey,
		/// Unsatisfied constraint system
		ConstraintSystemUnsatisfied,
		/// Invalid zero-knowladge data
		InvalidZkProof,
		/// Invalid depth of the tree specified
		InvalidTreeDepth,
		/// Invalid merkle root hash
		InvalidMerkleRoot,
		/// Manager is required for specific action
		ManagerIsRequired,
		/// Manager not found for specific tree
		ManagerDoesntExist,
		/// Error for unimplemented functionality
		Unimplemented,
		/// Unexpected/Unknown error
		Unknown,
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	#[pallet::metadata(T::AccountId = "AccountId", T::TreeId = "TreeId")]
	pub enum Event<T: Config> {
		/// New tree created
		NewTree(T::TreeId, T::AccountId, bool),
		/// New members/leaves added to the tree
		NewMembers(T::TreeId, T::AccountId, u32, Vec<ScalarBytes>),
		/// New nullifier submitted on verification
		NewNullifier(T::TreeId, T::AccountId, ScalarBytes),
	}

	/// Old name generated by `decl_event`.
	// #[deprecated(note = "use `Event` instead")]
	// pub type RawEvent<T, I = ()> = Event<T, I>;

	/// The next tree identifier up for grabs
	#[pallet::storage]
	#[pallet::getter(fn next_tree_id)]
	pub type NextTreeId<T: Config> = StorageValue<_, T::TreeId, ValueQuery>;

	/// The next tree identifier up for grabs
	#[pallet::storage]
	#[pallet::getter(fn next_key_id)]
	pub type NextKeyId<T: Config> = StorageValue<_, T::KeyId, ValueQuery>;

	/// The map of trees to their metadata
	#[pallet::storage]
	#[pallet::getter(fn trees)]
	pub type Trees<T: Config> = StorageMap<_, Blake2_128Concat, T::TreeId, Option<MerkleTree>, ValueQuery>;

	/// The map of trees to their metadata
	#[pallet::storage]
	#[pallet::getter(fn verifying_key_for_tree)]
	pub type VerifyingKeyForTree<T: Config> = StorageMap<_, Blake2_128Concat, T::TreeId, T::KeyId, ValueQuery>;

	/// The map of verifying keys for each backend
	#[pallet::storage]
	#[pallet::getter(fn verifying_keys)]
	pub type VerifyingKeys<T: Config> = StorageMap<_, Blake2_128Concat, T::KeyId, Option<Vec<u8>>, ValueQuery>;

	/// The map of (tree_id, index) to the leaf commitment
	#[pallet::storage]
	#[pallet::getter(fn leaves)]
	pub type Leaves<T: Config> =
		StorageDoubleMap<_, Blake2_128Concat, T::TreeId, Blake2_128Concat, u32, ScalarBytes, ValueQuery>;

	/// Map of cached/past Merkle roots at each block number and group. There
	/// can be more than one root update in a single block. Allows for easy
	/// pruning since we can remove all keys of the first map past a certain
	/// point.
	#[pallet::storage]
	#[pallet::getter(fn cached_roots)]
	pub type CachedRoots<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::BlockNumber,
		Blake2_128Concat,
		T::TreeId,
		Vec<ScalarBytes>,
		ValueQuery,
	>;

	/// Maps tree id to the manager of the tree
	#[pallet::storage]
	#[pallet::getter(fn get_manager)]
	pub type Managers<T: Config> = StorageMap<_, Blake2_128Concat, T::TreeId, Option<Manager<T>>, ValueQuery>;

	/// Block number of the oldest set of roots that we are caching
	#[pallet::storage]
	#[pallet::getter(fn lowest_cached_block)]
	pub type LowestCachedBlock<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	/// Block number of the newest set of roots that we are caching
	#[pallet::storage]
	#[pallet::getter(fn highest_cached_block)]
	pub type HighestCachedBlock<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	/// Map of used nullifiers for each tree.
	#[pallet::storage]
	#[pallet::getter(fn used_nullifiers)]
	pub type UsedNullifiers<T: Config> = StorageMap<_, Blake2_128Concat, (T::TreeId, ScalarBytes), bool, ValueQuery>;

	/// Indicates whether the group tree is stopped or not
	#[pallet::storage]
	#[pallet::getter(fn stopped)]
	pub type Stopped<T: Config> = StorageMap<_, Blake2_128Concat, T::TreeId, bool, ValueQuery>;

	#[pallet::pallet]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
		fn on_initialize(_n: T::BlockNumber) -> Weight {
			// Returning the weights for `on_finalize` in worst-case scenario where all if
			// branches are hit
			<T as Config>::WeightInfo::on_finalize()
		}

		fn on_finalize(n: T::BlockNumber) {
			// update highest block in cache
			if HighestCachedBlock::<T>::get() < n {
				HighestCachedBlock::<T>::set(n);
			}

			// initialise lowest block in cache if not already
			if LowestCachedBlock::<T>::get() < One::one() {
				LowestCachedBlock::<T>::set(n);
			}

			// update and prune database if pruning length has been hit
			if HighestCachedBlock::<T>::get() > T::CacheBlockLength::get() {
				if HighestCachedBlock::<T>::get() - T::CacheBlockLength::get() >= LowestCachedBlock::<T>::get() {
					CachedRoots::<T>::remove_prefix(LowestCachedBlock::<T>::get());
					LowestCachedBlock::<T>::set(LowestCachedBlock::<T>::get() + One::one());
				}
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Creates a new tree and sets a new manager for that tree. The
		/// initial manager is the sender. Also increments the mixer id counter
		/// in the storage. If _depth is not provided, max tree depth is
		/// assumed.
		///
		/// Weights:
		/// - Dependent on arguments: _depth
		///
		/// - Base weight: 8_356_000
		/// - DB weights: 1 read, 3 writes
		/// - Additional weights: 151_000 * _depth
		#[pallet::weight(<T as Config>::WeightInfo::create_tree(depth.map_or(T::MaxTreeDepth::get() as u32, |x| x as u32)))]
		pub fn create_tree(
			origin: OriginFor<T>,
			mgr_required: bool,
			setup: Setup,
			depth: Option<u8>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let depth = match depth {
				Some(d) => d,
				None => T::MaxTreeDepth::get(),
			};
			let _ = <Self as Tree<_>>::create_tree(sender, mgr_required, setup, depth)?;
			Ok(().into())
		}

		/// Sets if a manager is required for specific actions like adding
		/// nullifiers or leaves into the tree.
		///
		/// Can only be called by the root or the current manager.
		///
		/// Weights:
		/// - Independend of the arguments.
		///
		/// - Base weight: 7_000_000
		/// - DB weights: 1 read, 1 write
		#[pallet::weight(<T as Config>::WeightInfo::set_manager_required())]
		pub fn set_manager_required(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			manager_required: bool,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;

			<Self as Tree<_>>::set_manager_required(sender, tree_id, manager_required)?;
			Ok(().into())
		}

		/// Sets manager account id.
		///
		/// Can only be called by the root or the current manager.
		///
		/// Weights:
		/// - Independent of the arguments.
		///
		/// - Base weight: 8_000_000
		/// - DB weights: 1 read, 1 write
		#[pallet::weight(<T as Config>::WeightInfo::set_manager())]
		pub fn set_manager(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			new_manager: T::AccountId,
		) -> DispatchResultWithPostInfo {
			let manager_data = Managers::<T>::get(tree_id)
				.ok_or(Error::<T>::ManagerDoesntExist)
				.unwrap();
			// Changing manager should always require an extrinsic from the manager or root
			// even if the tree doesn't explicitly require managers for other calls.
			ensure_admin(origin, &manager_data.account_id)?;
			// We are passing manager always since we won't have account id when calling
			// from root origin
			<Self as Tree<_>>::set_manager(manager_data.account_id, tree_id, new_manager)?;
			Ok(().into())
		}

		/// Set stopped flag inside the storage.
		///
		/// Can only be called by the root or the current manager.
		///
		/// Weights:
		/// - Independent of the arguments.
		///
		/// - Base weight: 8_000_000
		/// - DB weights: 1 read, 1 write
		#[pallet::weight(<T as Config>::WeightInfo::set_stopped())]
		pub fn set_stopped(origin: OriginFor<T>, tree_id: T::TreeId, stopped: bool) -> DispatchResultWithPostInfo {
			let manager_data = Managers::<T>::get(tree_id)
				.ok_or(Error::<T>::ManagerDoesntExist)
				.unwrap();
			ensure_admin(origin, &manager_data.account_id)?;
			<Self as Tree<_>>::set_stopped(manager_data.account_id, tree_id, stopped)?;
			Ok(().into())
		}

		/// Adds an array of leaf data into the tree and adds calculated root to
		/// the cache.
		///
		/// Can only be called by the manager if a manager is set.
		///
		/// Weights:
		/// - Dependent on argument: `members`
		///
		/// - Base weight: 384_629_956_000
		/// - DB weights: 3 reads, 2 writes
		/// - Additional weights: 20_135_984_000 * members.len()
		#[pallet::weight(<T as Config>::WeightInfo::add_members(members.len() as u32))]
		pub fn add_members(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			members: Vec<ScalarBytes>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			<Self as Tree<_>>::add_members(sender, tree_id, members)?;
			Ok(().into())
		}

		/// Verification stub for testing, these verification functions should
		/// not need to be used directly as extrinsics. Rather, higher-order
		/// modules should use the module functions to verify and execute
		/// further logic.
		///
		/// Verifies the membership proof.
		///
		/// Weights:
		/// - Dependent on the argument: `path`
		/// - Base weight: 383_420_867_000
		/// - DB weights: 1 read
		/// - Additional weights: 814_291_000 * path.len()
		#[pallet::weight(<T as Config>::WeightInfo::verify_path(path.len() as u32))]
		pub fn verify(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			leaf: ScalarBytes,
			path: Vec<(bool, ScalarBytes)>,
		) -> DispatchResultWithPostInfo {
			let _sender = ensure_signed(origin)?;
			<Self as Tree<_>>::verify(tree_id, leaf, path)?;
			Ok(().into())
		}

		/// Initializes the merkle tree
		///
		/// Can only be called by the manager or root.
		#[pallet::weight(5_000_000)]
		pub fn initialize_tree(
			origin: OriginFor<T>,
			tree_id: T::TreeId,
			key_id: T::KeyId,
		) -> DispatchResultWithPostInfo {
			let manager_data = Managers::<T>::get(tree_id)
				.ok_or(Error::<T>::ManagerDoesntExist)
				.unwrap();
			// Changing manager should always require an extrinsic from the manager or root
			// even if the tree doesn't explicitly require managers for other calls.
			ensure_admin(origin, &manager_data.account_id)?;
			<Self as Tree<_>>::initialize_tree(tree_id, key_id)?;
			Ok(().into())
		}

		/// Adds a verifying key to the storage.
		///
		/// Can only be called by the root.
		#[pallet::weight(5_000_000)]
		pub fn add_verifying_key(origin: OriginFor<T>, key: Vec<u8>) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;
			<Self as Tree<_>>::add_verifying_key(key)?;
			Ok(().into())
		}

		/// Adds a verifying key to the storage.
		///
		/// Can only be called by the root.
		#[pallet::weight(5_000_000)]
		pub fn set_verifying_key(origin: OriginFor<T>, key_id: T::KeyId, key: Vec<u8>) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;

			<Self as Tree<_>>::set_verifying_key(key_id, key)?;
			Ok(().into())
		}

		/// Sets the verifying key for a tree.
		///
		/// Can only be called by the manager if a manager is set.
		#[pallet::weight(5_000_000)]
		pub fn set_verifying_key_for_tree(
			origin: OriginFor<T>,
			key_id: T::KeyId,
			tree_id: T::TreeId,
		) -> DispatchResultWithPostInfo {
			let manager_data = Managers::<T>::get(tree_id).ok_or(Error::<T>::ManagerDoesntExist)?;
			ensure_admin(origin, &manager_data.account_id)?;
			<Self as Tree<_>>::set_verifying_key_for_tree(key_id, tree_id)?;
			Ok(().into())
		}
	}
}

sp_api::decl_runtime_apis! {
	pub trait MerkleApi {
		/// Get the leaf of tree id at a given index.
		fn get_leaf(tree_id: u32, index: u32) -> Option<ScalarBytes>;
	}
}

/// Data about the manager of the MerkleTree
#[derive(Clone, Encode, Decode, PartialEq)]
pub struct Manager<T: Config> {
	/// Accound id of the manager
	pub account_id: T::AccountId,
	/// Is manager required to execute guarded functions in the tree
	pub required: bool,
}

impl<T: Config> Manager<T> {
	pub fn new(account_id: T::AccountId, required: bool) -> Self {
		Self { account_id, required }
	}
}

/// Essential data about the tree
///
/// It holds:
/// - Current state of the tree
/// - Data needed for the next insert into the tree
/// - Limits of the tree
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub struct MerkleTree {
	pub initialized: bool,
	/// Current number of leaves in the tree
	pub leaf_count: u32,
	/// Maximum allowed leaves in the tree
	pub max_leaves: u32,
	/// Depth of the tree
	pub depth: u8,
	/// Current root hash of the tree
	pub root_hash: ScalarBytes,
	/// Zero tree
	pub zero_tree: Vec<ScalarBytes>,
	/// Edge nodes needed for the next insert in the tree
	pub edge_nodes: Vec<ScalarBytes>,
	/// Hash function for the merkle tree
	/// Backend used
	pub setup: Setup,
	/// Decide to store leaves or not
	pub should_store_leaves: bool,
}

impl MerkleTree {
	pub fn new<T: Config>(setup: Setup, depth: u8) -> Result<Self, Error<T>> {
		// let (zero_tree, root_hash) = setup.generate_zero_tree(depth as usize)?;
		Ok(Self {
			initialized: false,
			root_hash: ScalarBytes::default(),
			leaf_count: 0,
			depth,
			max_leaves: u32::MAX >> (T::MaxTreeDepth::get() - depth),
			zero_tree: vec![],
			edge_nodes: vec![],
			setup,
			should_store_leaves: true, // the default for now.
		})
	}
}

impl<T: Config> Tree<T> for Pallet<T> {
	fn create_tree(
		sender: T::AccountId,
		is_manager_required: bool,
		setup: Setup,
		depth: u8,
	) -> Result<T::TreeId, DispatchError> {
		ensure!(
			depth <= T::MaxTreeDepth::get() && depth > 0,
			Error::<T>::InvalidTreeDepth
		);

		// Setting the next tree id
		let tree_id = Self::next_tree_id();
		NextTreeId::<T>::mutate(|id| *id += One::one());

		// Setting up the tree
		let mtree = MerkleTree::new::<T>(setup, depth).map_err(|_| Error::<T>::Unimplemented)?;
		Trees::<T>::insert(tree_id, Some(mtree));

		// Setting up the manager
		let manager = Manager::<T>::new(sender.clone(), is_manager_required);
		Managers::<T>::insert(tree_id, Some(manager));

		Self::deposit_event(Event::NewTree(tree_id, sender, is_manager_required));
		Ok(tree_id)
	}

	fn initialize_tree(tree_id: T::TreeId, key_id: T::KeyId) -> Result<(), DispatchError> {
		let mut tree = Trees::<T>::get(tree_id).ok_or(Error::<T>::TreeDoesntExist)?;
		ensure!(!tree.initialized, Error::<T>::AlreadyInitialized);
		let params = Self::get_verifying_key(key_id)?;
		let (zero_tree, root_hash) = tree.setup.generate_zero_tree::<T>(tree.depth as usize, &params)?;
		tree.root_hash = root_hash;
		tree.edge_nodes = zero_tree.clone();
		tree.zero_tree = zero_tree;
		tree.initialized = true;
		Trees::<T>::insert(tree_id, Some(tree));
		<Self as Tree<_>>::set_verifying_key_for_tree(key_id, tree_id)?;
		Ok(())
	}

	fn is_initialized(tree_id: T::TreeId) -> Result<bool, DispatchError> {
		let tree = Trees::<T>::get(tree_id).ok_or(Error::<T>::TreeDoesntExist)?;
		Ok(tree.initialized)
	}

	fn add_verifying_key(key: Vec<u8>) -> Result<T::KeyId, DispatchError> {
		let key_id = Self::next_key_id();
		// Setting the next key id
		NextKeyId::<T>::mutate(|id| *id += One::one());
		VerifyingKeys::<T>::insert(key_id, Some(key));
		Ok(key_id)
	}

	fn set_verifying_key(key_id: T::KeyId, key: Vec<u8>) -> Result<(), DispatchError> {
		let next_id = Self::next_key_id();
		ensure!(key_id < next_id, Error::<T>::InvalidVerifierKey);
		VerifyingKeys::<T>::insert(key_id, Some(key));
		Ok(())
	}

	fn set_verifying_key_for_tree(key_id: T::KeyId, tree_id: T::TreeId) -> Result<(), DispatchError> {
		VerifyingKeyForTree::<T>::insert(tree_id, key_id);
		Ok(())
	}

	fn set_stopped(sender: T::AccountId, id: T::TreeId, stopped: bool) -> Result<(), DispatchError> {
		let manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist)?;
		ensure!(sender == manager_data.account_id, Error::<T>::ManagerIsRequired);
		Stopped::<T>::insert(id, stopped);
		Ok(())
	}

	fn is_stopped(tree_id: T::TreeId) -> bool {
		Stopped::<T>::get(tree_id)
	}

	fn set_manager_required(sender: T::AccountId, id: T::TreeId, manager_required: bool) -> Result<(), DispatchError> {
		let mut manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist)?;
		// Changing manager required should always require an extrinsic from the
		// manager even if the tree doesn't explicitly require managers for
		// other calls.
		ensure!(sender == manager_data.account_id, Error::<T>::ManagerIsRequired);
		manager_data.required = manager_required;
		Managers::<T>::insert(id, Some(manager_data));
		Ok(())
	}

	fn set_manager(sender: T::AccountId, id: T::TreeId, new_manager: T::AccountId) -> Result<(), DispatchError> {
		let mut manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist)?;
		ensure!(sender == manager_data.account_id, Error::<T>::ManagerIsRequired);
		manager_data.account_id = new_manager;
		Managers::<T>::insert(id, Some(manager_data));
		Ok(())
	}

	fn add_members(sender: T::AccountId, id: T::TreeId, members: Vec<ScalarBytes>) -> Result<(), DispatchError> {
		let mut tree = Trees::<T>::get(id).ok_or(Error::<T>::TreeDoesntExist)?;
		let manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist)?;
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(
			Self::is_manager_required(sender.clone(), &manager_data),
			Error::<T>::ManagerIsRequired
		);
		let leaf_count_before = tree.leaf_count;
		let num_members = members.len() as u32;
		ensure!(
			leaf_count_before + num_members <= tree.max_leaves,
			Error::<T>::ExceedsMaxLeaves
		);

		let params = Self::get_verifying_key_for_tree(id)?;
		for data in &members {
			if tree.should_store_leaves {
				Leaves::<T>::insert(id, tree.leaf_count, data);
			}
			// then we add it to the tree itself.
			// note that, this method internally increments the leaves count.
			Self::add_leaf(&mut tree, data, &params)?;
		}
		let block_number: T::BlockNumber = <frame_system::Pallet<T>>::block_number();
		CachedRoots::<T>::append(block_number, id, tree.root_hash.clone());
		Trees::<T>::insert(id, Some(tree));

		// Raising the New Member event for the client to build a tree locally
		Self::deposit_event(Event::NewMembers(id, sender, leaf_count_before, members));
		Ok(())
	}

	fn add_nullifier(sender: T::AccountId, id: T::TreeId, nullifier_hash: ScalarBytes) -> Result<(), DispatchError> {
		let manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist)?;
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(
			Self::is_manager_required(sender.clone(), &manager_data),
			Error::<T>::ManagerIsRequired
		);
		UsedNullifiers::<T>::insert((id, nullifier_hash), true);
		Ok(())
	}

	fn has_used_nullifier(id: T::TreeId, nullifier: ScalarBytes) -> Result<(), DispatchError> {
		let _ = Trees::<T>::get(id).ok_or(Error::<T>::TreeDoesntExist)?;

		ensure!(
			!UsedNullifiers::<T>::contains_key((id, nullifier)),
			Error::<T>::AlreadyUsedNullifier
		);
		Ok(())
	}

	fn verify(id: T::TreeId, leaf: ScalarBytes, path: Vec<(bool, ScalarBytes)>) -> Result<(), DispatchError> {
		let tree = Trees::<T>::get(id).ok_or(Error::<T>::TreeDoesntExist)?;

		ensure!(tree.edge_nodes.len() == path.len(), Error::<T>::InvalidPathLength);
		let params = Self::get_verifying_key_for_tree(id)?;
		let mut hash = leaf;
		for (is_right, node) in path {
			hash = match is_right {
				true => tree.setup.hash::<T>(&hash, &node, &params)?,
				false => tree.setup.hash::<T>(&node, &hash, &params)?,
			}
		}

		ensure!(hash == tree.root_hash, Error::<T>::InvalidMembershipProof);
		Ok(())
	}

	fn verify_zk(
		tree_id: T::TreeId,
		block_number: T::BlockNumber,
		root: ScalarBytes,
		private_inputs: Vec<ScalarBytes>,
		nullifier_hash: ScalarBytes,
		proof_bytes: Vec<u8>,
		path_indices: Vec<ScalarBytes>,
		path_nodes: Vec<ScalarBytes>,
		recipient: ScalarBytes,
		relayer: ScalarBytes,
	) -> Result<(), DispatchError> {
		let tree = Trees::<T>::get(tree_id).ok_or(Error::<T>::TreeDoesntExist)?;
		let key_id = VerifyingKeyForTree::<T>::get(tree_id);
		let verifying_key = VerifyingKeys::<T>::get(key_id);
		// Ensure that root being checked against is in the cache
		let old_roots = Self::cached_roots(block_number, tree_id);
		ensure!(old_roots.iter().any(|r| *r == root), Error::<T>::InvalidMerkleRoot);
		tree.setup.verify_zk::<T>(
			tree.depth as usize,
			root,
			private_inputs,
			nullifier_hash,
			proof_bytes,
			verifying_key,
			path_indices,
			path_nodes,
			recipient,
			relayer,
		)?;
		Ok(())
	}
}

impl<T: Config> Pallet<T> {
	pub fn get_cache(tree_id: T::TreeId, block_number: T::BlockNumber) -> Vec<ScalarBytes> {
		Self::cached_roots(block_number, tree_id)
	}

	pub fn get_merkle_root(tree_id: T::TreeId) -> Result<ScalarBytes, DispatchError> {
		let tree = Self::get_tree(tree_id)?;
		ensure!(tree.initialized, Error::<T>::NotInitialized);
		Ok(tree.root_hash)
	}

	pub fn add_root_to_cache(tree_id: T::TreeId, block_number: T::BlockNumber) -> Result<(), DispatchError> {
		let root = Self::get_merkle_root(tree_id)?;
		CachedRoots::<T>::append(block_number, tree_id, root);
		Ok(())
	}

	pub fn get_tree(tree_id: T::TreeId) -> Result<MerkleTree, DispatchError> {
		let tree = Trees::<T>::get(tree_id).ok_or(Error::<T>::TreeDoesntExist).unwrap();
		Ok(tree)
	}

	pub fn is_manager_required(sender: T::AccountId, manager: &Manager<T>) -> bool {
		if manager.required {
			sender == manager.account_id
		} else {
			true
		}
	}

	pub fn add_leaf(tree: &mut MerkleTree, data: &ScalarBytes, params: &[u8]) -> Result<(), DispatchError> {
		let mut edge_index = tree.leaf_count;
		let mut hash = data.clone();
		let mut edge_nodes = tree.edge_nodes.clone();
		// Update the tree
		for i in 0..edge_nodes.len() {
			hash = if edge_index % 2 == 0 {
				edge_nodes[i] = hash.clone();
				tree.setup.hash::<T>(&hash, &tree.zero_tree[i], params)?
			} else {
				tree.setup.hash::<T>(&edge_nodes[i], &hash, params)?
			};

			edge_index /= 2;
		}

		tree.leaf_count += 1;
		tree.root_hash = hash;
		tree.edge_nodes = edge_nodes;
		Ok(())
	}

	pub fn get_verifying_key_for_tree(id: T::TreeId) -> Result<Vec<u8>, DispatchError> {
		let key_id = VerifyingKeyForTree::<T>::get(id);
		Self::get_verifying_key(key_id)
	}

	pub fn get_verifying_key(id: T::KeyId) -> Result<Vec<u8>, DispatchError> {
		ensure!(id < Self::next_key_id(), Error::<T>::InvalidVerifierKey);
		let maybe_verifying_key = VerifyingKeys::<T>::get(id);
		ensure!(maybe_verifying_key.is_some(), Error::<T>::InvalidVerifierKey);
		Ok(maybe_verifying_key.unwrap())
	}
}
