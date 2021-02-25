// A runtime module Groups with necessary imports

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
//! - Creating merkle trees.
//! - Adding the manager and setting whether the manager is required.
//! - Adding leaf data to the Merkle tree.
//! - Adding nullifiers to the storage.
//! - Managing start/stop flags.
//! - Caching merkle tree states.
//! - Verifying regular and zero-knowledge membership proofs
//!
//! ### Terminology
//!
//! - **Membership proof in zero-knowladge:** Proving that leaf is inside the
//!   tree without revealing which leaf you are proving over.
//!
//! - **Proof of creation in zero-knowladge:** TBA
//!
//! - **Nullifier:** Each leaf is made with an arithmetic circuit which includes
//!   hashing several values. Nullifier is a part of this leaf circuit and is
//!   revealed when proving membership in zero-knowladge.
//!
//! ### Implementations
//!
//! The merkle pallet provides implementations for following traits:
//!
//! - [`Group`](pallet_merkle::group_trait::Group) Functions for crerating and
//!   managing the group.
//!
//! ## Interface
//!
//! ### Dispatchable functions
//!
//! - `create_group` - Create merkle tree and their respective manager account.
//! - `set_manager_required` - Set whether manager is required to add members
//!   and nullifiers.
//! - `set_manager` - Set manager account id. Can only be called by the root or
//!   the current manager.
//! - `set_stopped` - Sets stopped storage flag. This flag by itself doesn't do
//!   anything. It's up to a higher level pallets to make an appropriate use of
//!   it. Can only be called by the root or the manager;
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
//! use pallet_merkle::group_trait::Group;
//! pub trait Config: frame_system::Config + pallet_merkle::Config {
//! 	type Group: Group<Self::AccountId, Self::BlockNumber, Self::GroupId>;
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod utils;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;

pub use crate::group_trait::Group;
use bulletproofs::{
	r1cs::{R1CSProof, Verifier},
	BulletproofGens, PedersenGens,
};
use codec::{Decode, Encode};
use curve25519_dalek::scalar::Scalar;
use curve25519_gadgets::{
	crypto_constants::smt::ZERO_TREE,
	fixed_deposit_tree::fixed_deposit_tree_verif_gadget,
	poseidon::{
		allocate_statics_for_verifier,
		builder::{Poseidon, PoseidonBuilder},
		gen_mds_matrix, gen_round_keys, PoseidonSbox, Poseidon_hash_2,
	},
	utils::AllocatedScalar,
};
use frame_support::{dispatch, ensure, traits::Get, weights::Weight, Parameter};
use frame_system::ensure_signed;
use sp_std::prelude::*;

use merlin::Transcript;
use rand_core::OsRng;
use sp_runtime::traits::{AtLeast32Bit, One};
use utils::{
	keys::{Commitment, ScalarData},
	permissions::ensure_admin,
};
use weights::WeightInfo;

pub mod group_trait;

// TODO find better way to have default hasher without saving it inside storage
pub fn default_hasher() -> Poseidon {
	let width = 6;
	let (full_b, full_e) = (4, 4);
	let partial_rounds = 57;
	// TODO: should be able to pass number of generators
	// TODO: Initialise these generators with the pallet
	let bp_gens = BulletproofGens::new(16400, 1);
	PoseidonBuilder::new(width)
		.num_rounds(full_b, full_e, partial_rounds)
		.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
		.mds_matrix(gen_mds_matrix(width))
		.bulletproof_gens(bp_gens)
		.sbox(PoseidonSbox::Inverse)
		.build()
}

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// The pallet's configuration trait.
	#[pallet::config]
	pub trait Config: frame_system::Config + balances::Config {
		/// The overarching event type.
		type Event: IsType<<Self as frame_system::Config>::Event> + From<Event<Self>>;
		/// The overarching group ID type
		type GroupId: Encode + Decode + Parameter + AtLeast32Bit + Default + Copy;
		/// The max depth of trees
		type MaxTreeDepth: Get<u8>;
		/// The amount of blocks to cache roots over
		type CacheBlockLength: Get<Self::BlockNumber>;
		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Value was None
		NoneValue,
		///
		IncorrectNumOfPubKeys,
		///
		ChallengeMismatch,
		///
		BadPoint,
		///
		ExceedsMaxDepth,
		///
		GroupDoesntExist,
		///
		InvalidMembershipProof,
		///
		InvalidPathLength,
		///
		InvalidPrivateInputs,
		///
		AlreadyUsedNullifier,
		///
		ZkVericationFailed,
		///
		InvalidZkProof,
		///
		InvalidTreeDepth,
		///
		InvalidMerkleRoot,
		///
		DepositLengthTooSmall,
		///
		ManagerIsRequired,
		///
		ManagerDoesntExist,
	}

	#[derive(Clone, Encode, Decode, PartialEq)]
	pub struct Manager<T: Config> {
		pub account_id: T::AccountId,
		pub required: bool,
	}

	impl<T: Config> Manager<T> {
		pub fn new(account_id: T::AccountId, required: bool) -> Self {
			Self { account_id, required }
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	pub enum Event<T: Config> {
		NewMember(T::GroupId, T::AccountId, Vec<ScalarData>),
	}

	/// Old name generated by `decl_event`.
	// #[deprecated(note = "use `Event` instead")]
	// pub type RawEvent<T, I = ()> = Event<T, I>;

	/// The next group identifier up for grabs
	#[pallet::storage]
	#[pallet::getter(fn next_group_id)]
	pub type NextGroupId<T: Config> = StorageValue<_, T::GroupId, ValueQuery>;

	/// The map of groups to their metadata
	#[pallet::storage]
	#[pallet::getter(fn groups)]
	pub type Groups<T: Config> = StorageMap<_, Blake2_128Concat, T::GroupId, Option<GroupTree>, ValueQuery>;

	/// Map of cached/past merkle roots at each blocknumber and group. There can
	/// be more than one root update in a single block. Allows for easy pruning
	/// since we can remove all keys of first map past a certain point.
	#[pallet::storage]
	#[pallet::getter(fn cached_roots)]
	pub type CachedRoots<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::BlockNumber,
		Blake2_128Concat,
		T::GroupId,
		Vec<ScalarData>,
		ValueQuery,
	>;

	#[pallet::storage]
	#[pallet::getter(fn get_manager)]
	pub type Managers<T: Config> = StorageMap<_, Blake2_128Concat, T::GroupId, Option<Manager<T>>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn lowest_cached_block)]
	pub type LowestCachedBlock<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn highest_cached_block)]
	pub type HighestCachedBlock<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;
	/// Map of used nullifiers (Data) for each tree.
	#[pallet::storage]
	#[pallet::getter(fn used_nullifiers)]
	pub type UsedNullifiers<T: Config> = StorageMap<_, Blake2_128Concat, (T::GroupId, ScalarData), bool, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn stopped)]
	pub type Stopped<T: Config> = StorageMap<_, Blake2_128Concat, T::GroupId, bool, ValueQuery>;

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
		/// Creates a new group and sets a new manager for that group. The
		/// initial manager is the sender. Also increments the mixer id counter
		/// in the storage. If _depth is not provided, max tree depth is
		/// assumed.
		///
		/// Weights:
		/// - Dependent on arguments: _depth
		///
		/// - Base weight: 7_618_000
		/// - DB weights: 1 read, 3 writes
		/// - Additional weights: 151_000 * _depth
		#[pallet::weight(<T as Config>::WeightInfo::create_group(_depth.map_or(T::MaxTreeDepth::get() as u32, |x| x as u32)))]
		pub fn create_group(origin: OriginFor<T>, r_is_mgr: bool, _depth: Option<u8>) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let depth = match _depth {
				Some(d) => d,
				None => T::MaxTreeDepth::get(),
			};
			let _ = <Self as Group<_, _, _>>::create_group(sender, r_is_mgr, depth)?;
			Ok(().into())
		}

		/// Sets if manager is required for specific actions like adding
		/// nullifiers or leaves into the tree.
		///
		/// Can only be called by the root or the current manager.
		///
		/// Weights:
		/// - Independend of the arguments.
		///
		/// - Base weight: 8_000_000
		/// - DB weights: 1 read, 1 write
		#[pallet::weight(<T as Config>::WeightInfo::set_manager_required())]
		pub fn set_manager_required(
			origin: OriginFor<T>,
			group_id: T::GroupId,
			manager_required: bool,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;

			<Self as Group<_, _, _>>::set_manager_required(sender, group_id, manager_required)?;
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
			group_id: T::GroupId,
			new_manager: T::AccountId,
		) -> DispatchResultWithPostInfo {
			let manager_data = Managers::<T>::get(group_id)
				.ok_or(Error::<T>::ManagerDoesntExist)
				.unwrap();
			// Changing manager should always require an extrinsic from the manager or root
			// even if the group doesn't explicitly require managers for other calls.
			ensure_admin(origin, &manager_data.account_id)?;
			// We are passing manager always, since we wont have account id when calling
			// from root origin
			<Self as Group<_, _, _>>::set_manager(manager_data.account_id, group_id, new_manager)?;
			Ok(().into())
		}

		/// Set stopped flag inside the storage.
		///
		/// Can only be called by the root or the current manager.
		///
		/// Weights:
		/// - Independent of the arguments.
		///
		/// - Base weight: 7_000_000
		/// - DB weights: 1 read, 1 write
		#[pallet::weight(<T as Config>::WeightInfo::set_stopped())]
		pub fn set_stopped(origin: OriginFor<T>, group_id: T::GroupId, stopped: bool) -> DispatchResultWithPostInfo {
			let manager_data = Managers::<T>::get(group_id)
				.ok_or(Error::<T>::ManagerDoesntExist)
				.unwrap();
			ensure_admin(origin, &manager_data.account_id)?;
			<Self as Group<_, _, _>>::set_stopped(manager_data.account_id, group_id, stopped)?;
			Ok(().into())
		}

		/// Adds an array of leaf data into the tree and adds calculated root to
		/// the cache.
		///
		/// Can only be called by the manager if manager is set.
		///
		/// Weights:
		/// - Dependent on argument: `members`
		///
		/// - Base weight: 305_389_489_000
		/// - DB weights: 3 reads, 2 writes
		/// - Additional weights: 63_659_275_000 * members.len()
		#[pallet::weight(<T as Config>::WeightInfo::add_members(members.len() as u32))]
		pub fn add_members(
			origin: OriginFor<T>,
			group_id: T::GroupId,
			members: Vec<ScalarData>,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			<Self as Group<_, _, _>>::add_members(sender, group_id, members)?;
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
		/// - Base weight: 310_970_311_000
		/// - DB weights: 1 read
		/// - Additional weights: 3_666_683_000 * path.len()
		#[pallet::weight(<T as Config>::WeightInfo::verify_path(path.len() as u32))]
		pub fn verify(
			origin: OriginFor<T>,
			group_id: T::GroupId,
			leaf: ScalarData,
			path: Vec<(bool, ScalarData)>,
		) -> DispatchResultWithPostInfo {
			let _sender = ensure_signed(origin)?;
			<Self as Group<_, _, _>>::verify(group_id, leaf, path)?;
			Ok(().into())
		}
	}
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub struct GroupTree {
	pub leaf_count: u32,
	pub max_leaves: u32,
	pub depth: u8,
	pub root_hash: ScalarData,
	pub edge_nodes: Vec<ScalarData>,
}

impl GroupTree {
	pub fn new<T: Config>(depth: u8) -> Self {
		let init_edges: Vec<ScalarData> = ZERO_TREE[0..depth as usize]
			.iter()
			.map(|x| ScalarData::from(*x))
			.collect();
		let init_root = ScalarData::from(ZERO_TREE[depth as usize]);
		Self {
			root_hash: init_root,
			leaf_count: 0,
			depth,
			max_leaves: u32::MAX >> (T::MaxTreeDepth::get() - depth),
			edge_nodes: init_edges,
		}
	}
}

impl<T: Config> Group<T::AccountId, T::BlockNumber, T::GroupId> for Pallet<T> {
	fn create_group(
		sender: T::AccountId,
		is_manager_required: bool,
		depth: u8,
	) -> Result<T::GroupId, dispatch::DispatchError> {
		ensure!(
			depth <= T::MaxTreeDepth::get() && depth > 0,
			Error::<T>::InvalidTreeDepth
		);

		// Setting the next group id
		let group_id = Self::next_group_id();
		NextGroupId::<T>::mutate(|id| *id += One::one());

		// Setting up the tree
		let mtree = GroupTree::new::<T>(depth);
		Groups::<T>::insert(group_id, Some(mtree));

		// Setting up the manager
		let manager = Manager::<T>::new(sender, is_manager_required);
		Managers::<T>::insert(group_id, Some(manager));
		Ok(group_id)
	}

	fn set_stopped(sender: T::AccountId, id: T::GroupId, stopped: bool) -> Result<(), dispatch::DispatchError> {
		let manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist).unwrap();
		ensure!(sender == manager_data.account_id, Error::<T>::ManagerIsRequired);
		Stopped::<T>::insert(id, stopped);
		Ok(())
	}

	fn set_manager_required(
		sender: T::AccountId,
		id: T::GroupId,
		manager_required: bool,
	) -> Result<(), dispatch::DispatchError> {
		let mut manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist).unwrap();
		// Changing manager required should always require an extrinsic from the
		// manager even if the group doesn't explicitly require managers for
		// other calls.
		ensure!(sender == manager_data.account_id, Error::<T>::ManagerIsRequired);
		manager_data.required = manager_required;
		Managers::<T>::insert(id, Some(manager_data));
		Ok(())
	}

	fn set_manager(
		sender: T::AccountId,
		id: T::GroupId,
		new_manager: T::AccountId,
	) -> Result<(), dispatch::DispatchError> {
		let mut manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist).unwrap();
		ensure!(sender == manager_data.account_id, Error::<T>::ManagerIsRequired);
		manager_data.account_id = new_manager;
		Managers::<T>::insert(id, Some(manager_data));
		Ok(())
	}

	fn add_members(
		sender: T::AccountId,
		id: T::GroupId,
		members: Vec<ScalarData>,
	) -> Result<(), dispatch::DispatchError> {
		let mut tree = Groups::<T>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		let manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist).unwrap();
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(
			Self::is_manager_required(sender.clone(), &manager_data),
			Error::<T>::ManagerIsRequired
		);
		let num_points = members.len() as u32;
		ensure!(
			tree.leaf_count + num_points <= tree.max_leaves,
			Error::<T>::ExceedsMaxDepth
		);

		let h = default_hasher();
		for data in &members {
			Self::add_leaf(&mut tree, *data, &h);
		}
		let block_number: T::BlockNumber = <frame_system::Module<T>>::block_number();
		CachedRoots::<T>::append(block_number, id, tree.root_hash);
		Groups::<T>::insert(id, Some(tree));

		// Raising the New Member event for the client to build a tree locally
		Self::deposit_event(Event::NewMember(id, sender, members));
		Ok(())
	}

	fn add_nullifier(
		sender: T::AccountId,
		id: T::GroupId,
		nullifier_hash: ScalarData,
	) -> Result<(), dispatch::DispatchError> {
		let manager_data = Managers::<T>::get(id).ok_or(Error::<T>::ManagerDoesntExist).unwrap();
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(
			Self::is_manager_required(sender.clone(), &manager_data),
			Error::<T>::ManagerIsRequired
		);
		UsedNullifiers::<T>::insert((id, nullifier_hash), true);
		Ok(())
	}

	fn has_used_nullifier(id: T::GroupId, nullifier: ScalarData) -> Result<(), dispatch::DispatchError> {
		let _ = Groups::<T>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();

		ensure!(
			!UsedNullifiers::<T>::contains_key((id, nullifier)),
			Error::<T>::AlreadyUsedNullifier
		);
		Ok(())
	}

	fn verify(id: T::GroupId, leaf: ScalarData, path: Vec<(bool, ScalarData)>) -> Result<(), dispatch::DispatchError> {
		let tree = Groups::<T>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();

		ensure!(tree.edge_nodes.len() == path.len(), Error::<T>::InvalidPathLength);
		let h = default_hasher();
		let mut hash = leaf.0;
		for (is_right, node) in path {
			hash = match is_right {
				true => Poseidon_hash_2(hash, node.0, &h),
				false => Poseidon_hash_2(node.0, hash, &h),
			}
		}

		ensure!(hash == tree.root_hash.0, Error::<T>::InvalidMembershipProof);
		Ok(())
	}

	fn verify_zk_membership_proof(
		group_id: T::GroupId,
		cached_block: T::BlockNumber,
		cached_root: ScalarData,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
	) -> Result<(), dispatch::DispatchError> {
		let tree = Groups::<T>::get(group_id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		ensure!(
			tree.edge_nodes.len() == proof_commitments.len(),
			Error::<T>::InvalidPathLength
		);
		// Ensure that root being checked against is in the cache
		let old_roots = Self::cached_roots(cached_block, group_id);
		ensure!(
			old_roots.iter().any(|r| *r == cached_root),
			Error::<T>::InvalidMerkleRoot
		);
		// TODO: Initialise these generators with the pallet
		let pc_gens = PedersenGens::default();
		<Self as Group<_, _, _>>::verify_zk(
			pc_gens,
			cached_root,
			tree.depth,
			comms,
			nullifier_hash,
			proof_bytes,
			leaf_index_commitments,
			proof_commitments,
		)
	}

	fn verify_zk(
		pc_gens: PedersenGens,
		m_root: ScalarData,
		depth: u8,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
	) -> Result<(), dispatch::DispatchError> {
		let label = b"zk_membership_proof";
		let h = default_hasher();
		let mut verifier_transcript = Transcript::new(label);
		let mut verifier = Verifier::new(&mut verifier_transcript);

		ensure!(comms.len() == 3, Error::<T>::InvalidPrivateInputs);
		let r_val = verifier.commit(comms[0].0);
		let r_alloc = AllocatedScalar {
			variable: r_val,
			assignment: None,
		};
		let nullifier_val = verifier.commit(comms[1].0);
		let nullifier_alloc = AllocatedScalar {
			variable: nullifier_val,
			assignment: None,
		};

		let var_leaf = verifier.commit(comms[2].0);
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: None,
		};

		let mut leaf_index_alloc_scalars = vec![];
		for l in leaf_index_commitments {
			let v = verifier.commit(l.0);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let mut proof_alloc_scalars = vec![];
		for p in proof_commitments {
			let v = verifier.commit(p.0);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);
		let gadget_res = fixed_deposit_tree_verif_gadget(
			&mut verifier,
			depth as usize,
			&m_root.0,
			&nullifier_hash.0,
			r_alloc,
			nullifier_alloc,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&h,
		);
		ensure!(gadget_res.is_ok(), Error::<T>::InvalidZkProof);

		let proof = R1CSProof::from_bytes(&proof_bytes);
		ensure!(proof.is_ok(), Error::<T>::InvalidZkProof);
		let proof = proof.unwrap();

		let mut rng = OsRng::default();
		let verify_res = verifier.verify_with_rng(&proof, &h.pc_gens, &h.bp_gens, &mut rng);
		ensure!(verify_res.is_ok(), Error::<T>::ZkVericationFailed);
		Ok(())
	}
}

impl<T: Config> Pallet<T> {
	pub fn get_cache(group_id: T::GroupId, block_number: T::BlockNumber) -> Vec<ScalarData> {
		Self::cached_roots(block_number, group_id)
	}

	pub fn get_merkle_root(group_id: T::GroupId) -> Result<ScalarData, dispatch::DispatchError> {
		let group = Self::get_group(group_id)?;
		Ok(group.root_hash)
	}

	pub fn add_root_to_cache(
		group_id: T::GroupId,
		block_number: T::BlockNumber,
	) -> Result<(), dispatch::DispatchError> {
		let root = Self::get_merkle_root(group_id)?;
		CachedRoots::<T>::append(block_number, group_id, root);
		Ok(())
	}

	pub fn get_group(group_id: T::GroupId) -> Result<GroupTree, dispatch::DispatchError> {
		let tree = Groups::<T>::get(group_id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		Ok(tree)
	}

	pub fn is_manager_required(sender: T::AccountId, manager: &Manager<T>) -> bool {
		if manager.required {
			return sender == manager.account_id;
		} else {
			return true;
		}
	}

	pub fn add_leaf(tree: &mut GroupTree, data: ScalarData, h: &Poseidon) {
		let mut edge_index = tree.leaf_count;
		let mut hash = data.0;
		// Update the tree
		for i in 0..tree.edge_nodes.len() {
			hash = if edge_index % 2 == 0 {
				tree.edge_nodes[i] = ScalarData(hash);
				let zero_h = Scalar::from_bytes_mod_order(ZERO_TREE[i]);
				Poseidon_hash_2(hash, zero_h, h)
			} else {
				Poseidon_hash_2(tree.edge_nodes[i].0, hash, h)
			};

			edge_index /= 2;
		}

		tree.leaf_count += 1;
		tree.root_hash = ScalarData(hash);
	}
}
