#![cfg_attr(not(feature = "std"), no_std)]

/// A runtime module Groups with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references

/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs
pub mod merkle;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

use sp_runtime::traits::One;
use frame_support::traits::Get;
use sp_runtime::traits::AtLeast32Bit;
use frame_support::Parameter;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use merkle::hasher::Hasher;
use merkle::keys::{Commitment, Data};

use merkle::poseidon::Poseidon;
use merlin::Transcript;
use rand_core::OsRng;
use sp_std::prelude::*;

/// The pallet's configuration trait.
pub trait Trait: balances::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	/// The overarching group ID type
	type GroupId: Parameter + AtLeast32Bit + Default + Copy;
	/// The max depth of trees
	type MaxTreeDepth: Get<u8>;
	/// The amount of blocks to cache roots over
	type CacheBlockLength: Get<Self::BlockNumber>;
}

// TODO find better way to have default hasher without saving it inside storage
fn default_hasher() -> impl Hasher {
	Poseidon::new(4)
	// Mimc::new(70)
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Encode, Decode, PartialEq)]
pub struct GroupTree<T: Trait> {
	pub manager: T::AccountId,
	pub requires_is_manager: bool,
	pub leaf_count: u32,
	pub max_leaves: u32,
	pub root_hash: Data,
	pub edge_nodes: Vec<Data>,
}

impl<T: Trait> GroupTree<T> {
	pub fn new(mgr: T::AccountId, r_is_mgr: bool, depth: u8) -> Self {
		Self {
			manager: mgr,
			requires_is_manager: r_is_mgr,
			root_hash: Data::zero(),
			leaf_count: 0,
			max_leaves: u32::MAX >> (T::MaxTreeDepth::get() - depth),
			edge_nodes: vec![Data::zero(); depth as usize],
		}
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as MerkleGroups {
		/// The next group identifier up for grabs
		pub NextGroupId get(fn next_group_id): T::GroupId;
		/// The map of groups to their metadata
		pub Groups get(fn groups): map hasher(blake2_128_concat) T::GroupId => Option<GroupTree<T>>;
		/// Map of cached/past merkle roots at each blocknumber and group. There can be more than one root update in a single block.
		/// Allows for easy pruning since we can remove all keys of first map past a certain point.
		pub CachedRoots get(fn cached_roots): double_map hasher(blake2_128_concat) T::BlockNumber, hasher(blake2_128_concat) T::GroupId => Vec<Data>;
		pub LowestCachedBlock get(fn lowest_cached_block): T::BlockNumber;
		pub HighestCachedBlock get(fn highest_cached_block): T::BlockNumber;
		/// Map of used nullifiers (Data) for each tree.
		pub UsedNullifiers get(fn used_nullifiers): map hasher(blake2_128_concat) (T::GroupId, Data) => bool;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T>
	where
		AccountId = <T as frame_system::Trait>::AccountId,
		GroupId = <T as Trait>::GroupId,
	{
		NewMember(GroupId, AccountId, Vec<Data>),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Trait> {
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
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 0]
		pub fn set_manager_required(origin, group_id: T::GroupId, manager_required: bool) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;

			let mut tree = <Groups<T>>::get(group_id)
				.ok_or(Error::<T>::GroupDoesntExist)
				.unwrap();
			// Changing manager required should always require an extrinsic from the manager even
			// if the group doesn't explicitly require managers for other calls.
			ensure!(sender == tree.manager, Error::<T>::ManagerIsRequired);
			tree.requires_is_manager = manager_required;
			Ok(())
		}

		#[weight = 0]
		pub fn set_manager(origin, group_id: T::GroupId, new_manager: T::AccountId) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;

			let mut tree = <Groups<T>>::get(group_id)
				.ok_or(Error::<T>::GroupDoesntExist)
				.unwrap();
			// Changing manager should always require an extrinsic from the manager even
			// if the group doesn't explicitly require managers for other calls.
			ensure!(sender == tree.manager, Error::<T>::ManagerIsRequired);
			
			tree.manager = new_manager;
			Ok(())
		}

		#[weight = 0]
		pub fn add_members(origin, group_id: T::GroupId, data_points: Vec<Data>) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;

			let mut tree = <Groups<T>>::get(group_id)
				.ok_or(Error::<T>::GroupDoesntExist)
				.unwrap();
			// Check if the tree requires extrinsics to be called from a manager
			ensure!(Self::is_manager_required(sender.clone(), &tree), Error::<T>::ManagerIsRequired);
			let num_points = data_points.len() as u32;
			ensure!(tree.leaf_count + num_points <= tree.max_leaves, Error::<T>::ExceedsMaxDepth);

			let h = default_hasher();
			for data in &data_points {
				Self::add_leaf(&mut tree, *data, &h);
			}
			let block_number: T::BlockNumber = <frame_system::Module<T>>::block_number();
			CachedRoots::<T>::append(block_number, group_id, tree.root_hash);
			Groups::<T>::insert(group_id, tree);

			// Raising the New Member event for the client to build a tree locally
			Self::deposit_event(RawEvent::NewMember(group_id, sender, data_points));
			Ok(())
		}

		/// Verification stub for testing, these verification functions should
		/// not need to be used directly as extrinsics. Rather, higher-order
		/// modules should use the module functions to verify and execute further
		/// logic.
		#[weight = 0]
		pub fn verify(origin, group_id: T::GroupId, leaf: Data, path: Vec<(bool, Data)>) -> dispatch::DispatchResult {
			let tree = <Groups<T>>::get(group_id)
				.ok_or(Error::<T>::GroupDoesntExist)
				.unwrap();
			ensure!(tree.edge_nodes.len() == path.len(), Error::<T>::InvalidPathLength);
			let h = default_hasher();
			let mut hash = leaf;
			for (is_right, node) in path {
				hash = match is_right {
					true => Data::hash(hash, node, &h),
					false => Data::hash(node, hash, &h),
				}
			}

			ensure!(hash == tree.root_hash, Error::<T>::InvalidMembershipProof);
			Ok(())
		}

		#[weight = 0]
		pub fn create_group(origin, r_is_mgr: bool, _depth: Option<u8>) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			let group_id = Self::next_group_id();
			NextGroupId::<T>::mutate(|id| *id += One::one());

			let depth = match _depth {
				Some(d) => d,
				None => T::MaxTreeDepth::get()
			};

			ensure!(depth <= T::MaxTreeDepth::get() && depth > 0, Error::<T>::InvalidTreeDepth);

			let mtree = GroupTree::<T>::new(sender, r_is_mgr, depth);
			<Groups<T>>::insert(group_id, mtree);

			Ok(())
		}

		/// Verification stub for testing, these verification functions should
		/// not need to be used directly as extrinsics. Rather, higher-order
		/// modules should use the module functions to verify and execute further
		/// logic.
		#[weight = 0]
		pub fn verify_zk_membership_proof(
			origin,
			group_id: T::GroupId,
			leaf_com: Commitment,
			path: Vec<(Commitment, Commitment)>,
			r_com: Commitment,
			nullifier: Data,
			proof_bytes: Vec<u8>
		) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::verify_zk_proof(
				sender,
				group_id,
				leaf_com,
				path,
				r_com,
				nullifier,
				proof_bytes,
			)?;
			// Set nullifier as used
			UsedNullifiers::<T>::insert((group_id, nullifier), true);
			Ok(())
		}

		/// Verification stub for testing, these verification functions should
		/// not need to be used directly as extrinsics. Rather, higher-order
		/// modules should use the module functions to verify and execute further
		/// logic.
		#[weight = 0]
		pub fn verify_zk_membership_proof_with_cache(
			origin,
			old_block: T::BlockNumber,
			old_root: Data,
			group_id: T::GroupId,
			leaf_com: Commitment,
			path: Vec<(Commitment, Commitment)>,
			r_com: Commitment,
			nullifier: Data,
			proof_bytes: Vec<u8>
		) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::verify_zk_proof_with_cache(
				sender,
				old_block,
				old_root,
				group_id,
				leaf_com,
				path,
				r_com,
				nullifier,
				proof_bytes,
			)?;
			// Set nullifier as used
			UsedNullifiers::<T>::insert((group_id, nullifier), true);
			Ok(())
		}

		fn on_finalize(_n: T::BlockNumber) {
			// update highest block in cache
			if HighestCachedBlock::<T>::get() < _n {
				HighestCachedBlock::<T>::set(_n);
			}

			// initialise lowest block in cache if not already
			if LowestCachedBlock::<T>::get() <= One::one() {
				LowestCachedBlock::<T>::set(_n);
			}

			// update and prune database if pruning length has been hit
			if HighestCachedBlock::<T>::get() - T::CacheBlockLength::get() > LowestCachedBlock::<T>::get() {
				CachedRoots::<T>::remove_prefix(LowestCachedBlock::<T>::get());
				LowestCachedBlock::<T>::set(LowestCachedBlock::<T>::get() + One::one());
			}
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn is_manager_required(sender: T::AccountId, tree: &GroupTree<T>) -> bool {
		if tree.requires_is_manager {
			return sender == tree.manager;
		} else {
			return true;
		}
	}

	pub fn add_leaf<H: Hasher>(tree: &mut GroupTree<T>, data: Data, h: &H) {
		let mut edge_index = tree.leaf_count;
		let mut pair_hash = data;
		// Update the tree
		for i in 0..tree.edge_nodes.len() {
			if edge_index % 2 == 0 {
				tree.edge_nodes[i] = pair_hash;
			}

			let hash = tree.edge_nodes[i];
			pair_hash = Data::hash(hash, pair_hash, h);

			edge_index /= 2;
		}

		tree.leaf_count += 1;
		tree.root_hash = pair_hash;
	}

	pub fn verify_zk_proof(
		sender: T::AccountId,
		group_id: T::GroupId,
		leaf_com: Commitment,
		path: Vec<(Commitment, Commitment)>,
		r_com: Commitment,
		nullifier: Data,
		proof_bytes: Vec<u8>
	) -> Result<(), Error<T>> {
		let tree = <Groups<T>>::get(group_id)
			.ok_or(Error::<T>::GroupDoesntExist)
			.unwrap();
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(Self::is_manager_required(sender, &tree), Error::<T>::ManagerIsRequired);
		// Ensure that nullifier is not used
		ensure!(!UsedNullifiers::<T>::get((group_id, nullifier)), Error::<T>::AlreadyUsedNullifier);
		ensure!(tree.edge_nodes.len() == path.len(), Error::<T>::InvalidPathLength);
		// TODO: Initialise these generators with the pallet
		let pc_gens = PedersenGens::default();
		// TODO: should be able to pass number of generators
		// TODO: Initialise these generators with the pallet
		let bp_gens = BulletproofGens::new(4096, 1);
		Self::verify_zk(
			pc_gens,
			bp_gens,
			tree.root_hash,
			leaf_com,
			path,
			r_com,
			nullifier,
			proof_bytes,
		)
		// // Set nullifier as used
		// UsedNullifiers::<T>::insert((group_id, nullifier), true);
		// Ok(())
	}

	pub fn verify_zk_proof_with_cache(
		sender: T::AccountId,
		old_block: T::BlockNumber,
		old_root: Data,
		group_id: T::GroupId,
		leaf_com: Commitment,
		path: Vec<(Commitment, Commitment)>,
		r_com: Commitment,
		nullifier: Data,
		proof_bytes: Vec<u8>
	) -> Result<(), Error<T>> {
		let tree = <Groups<T>>::get(group_id)
			.ok_or(Error::<T>::GroupDoesntExist)
			.unwrap();
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(Self::is_manager_required(sender, &tree), Error::<T>::ManagerIsRequired);
		// Ensure that nullifier is not used
		ensure!(!UsedNullifiers::<T>::get((group_id, nullifier)), Error::<T>::AlreadyUsedNullifier);
		ensure!(tree.edge_nodes.len() == path.len(), Error::<T>::InvalidPathLength);
		// Ensure that root being checked against is in the cache
		let old_roots = Self::cached_roots(old_block, group_id);
		ensure!(old_roots.iter().any(|r| *r == old_root), Error::<T>::InvalidMerkleRoot);
		// TODO: Initialise these generators with the pallet
		let pc_gens = PedersenGens::default();
		// TODO: should be able to pass number of generators
		// TODO: Initialise these generators with the pallet
		let bp_gens = BulletproofGens::new(4096, 1);
		Self::verify_zk(
			pc_gens,
			bp_gens,
			tree.root_hash,
			leaf_com,
			path,
			r_com,
			nullifier,
			proof_bytes,
		)
	}

	fn verify_zk(
		pc_gens: PedersenGens,
		bp_gens: BulletproofGens,
		m_root: Data,
		leaf_com: Commitment,
		path: Vec<(Commitment, Commitment)>,
		r_com: Commitment,
		nullifier: Data,
		proof_bytes: Vec<u8>
	) -> Result<(), Error<T>>{
		let h = default_hasher();
		let mut verifier_transcript = Transcript::new(b"zk_membership_proof");
		let mut verifier = Verifier::new(&mut verifier_transcript);

		let var_leaf = verifier.commit(leaf_com.0);
		let var_s = verifier.commit(r_com.0);
		let leaf_lc =
			Data::constrain_verifier(&mut verifier, &pc_gens, var_s.into(), nullifier.0.into(), &h);
		// Commited leaf value should be the same as calculated
		verifier.constrain(leaf_lc - var_leaf);

		// Check of path proof is correct
		// hash = 5
		let mut hash: LinearCombination = var_leaf.into();
		for (bit, pair) in path {
			// e.g. If bit is 1 that means pair is on the right side
			// var_bit = 1
			let var_bit = verifier.commit(bit.0);
			// pair = 3
			let var_pair = verifier.commit(pair.0);

			// temp = 1 * 3 - 5 = -2
			let (_, _, var_temp) = verifier.multiply(var_bit.into(), var_pair - hash.clone());
			// left = 5 - 2 = 3
			let left = hash.clone() + var_temp;
			// right = 3 + 5 - 3 = 5
			let right = var_pair + hash - left.clone();

			hash = Data::constrain_verifier(&mut verifier, &pc_gens, left, right, &h);
		}
		// Commited path evaluate to correct root
		verifier.constrain(hash - m_root.0);

		let proof = R1CSProof::from_bytes(&proof_bytes);
		ensure!(proof.is_ok(), Error::<T>::InvalidZkProof);
		let proof = proof.unwrap();

		let mut rng = OsRng {};
		// Final verification
		let res = verifier.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut rng);
		if res.is_ok() {
			Ok(())
		} else {
			Err(Error::<T>::ZkVericationFailed)
		}
	}
}
