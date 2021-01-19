#![cfg_attr(not(feature = "std"), no_std)]

/// A runtime module Groups with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in
/// runtime/src/lib.rs If you remove this file, you can remove those references

/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs
pub mod merkle;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

pub use crate::group_trait::Group;
use bulletproofs::{
	r1cs::{ConstraintSystem, LinearCombination, R1CSProof, Verifier},
	BulletproofGens, PedersenGens,
};
use codec::{Decode, Encode};
use curve25519_gadgets::smt::smt::vanilla_merkle_merkle_tree_verif_gadget;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure, traits::Get, Parameter};
use frame_system::{ensure_root, ensure_signed};
use merkle::{
	hasher::Hasher,
	keys::{Commitment, Data},
	poseidon::Poseidon,
};
use merlin::Transcript;
use rand_core::OsRng;
use sp_runtime::traits::{AtLeast32Bit, One};
use sp_std::prelude::*;

pub mod group_trait;

/// The pallet's configuration trait.
pub trait Config: frame_system::Config + balances::Config {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
	/// The overarching group ID type
	type GroupId: Encode + Decode + Parameter + AtLeast32Bit + Default + Copy;
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
#[derive(Clone, Encode, Decode, PartialEq)]
pub struct GroupTree<T: Config> {
	pub manager: T::AccountId,
	pub manager_required: bool,
	pub leaf_count: u32,
	pub max_leaves: u32,
	pub root_hash: Data,
	pub edge_nodes: Vec<Data>,
}

impl<T: Config> GroupTree<T> {
	pub fn new(mgr: T::AccountId, r_is_mgr: bool, depth: u8) -> Self {
		Self {
			manager: mgr,
			manager_required: r_is_mgr,
			root_hash: Data::zero(),
			leaf_count: 0,
			max_leaves: u32::MAX >> (T::MaxTreeDepth::get() - depth),
			edge_nodes: vec![Data::zero(); depth as usize],
		}
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Config> as MerkleGroups {
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
		AccountId = <T as frame_system::Config>::AccountId,
		GroupId = <T as Config>::GroupId,
	{
		NewMember(GroupId, AccountId, Vec<Data>),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Config> {
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
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 0]
		pub fn create_group(origin, r_is_mgr: bool, _depth: Option<u8>) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			let depth = match _depth {
				Some(d) => d,
				None => T::MaxTreeDepth::get()
			};
			let _ = <Self as Group<_,_,_>>::create_group(sender, r_is_mgr, depth)?;
			Ok(())
		}

		#[weight = 0]
		pub fn set_manager_required(origin, group_id: T::GroupId, manager_required: bool) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;

			<Self as Group<_,_,_>>::set_manager_required(sender, group_id, manager_required)
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
		pub fn force_set_manager(origin, group_id: T::GroupId, new_manager: T::AccountId) -> dispatch::DispatchResult {
			let _ = ensure_root(origin)?;

			let mut tree = <Groups<T>>::get(group_id)
				.ok_or(Error::<T>::GroupDoesntExist)
				.unwrap();
			tree.manager = new_manager;
			Ok(())
		}

		#[weight = 0]
		pub fn add_members(origin, group_id: T::GroupId, members: Vec<Data>) -> dispatch::DispatchResult {
			let sender = ensure_signed(origin)?;
			<Self as Group<_,_,_>>::add_members(sender, group_id, members)
		}

		/// Verification stub for testing, these verification functions should
		/// not need to be used directly as extrinsics. Rather, higher-order
		/// modules should use the module functions to verify and execute further
		/// logic.
		#[weight = 0]
		pub fn verify(origin, group_id: T::GroupId, leaf: Data, path: Vec<(bool, Data)>) -> dispatch::DispatchResult {
			let _sender = ensure_signed(origin)?;
			<Self as Group<_,_,_>>::verify(group_id, leaf, path)
		}

		fn on_finalize(_n: T::BlockNumber) {
			// update highest block in cache
			if HighestCachedBlock::<T>::get() < _n {
				HighestCachedBlock::<T>::set(_n);
			}

			// initialise lowest block in cache if not already
			if LowestCachedBlock::<T>::get() < One::one() {
				LowestCachedBlock::<T>::set(_n);
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
}

impl<T: Config> Group<T::AccountId, T::BlockNumber, T::GroupId> for Module<T> {
	fn create_group(
		sender: T::AccountId,
		is_manager_required: bool,
		depth: u8,
	) -> Result<T::GroupId, dispatch::DispatchError> {
		ensure!(
			depth <= T::MaxTreeDepth::get() && depth > 0,
			Error::<T>::InvalidTreeDepth
		);

		let group_id = Self::next_group_id();
		NextGroupId::<T>::mutate(|id| *id += One::one());

		let mtree = GroupTree::<T>::new(sender, is_manager_required, depth);
		<Groups<T>>::insert(group_id, mtree);
		Ok(group_id)
	}

	fn set_manager_required(
		sender: T::AccountId,
		id: T::GroupId,
		manager_required: bool,
	) -> Result<(), dispatch::DispatchError> {
		let mut tree = <Groups<T>>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		// Changing manager required should always require an extrinsic from the
		// manager even if the group doesn't explicitly require managers for
		// other calls.
		ensure!(sender == tree.manager, Error::<T>::ManagerIsRequired);
		tree.manager_required = manager_required;
		Ok(())
	}

	fn add_members(sender: T::AccountId, id: T::GroupId, members: Vec<Data>) -> Result<(), dispatch::DispatchError> {
		let mut tree = <Groups<T>>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(
			Self::is_manager_required(sender.clone(), &tree),
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
		Groups::<T>::insert(id, tree);

		// Raising the New Member event for the client to build a tree locally
		Self::deposit_event(RawEvent::NewMember(id, sender, members));
		Ok(())
	}

	fn add_nullifier(
		sender: T::AccountId,
		id: T::GroupId,
		nullifier_hash: Data,
	) -> Result<(), dispatch::DispatchError> {
		let tree = <Groups<T>>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		// Check if the tree requires extrinsics to be called from a manager
		ensure!(
			Self::is_manager_required(sender.clone(), &tree),
			Error::<T>::ManagerIsRequired
		);
		UsedNullifiers::<T>::insert((id, nullifier_hash), true);
		Ok(())
	}

	fn has_used_nullifier(id: T::GroupId, nullifier: Data) -> Result<(), dispatch::DispatchError> {
		let _ = <Groups<T>>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();

		ensure!(
			!UsedNullifiers::<T>::contains_key((id, nullifier)),
			Error::<T>::AlreadyUsedNullifier
		);
		Ok(())
	}

	fn verify(id: T::GroupId, leaf: Data, path: Vec<(bool, Data)>) -> Result<(), dispatch::DispatchError> {
		let tree = <Groups<T>>::get(id).ok_or(Error::<T>::GroupDoesntExist).unwrap();

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

	fn verify_zk_membership_proof(
		group_id: T::GroupId,
		cached_block: T::BlockNumber,
		cached_root: Data,
		leaf_com: Commitment,
		path: Vec<(Commitment, Commitment)>,
		r_com: Commitment,
		nullifier_com: Commitment,
		nullifier_hash: Data,
		proof_bytes: Vec<u8>,
	) -> Result<(), dispatch::DispatchError> {
		let tree = <Groups<T>>::get(group_id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		ensure!(tree.edge_nodes.len() == path.len(), Error::<T>::InvalidPathLength);
		// Ensure that root being checked against is in the cache
		let old_roots = Self::cached_roots(cached_block, group_id);
		ensure!(
			old_roots.iter().any(|r| *r == cached_root),
			Error::<T>::InvalidMerkleRoot
		);
		// TODO: Initialise these generators with the pallet
		let pc_gens = PedersenGens::default();
		// TODO: should be able to pass number of generators
		// TODO: Initialise these generators with the pallet
		let bp_gens = BulletproofGens::new(4096, 1);
		<Self as Group<_, _, _>>::verify_zk(
			pc_gens,
			bp_gens,
			tree.root_hash,
			leaf_com,
			path,
			r_com,
			nullifier_com,
			nullifier_hash,
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
		nullifier_com: Commitment,
		nullifier_hash: Data,
		proof_bytes: Vec<u8>,
	) -> Result<(), dispatch::DispatchError> {
		let h = default_hasher();
		let mut verifier_transcript = Transcript::new(b"zk_membership_proof");
		let mut verifier = Verifier::new(&mut verifier_transcript);

		let var_leaf = verifier.commit(leaf_com.0);
		let var_r = verifier.commit(r_com.0);
		let var_nullifier = verifier.commit(nullifier_com.0);
		let leaf_lc = Data::constrain_verifier(&mut verifier, &pc_gens, var_r.into(), var_nullifier.into(), &h);
		// Commited leaf value should be the same as calculated
		verifier.constrain(leaf_lc - var_leaf);
		// committed nullifier into a hash should match hash of nullifier
		let nullifier_hash_lc =
			Data::constrain_verifier(&mut verifier, &pc_gens, var_nullifier.into(), var_nullifier.into(), &h);
		verifier.constrain(nullifier_hash_lc - LinearCombination::from(nullifier_hash.0));

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
		ensure!(res.is_ok(), Error::<T>::ZkVericationFailed);
		Ok(())
	}
}

impl<T: Config> Module<T> {
	pub fn get_cache(group_id: T::GroupId, block_number: T::BlockNumber) -> Vec<Data> {
		Self::cached_roots(block_number, group_id)
	}

	pub fn get_merkle_root(group_id: T::GroupId) -> Result<Data, dispatch::DispatchError> {
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

	pub fn get_group(group_id: T::GroupId) -> Result<GroupTree<T>, dispatch::DispatchError> {
		let tree = <Groups<T>>::get(group_id).ok_or(Error::<T>::GroupDoesntExist).unwrap();
		Ok(tree)
	}

	pub fn is_manager_required(sender: T::AccountId, tree: &GroupTree<T>) -> bool {
		if tree.manager_required {
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
}
