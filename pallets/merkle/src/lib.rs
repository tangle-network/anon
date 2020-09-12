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

use codec::{Encode, Decode};
use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, ensure};
use frame_system::{ensure_signed};
use sp_std::prelude::*;
use sp_runtime::traits::{Zero};

pub type MerkleLeaf = crate::merkle::keys::PublicKey;
pub type MerkleNullifier = crate::merkle::keys::PrivateKey;

/// The pallet's configuration trait.
pub trait Trait: balances::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

type GroupId = u32;

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Encode, Decode, PartialEq)]
pub struct GroupTree<T: Trait> {
	pub fee: T::Balance,
	pub depth: u32,
	pub leaf_count: u32,
	pub members: Vec<MerkleLeaf>,
}

impl<T: Trait> GroupTree<T> {
	pub fn new(fee: T::Balance, depth: u32, leaf_count: u32, members: Vec<MerkleLeaf>) -> Self {
		Self {
			fee: fee,
			depth: depth,
			leaf_count: leaf_count,
			members: members
		}
	}
}

const DEFAULT_TREE_DEPTH: u32 = 31;
// TODO: Better estimates/decisions
const MAX_DEPTH: u32 = 31;
const ZERO: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as MerkleGroups {
		pub Groups get(fn groups): map hasher(blake2_128_concat) GroupId => Option<GroupTree<T>>;
		pub NumberOfTrees get(fn number_of_trees): GroupId;
		pub MerkleTreeLevels get(fn merkle_tree_level): map hasher(blake2_128_concat) (GroupId, u32) => Option<Vec<MerkleLeaf>>;
		pub UsedNullifiers get(fn used_nullifiers): map hasher(blake2_128_concat) MerkleNullifier => bool;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		NewMember(u32, AccountId, MerkleLeaf),
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
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 0]
		pub fn add_member(origin, group_id: u32, pub_key: MerkleLeaf) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let who = ensure_signed(origin)?;
			let mut group = <Groups<T>>::get(group_id).ok_or("Group doesn't exist").unwrap();
			// add new member
			group.members.push(pub_key.clone());
			<Groups<T>>::insert(group_id, group);
			Self::add_leaf(group_id, pub_key.clone());

			// Here we are raising the Something event
			Self::deposit_event(RawEvent::NewMember(group_id, who, pub_key));
			Ok(())
		}

		#[weight = 0]
		pub fn create_group(origin, _fee: Option<T::Balance>, _depth: Option<u32>, _leaves: Option<Vec<MerkleLeaf>>) -> dispatch::DispatchResult {
			let _sender = ensure_signed(origin)?;

			let fee = match _fee {
				Some(f) => f,
				None => Zero::zero(),
			};

			let depth = match _depth {
				Some(d) => d,
				None => DEFAULT_TREE_DEPTH,
			};
			ensure!(depth <= MAX_DEPTH, "Fee is too large");

			let ctr = Self::number_of_trees();
			let empty: Vec<MerkleLeaf> = vec![];
			for i in 0..depth {
				println!("{:?}", i);
				<MerkleTreeLevels>::insert((ctr, i), empty.clone());
			}

			let mtree = GroupTree::<T>::new(fee, depth, 0, vec![]);
			<Groups<T>>::insert(ctr, mtree);
			<NumberOfTrees>::put(ctr + 1);

			if let Some(leaves) = _leaves {
				for i in 0..leaves.len() {
					Self::add_leaf(ctr, leaves[i].clone());
				}
			}

			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
	
	pub fn get_members(group_id: u32) -> Option<Vec<MerkleLeaf>> {
		match <Groups<T>>::get(group_id) {
			Some(g) => Some(g.members),
			None => None,
		}
	}

	pub fn hash_leaves(left: MerkleLeaf, right: MerkleLeaf) -> MerkleLeaf {
		return MerkleLeaf::from_ristretto(left.0.decompress().unwrap() + right.0.decompress().unwrap());
	}

	// TODO: Implement pre-computed hash values for Sparse Merkle Tree
	pub fn get_unique_node(leaf: MerkleLeaf, _index: usize) -> MerkleLeaf {
		if leaf != MerkleLeaf::new(ZERO) {
			return leaf;
		} else {
			return MerkleLeaf::new(ZERO);
		}
	}

	pub fn add_leaf(group_id: GroupId, leaf: MerkleLeaf) {
		let mut tree = <Groups<T>>::get(group_id).ok_or("Group doesn't exist").unwrap();
		// Add element
		let leaf_index = tree.leaf_count;
		tree.leaf_count += 1;
		if let Some(mut mt_level) = <MerkleTreeLevels>::get((group_id, tree.depth - 1)) {
			mt_level.push(leaf);
			<MerkleTreeLevels>::insert((group_id, tree.depth - 1), mt_level);
		}

		let mut curr_index = leaf_index as usize;
		// Update the tree
		for i in 0..(tree.depth - 1) {
			let left: MerkleLeaf;
			let right: MerkleLeaf;
			let next_index = curr_index / 2;
			let level = <MerkleTreeLevels>::get((group_id, tree.depth - i - 1)).unwrap();
			if curr_index % 2 == 0 {
				left = level.clone()[curr_index].clone();
				// Get leaf if exists or use precomputed hash
				right = {
					let mut temp = MerkleLeaf::new(ZERO);
					if level.len() >= curr_index + 2 {
						temp = level.clone()[curr_index + 1].clone()
					}
					// returns precompute for an index or the node
					Self::get_unique_node(temp, i as usize)
				};
			} else {
				left = Self::get_unique_node(level.clone()[curr_index - 1].clone(), i as usize);
				right = level.clone()[curr_index].clone();
			}

			if let Some(mut next_level) = <MerkleTreeLevels>::get((group_id, tree.depth - i - 2)) {
				// println!("Next level {:?}", tree.depth - i - 2);
				let new_node = Self::hash_leaves(left, right);
				// println!("{:?}", new_node);
				if next_level.len() >= next_index + 1 {
					next_level[next_index] = new_node;
				} else {
					next_level.push(new_node);
				}
				// println!("{:?}", next_level);

				<MerkleTreeLevels>::insert((group_id, tree.depth - i - 2), next_level);
			}

			curr_index = next_index;
		}
	}
}
