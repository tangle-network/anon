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

use codec::{Decode, Encode};
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use sp_runtime::traits::Zero;
use sp_std::prelude::*;

pub type MerkleLeaf = crate::merkle::keys::PublicKey;
pub type MerkleNullifier = crate::merkle::keys::PrivateKey;

/// The pallet's configuration trait.
pub trait Trait: balances::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

type GroupId = u32;
const MAX_DEPTH: u32 = 31;
const ZERO: [u8; 32] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Encode, Decode, PartialEq)]
pub struct GroupTree<T: Trait> {
	pub fee: T::Balance,
	pub leaf_count: u32,
	pub max_leaves: u32,
	pub root_hash: MerkleLeaf,
	pub edge_nodes: Vec<MerkleLeaf>,
}

impl<T: Trait> GroupTree<T> {
	pub fn new(fee: T::Balance, depth: u32) -> Self {
		Self {
			fee,
			root_hash: MerkleLeaf::new(&ZERO),
			leaf_count: 0,
			max_leaves: 1 << depth - 1,
			edge_nodes: vec![MerkleLeaf::new(&ZERO); (depth - 1) as usize],
		}
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as MerkleGroups {
		pub Groups get(fn groups): map hasher(blake2_128_concat) GroupId => Option<GroupTree<T>>;
		pub UsedNullifiers get(fn used_nullifiers): map hasher(blake2_128_concat) MerkleNullifier => bool;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T>
	where
		AccountId = <T as frame_system::Trait>::AccountId,
	{
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
			let mut tree = <Groups<T>>::get(group_id).ok_or("Group doesn't exist").unwrap();
			ensure!(tree.leaf_count < tree.max_leaves, "Exceeded maximum tree depth.");

			let mut edge_index = tree.leaf_count;
			let mut pair_hash = pub_key;
			// Update the tree
			for i in 0..tree.edge_nodes.len() {
				if edge_index % 2 == 0 {
					tree.edge_nodes[i] = pair_hash;
				}

				let hash = tree.edge_nodes[i];
				pair_hash = Self::hash_leaves(hash, pair_hash);

				edge_index /= 2;
			}

			tree.leaf_count += 1;
			tree.root_hash = pair_hash;

			<Groups<T>>::insert(group_id, tree);

			// Raising the New Member event for the client to build a tree locally
			Self::deposit_event(RawEvent::NewMember(group_id, who, pub_key));
			Ok(())
		}

		#[weight = 0]
		pub fn create_group(origin, group_id: GroupId, _fee: Option<T::Balance>, _depth: Option<u32>) -> dispatch::DispatchResult {
			let _sender = ensure_signed(origin)?;
			ensure!(!<Groups<T>>::contains_key(group_id), "Group already exists.");

			let fee = match _fee {
				Some(f) => f,
				None => Zero::zero(),
			};

			let depth = match _depth {
				Some(d) => d,
				None => MAX_DEPTH
			};

			let mtree = GroupTree::<T>::new(fee, depth);
			<Groups<T>>::insert(group_id, mtree);

			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn hash_leaves(left: MerkleLeaf, right: MerkleLeaf) -> MerkleLeaf {
		return MerkleLeaf::from_ristretto(
			left.0.decompress().unwrap() + right.0.decompress().unwrap(),
		);
	}
}
