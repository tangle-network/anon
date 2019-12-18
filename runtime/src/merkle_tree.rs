use sp_std::prelude::*;
use codec::{Decode, Encode};
use codec::alloc::string::{ToString};
use sp_runtime::RuntimeDebug;
use sp_runtime::traits::{Zero};
use frame_support::traits::{Currency, ReservableCurrency};
use frame_support::{decl_module, decl_storage, decl_event, dispatch::Result};
use system::ensure_signed;
use pairing::{Field, PrimeField};

const DEFAULT_TREE_DEPTH: u32 = 32;
const MAX_DEPTH: u32 = 32;

pub type NodeDataType = sp_std::vec::Vec<u8>;

#[derive(Encode, Decode, Clone, Eq, PartialEq, Ord, PartialOrd, RuntimeDebug)]
pub struct MTree<T: Trait> {
	pub root: NodeDataType,
	pub fee: T::Balance,
	pub depth: u32,
	pub leaf_count: u32
}

impl<T: Trait> MTree<T> {
	pub fn new(root: NodeDataType, fee: T::Balance, depth: u32) -> Self {
		MTree {
			root: root,
			fee: fee,
			depth: depth,
			leaf_count: 0
		}
	}
}

pub trait Trait: balances::Trait {
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
	/// The account balance.
	type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;
	/// The Prime field type
	type Field: Field + PrimeField + ToString;
}

decl_storage! {
	trait Store for Module<T: Trait> as SparseMerkleTree {
		pub NumberOfTrees get(number_of_trees): u32;
		pub MerkleTreeMetadata get(merkle_tree_metadata): map u32 => Option<MTree<T>>;
		pub MerkleTreeLevels get(merkle_tree_level): map (u32, u32) => Option<Vec<NodeDataType>>;
		pub UsedNullifiers get(used_nullifiers): map Vec<u8> => bool;
	}
}


decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;
		pub fn create_new_tree(origin, root: Option<NodeDataType>, fee: Option<T::Balance>, depth: Option<u32>, leaves: Option<Vec<NodeDataType>>) -> Result {
			let _sender = ensure_signed(origin)?;
			let should_update = match root { Some(_) => false, None => false };
			let root = match root { Some(r) => r, None => vec![] };
			let fee = match fee { Some(f) => f, None => Zero::zero() };
			let depth = match depth { Some(d) => d, None => DEFAULT_TREE_DEPTH };
			assert!(depth <= MAX_DEPTH, "Depth is too large");
			// Get counter of trees
			let ctr = Self::number_of_trees();
			// Insert tree metadata
			let mt = MTree::<T>::new(root, fee, depth);
			<MerkleTreeMetadata<T>>::insert(ctr, mt);
			// Increment counter
			<NumberOfTrees>::put(ctr + 1);
			// Initialize empty merkle tree levels
			for i in 0..depth {
				let empty_vec = Vec::new();
				<MerkleTreeLevels>::insert((ctr, i), empty_vec);
			}
			// Add leaves
			if let Some(leaves) = leaves {
				Self::add_batch_leaves(ctr, leaves);
				// TODO: Implement first round merkle root calculation
				//       if leaves are provided without a root hash
				if should_update {
					Self::update_first_root(ctr);
				}
			}

			Ok(())
		}

		pub fn add_leaf(origin, tree_id: u32, leaf: NodeDataType) -> Result {
			let _sender = ensure_signed(origin)?;
			Self::add_leaf_element(tree_id, leaf);
			Self::update_tree_root(tree_id);
			Ok(())
		}
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		SomethingStored(u32, AccountId),
	}
);

impl<T: Trait> Module<T> {
	pub fn update_first_root(_tree_id: u32) {
		return;
	}

	pub fn update_tree_root(tree_id: u32) {
		let tree = <MerkleTreeMetadata<T>>::get(tree_id).ok_or("Tree doesn't exist").unwrap();
		let mut curr_index = (tree.leaf_count - 1) as usize;
		for i in 0..tree.depth {
			let left: NodeDataType;
			let right: NodeDataType;
			let next_index = curr_index / 2;
			let level_key = (tree_id, i);
			let next_level_key = (tree_id, i + 1);
			let level = <MerkleTreeLevels>::get(level_key).unwrap();
			if curr_index % 2 == 0 {
				left = level[curr_index].clone();
				// Get leaf if exists or use precomputed hash
				right = {
					let mut temp = vec![];
					if level.len() >= curr_index + 2 {
						temp = level[curr_index + 1].clone()
					}
					// returns precompute for an index or the node
					Self::get_unique_node(temp, i as usize)
				};
			} else {
				left = Self::get_unique_node(level[curr_index - 1].clone(), i as usize);
				right = level[curr_index].clone();
			}

			let mut next_level = <MerkleTreeLevels>::get(next_level_key).unwrap();
			let new_node = Self::mimc(left, right, 2);
			if next_level.len() >= next_index + 1 {
			    next_level[next_index] = new_node;
			} else {
			    next_level.push(new_node);
			}

			<MerkleTreeLevels>::insert(next_level_key, next_level);
			// Re-assign current node index for next level in tree
			curr_index = next_index;
		}
	}

	pub fn add_batch_leaves(tree_id: u32, leaf_elements: Vec<NodeDataType>) {
		let mut tree = <MerkleTreeMetadata<T>>::get(tree_id).ok_or("Tree doesn't exist").unwrap();
		let level_key = (tree_id, 0);
		if let Some(mut leaf_level) = <MerkleTreeLevels>::get(level_key) {
			for leaf in leaf_elements {
				leaf_level.push(leaf);
				tree.leaf_count += 1;
			}

			<MerkleTreeLevels>::insert(level_key, leaf_level);
			<MerkleTreeMetadata<T>>::insert(tree_id, tree);
		}
	}

	pub fn add_leaf_element(tree_id: u32, leaf: NodeDataType) {
		let mut tree = <MerkleTreeMetadata<T>>::get(tree_id).ok_or("Tree doesn't exist").unwrap();
		let level_key = (tree_id, 0);
		if let Some(mut leaf_level) = <MerkleTreeLevels>::get(level_key) {
			leaf_level.push(leaf);
			tree.leaf_count += 1;
			<MerkleTreeLevels>::insert(level_key, leaf_level);
			<MerkleTreeMetadata<T>>::insert(tree_id, tree);
		}
	}

	pub fn get_unique_node(leaf: NodeDataType, _index: usize) -> NodeDataType {
		if leaf.len() > 0 {
			return leaf;
		} else {
			return vec![];
		}
	}

	fn mimc(left: NodeDataType, right: NodeDataType, rounds: u32) -> NodeDataType {
		let k = T::Field::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();
		let mut l = T::Field::from_str(&left.to_string()).unwrap();
		let mut r = T::Field::from_str(&right.to_string()).unwrap();

		for i in 0..rounds {
			let (temp_l, temp_r) = Self::mimc_round(l, r, k, i);
			l = temp_l;
			r = temp_r;
		}
		
		return r.into();
	}

	fn mimc_round(left: T::Field, _right: T::Field, k: T::Field, _round: u32) -> (T::Field, T::Field) {
		let mut inner_temp = left;
		inner_temp.add_assign(&k);
		// inner_temp.add_assign(round_constants[round])
		let mut right = inner_temp;
		for _ in 0..2 {
			right.mul_assign(&inner_temp);
		}
		right.add_assign(&left);
		return (right, left);
	}
}
