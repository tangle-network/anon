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

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use codec::{Decode, Encode};
use curve25519_dalek::ristretto::CompressedRistretto;
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use merkle::keys::{Commitment, Data};
use merlin::Transcript;
use sp_runtime::traits::Zero;
use sp_std::prelude::*;

/// The pallet's configuration trait.
pub trait Trait: balances::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

type GroupId = u32;
const MAX_DEPTH: u32 = 32;
const ZERO: [u8; 32] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Encode, Decode, PartialEq)]
pub struct GroupTree<T: Trait> {
	pub fee: T::Balance,
	pub leaf_count: u32,
	pub max_leaves: u32,
	pub root_hash: Data,
	pub edge_nodes: Vec<Data>,
}

impl<T: Trait> GroupTree<T> {
	pub fn new(fee: T::Balance, depth: u32) -> Self {
		Self {
			fee,
			root_hash: Data::zero(),
			leaf_count: 0,
			max_leaves: u32::MAX >> (32 - depth),
			edge_nodes: vec![Data::zero(); depth as usize],
		}
	}
}

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as MerkleGroups {
		pub Groups get(fn groups): map hasher(blake2_128_concat) GroupId => Option<GroupTree<T>>;
		pub UsedNullifiers get(fn used_nullifiers): map hasher(blake2_128_concat) Data => bool;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T>
	where
		AccountId = <T as frame_system::Trait>::AccountId,
	{
		NewMember(u32, AccountId, Data),
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
		pub fn add_member(origin, group_id: u32, data: Data) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let who = ensure_signed(origin)?;
			let mut tree = <Groups<T>>::get(group_id).ok_or("Group doesn't exist").unwrap();
			ensure!(tree.leaf_count < tree.max_leaves, "Exceeded maximum tree depth.");

			let mut edge_index = tree.leaf_count;
			let mut pair_hash = data;
			// Update the tree
			for i in 0..tree.edge_nodes.len() {
				if edge_index % 2 == 0 {
					tree.edge_nodes[i] = pair_hash;
				}

				let hash = tree.edge_nodes[i];
				pair_hash = Data::hash_mimc(hash, pair_hash);

				edge_index /= 2;
			}

			tree.leaf_count += 1;
			tree.root_hash = pair_hash;

			<Groups<T>>::insert(group_id, tree);

			// Raising the New Member event for the client to build a tree locally
			Self::deposit_event(RawEvent::NewMember(group_id, who, data));
			Ok(())
		}

		#[weight = 0]
		pub fn verify(origin, group_id: u32, leaf: Data, path: Vec<(bool, Data)>) -> dispatch::DispatchResult {
			let tree = <Groups<T>>::get(group_id)
				.ok_or("Invalid group id.")
				.unwrap();
			ensure!(tree.edge_nodes.len() == path.len(), "Invalid path length.");
			let mut hash = leaf;
			for (is_right, node) in path {
				hash = match is_right {
					true => Data::hash_mimc(hash, node),
					false => Data::hash_mimc(node, hash),
				}
			}

			ensure!(hash == tree.root_hash, "Invalid proof of membership.");
			Ok(())
		}

		#[weight = 0]
		pub fn verify_zk_membership_proof(
			origin,
			group_id: u32,
			leaf_com: Commitment,
			path: Vec<(bool, Commitment)>,
			s_com: Commitment,
			nullifier: Data,
			proof_bytes: Vec<u8>
		) -> dispatch::DispatchResult {
			ensure!(!UsedNullifiers::get(nullifier), "Nullifier already used.");
			let tree = <Groups<T>>::get(group_id)
				.ok_or("Invalid group id.")
				.unwrap();
			ensure!(tree.edge_nodes.len() == path.len(), "Invalid path length.");

			let pc_gens = PedersenGens::default();
			let bp_gens = BulletproofGens::new(2048, 1);

			let mut verifier_transcript = Transcript::new(b"zk_membership_proof");
			let mut verifier = Verifier::new(&mut verifier_transcript);

			let var_leaf = verifier.commit(leaf_com.0);

			let var_s = verifier.commit(s_com.0);
			let leaf_lc = Data::constrain_mimc(&mut verifier, var_s.into(), nullifier.0.into());
			verifier.constrain(leaf_lc - var_leaf);

			let mut hash: LinearCombination = var_leaf.into();
			for (is_right, node) in path {
				let var_node = verifier.commit(node.0);
				hash = match is_right {
					true => Data::constrain_mimc(&mut verifier, hash, var_node.into()),
					false => Data::constrain_mimc(&mut verifier, var_node.into(), hash),
				}
			}

			verifier.constrain(hash - tree.root_hash.0);

			let proof = R1CSProof::from_bytes(&proof_bytes);
			ensure!(proof.is_ok(), "Invalid proof bytes.");
			let proof = proof.unwrap();

			let res = verifier.verify(&proof, &pc_gens, &bp_gens);
			ensure!(res.is_ok(), "Invalid proof of membership or leaf creation.");

			UsedNullifiers::insert(nullifier, true);

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

			ensure!(depth <= MAX_DEPTH && depth > 0, "Invalid tree depth.");

			let mtree = GroupTree::<T>::new(fee, depth);
			<Groups<T>>::insert(group_id, mtree);

			Ok(())
		}
	}
}
