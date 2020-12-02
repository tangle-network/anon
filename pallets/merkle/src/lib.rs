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
use frame_support::{decl_error, decl_event, decl_module, decl_storage, dispatch, ensure};
use frame_system::ensure_signed;
use merkle::hasher::Hasher;
use merkle::keys::{Commitment, Data};
use merkle::mimc::Mimc;
use merkle::poseidon::Poseidon;
use merlin::Transcript;
use rand_core::OsRng;
use sp_runtime::traits::Zero;
use sp_std::prelude::*;

/// The pallet's configuration trait.
pub trait Trait: balances::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

type GroupId = u32;
const MAX_DEPTH: u32 = 32;

// TODO find better way to have default hasher without saving it inside storage
fn default_hasher() -> impl Hasher {
	Poseidon::new(4)
	// Mimc::new(70)
}

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
			max_leaves: u32::MAX >> (MAX_DEPTH - depth),
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
		NewMember(u32, AccountId, Vec<Data>),
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
		pub fn add_members(origin, group_id: u32, data_points: Vec<Data>) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let who = ensure_signed(origin)?;

			let mut tree = <Groups<T>>::get(group_id)
				.ok_or("Group doesn't exist")
				.unwrap();
			let num_points = data_points.len() as u32;
			ensure!(
				tree.leaf_count + num_points <= tree.max_leaves,
				"Exceeded maximum tree depth."
			);

			let h = default_hasher();
			for data in &data_points {
				Self::add_leaf(&mut tree, *data, &h);
			}
			<Groups<T>>::insert(group_id, tree);

			// Raising the New Member event for the client to build a tree locally
			Self::deposit_event(RawEvent::NewMember(group_id, who, data_points));
			Ok(())
		}

		#[weight = 0]
		pub fn verify(origin, group_id: u32, leaf: Data, path: Vec<(bool, Data)>) -> dispatch::DispatchResult {
			let tree = <Groups<T>>::get(group_id)
				.ok_or("Invalid group id.")
				.unwrap();
			ensure!(tree.edge_nodes.len() == path.len(), "Invalid path length.");
			let h = default_hasher();
			let mut hash = leaf;
			for (is_right, node) in path {
				hash = match is_right {
					true => Data::hash(hash, node, &h),
					false => Data::hash(node, hash, &h),
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
			path: Vec<(Commitment, Commitment)>,
			s_com: Commitment,
			nullifier: Data,
			proof_bytes: Vec<u8>
		) -> dispatch::DispatchResult {
			// Ensure that nullifier is not used
			ensure!(!UsedNullifiers::get(nullifier), "Nullifier already used.");
			let tree = <Groups<T>>::get(group_id)
				.ok_or("Invalid group id.")
				.unwrap();
			ensure!(tree.edge_nodes.len() == path.len(), "Invalid path length.");

			let pc_gens = PedersenGens::default();
			// TODO: should be able to pass number of generators
			let bp_gens = BulletproofGens::new(4096, 1);
			let h = default_hasher();

			let mut verifier_transcript = Transcript::new(b"zk_membership_proof");
			let mut verifier = Verifier::new(&mut verifier_transcript);

			let var_leaf = verifier.commit(leaf_com.0);
			let var_s = verifier.commit(s_com.0);
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
			verifier.constrain(hash - tree.root_hash.0);

			let proof = R1CSProof::from_bytes(&proof_bytes);
			ensure!(proof.is_ok(), "Invalid proof bytes.");
			let proof = proof.unwrap();

			let mut rng = OsRng {};
			// Final verification
			let res = verifier.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut rng);
			ensure!(res.is_ok(), "Invalid proof of membership or leaf creation.");

			// Set nullifier as used
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

impl<T: Trait> Module<T> {
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
