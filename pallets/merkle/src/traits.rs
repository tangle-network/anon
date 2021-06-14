//! All the traits exposed to be used in other custom pallets
use crate::{
	utils::keys::{Commitment, ScalarData},
	Config,
};
use bulletproofs::PedersenGens;
use bulletproofs_gadgets::poseidon::builder::Poseidon;
pub use frame_support::dispatch;
use sp_std::vec::Vec;

/// Tree trait definition to be used in other pallets
pub trait Tree<T: Config> {
	/// Check if nullifier is already used, in which case return an error
	fn has_used_nullifier(id: T::TreeId, nullifier: ScalarData) -> Result<(), dispatch::DispatchError>;
	/// Sets stopped flag in storage. This flag doesn't do much by itself, it is
	/// up to higher-level pallet to find the use for it
	/// Can only be called by the manager, regardless if the manager is required
	fn set_stopped(sender: T::AccountId, tree_id: T::TreeId, stopped: bool) -> Result<(), dispatch::DispatchError>;
	/// Sets whether the manager is required for guarded calls.
	/// Can only be called by the current manager
	fn set_manager_required(
		sender: T::AccountId,
		id: T::TreeId,
		is_manager_required: bool,
	) -> Result<(), dispatch::DispatchError>;
	/// Sets manager account id
	/// Can only be called by the current manager
	fn set_manager(
		sender: T::AccountId,
		id: T::TreeId,
		new_manager: T::AccountId,
	) -> Result<(), dispatch::DispatchError>;
	/// Creates a new Tree tree, including a manager for that tree
	fn create_tree(
		sender: T::AccountId,
		is_manager_required: bool,
		depth: u8,
	) -> Result<T::TreeId, dispatch::DispatchError>;
	/// Initializes the tree with the root hash and edge nodes, must happen
	/// after keys are set
	fn initialize_tree(tree_id: T::TreeId, key_id: T::KeyId) -> Result<(), dispatch::DispatchError>;
	/// Checks if a tree is initialized
	fn is_initialized(tree_id: T::TreeId) -> Result<bool, dispatch::DispatchError>;
	/// Adds members/leaves to the tree
	fn add_members(
		sender: T::AccountId,
		id: T::TreeId,
		members: Vec<ScalarData>,
	) -> Result<(), dispatch::DispatchError>;
	/// Adds a nullifier to the storage
	/// Can only be called by the manager if the manager is required
	fn add_nullifier(sender: T::AccountId, id: T::TreeId, nullifier: ScalarData)
		-> Result<(), dispatch::DispatchError>;
	/// Add verifying key to storage and increment the next available key id
	fn add_verifying_key(key: Vec<u8>) -> Result<T::KeyId, dispatch::DispatchError>;
	/// Set verifying key in storage
	fn set_verifying_key(key_id: T::KeyId, key: Vec<u8>) -> Result<(), dispatch::DispatchError>;
	/// Set verifying key for tree
	fn set_verifying_key_for_tree(key_id: T::KeyId, tree_id: T::TreeId) -> Result<(), dispatch::DispatchError>;
	/// Verify membership proof
	fn verify(id: T::TreeId, leaf: ScalarData, path: Vec<(bool, ScalarData)>) -> Result<(), dispatch::DispatchError>;
	/// Verify zero-knowladge membership proof
	fn verify_zk_membership_proof(
		tree_id: T::TreeId,
		cached_block: T::BlockNumber,
		cached_root: ScalarData,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
		recipient: ScalarData,
		relayer: ScalarData,
	) -> Result<(), dispatch::DispatchError>;
	fn verify_zk(
		pc_gens: PedersenGens,
		m_root: ScalarData,
		depth: u8,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
		recipient: ScalarData,
		relayer: ScalarData,
		hash_params: &Poseidon,
	) -> Result<(), dispatch::DispatchError>;
}
