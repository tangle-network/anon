//! All the traits exposed to be used in other custom pallets

use crate::utils::{
	hasher::{Backend, HashFunction},
	keys::ScalarBytes,
};
pub use frame_support::dispatch;
use sp_std::vec::Vec;

/// Tree trait definition to be used in other pallets
pub trait Tree<AccountId, BlockNumber, TreeId> {
	/// Check if nullifier is already used, in which case return an error
	fn has_used_nullifier(id: TreeId, nullifier: ScalarBytes) -> Result<(), dispatch::DispatchError>;
	/// Sets stopped flag in storage. This flag doesn't do much by itself, it is
	/// up to higher-level pallet to find the use for it
	/// Can only be called by the manager, regardless if the manager is required
	fn set_stopped(sender: AccountId, tree_id: TreeId, stopped: bool) -> Result<(), dispatch::DispatchError>;
	/// Sets whether the manager is required for guarded calls.
	/// Can only be called by the current manager
	fn set_manager_required(
		sender: AccountId,
		id: TreeId,
		is_manager_required: bool,
	) -> Result<(), dispatch::DispatchError>;
	/// Sets manager account id
	/// Can only be called by the current manager
	fn set_manager(sender: AccountId, id: TreeId, new_manager: AccountId) -> Result<(), dispatch::DispatchError>;
	/// Creates a new Tree tree, including a manager for that tree
	fn create_tree(
		sender: AccountId,
		is_manager_required: bool,
		hasher: HashFunction,
		backend: Backend,
		depth: u8,
	) -> Result<TreeId, dispatch::DispatchError>;
	/// Adds members/leaves to the tree
	fn add_members(sender: AccountId, id: TreeId, members: Vec<ScalarBytes>) -> Result<(), dispatch::DispatchError>;
	/// Adds a nullifier to the storage
	/// Can only be called by the manager if the manager is required
	fn add_nullifier(sender: AccountId, id: TreeId, nullifier: ScalarBytes) -> Result<(), dispatch::DispatchError>;
	/// Verify membership proof
	fn verify(id: TreeId, leaf: ScalarBytes, path: Vec<(bool, ScalarBytes)>) -> Result<(), dispatch::DispatchError>;
	/// Verify zero-knowladge membership proof
	fn verify_zk(
		tree_id: TreeId,
		cached_block: BlockNumber,
		cached_root: ScalarBytes,
		comms: Vec<ScalarBytes>,
		nullifier_hash: ScalarBytes,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<ScalarBytes>,
		proof_commitments: Vec<ScalarBytes>,
		recipient: ScalarBytes,
		relayer: ScalarBytes,
	) -> Result<(), dispatch::DispatchError>;
}
