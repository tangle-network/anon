//! All the traits exposed to be used in other custom pallets

use crate::utils::keys::{Commitment, ScalarData};
use bulletproofs::PedersenGens;
pub use frame_support::dispatch;
use sp_std::vec::Vec;

/// Group trait definition to be used in other pallets
pub trait Group<AccountId, BlockNumber, GroupId> {
	/// Check if nullifier is already used, in which case throws an error
	fn has_used_nullifier(id: GroupId, nullifier: ScalarData) -> Result<(), dispatch::DispatchError>;
	/// Sets stopped flag in storage. This flag doesn't do much by itself, it is
	/// up to higher level pallet to find the use for it
	/// Can only be called by the manager, regardless if the manager is required
	fn set_stopped(sender: AccountId, group_id: GroupId, stopped: bool) -> Result<(), dispatch::DispatchError>;
	/// Sets whether the manager is required for guarded calls.
	/// Can only be called by the current manager
	fn set_manager_required(
		sender: AccountId,
		id: GroupId,
		is_manager_required: bool,
	) -> Result<(), dispatch::DispatchError>;
	/// Sets manager account id
	/// Can only be called by the current manager
	fn set_manager(sender: AccountId, id: GroupId, new_manager: AccountId) -> Result<(), dispatch::DispatchError>;
	/// Creates a new group tree, including a manager for that tree
	fn create_group(
		sender: AccountId,
		is_manager_required: bool,
		depth: u8,
	) -> Result<GroupId, dispatch::DispatchError>;
	/// Adds members/leaves to the tree
	fn add_members(sender: AccountId, id: GroupId, members: Vec<ScalarData>) -> Result<(), dispatch::DispatchError>;
	/// Adds a nullifier to the storage
	/// Can only be called by the manager, if the manager is required
	fn add_nullifier(sender: AccountId, id: GroupId, nullifier: ScalarData) -> Result<(), dispatch::DispatchError>;
	/// Verify membership proof
	fn verify(id: GroupId, leaf: ScalarData, path: Vec<(bool, ScalarData)>) -> Result<(), dispatch::DispatchError>;
	/// Verify zero-knowladge membership proof
	fn verify_zk_membership_proof(
		group_id: GroupId,
		cached_block: BlockNumber,
		cached_root: ScalarData,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
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
	) -> Result<(), dispatch::DispatchError>;
}
