use crate::utils::keys::{Commitment, ScalarData};
use bulletproofs::PedersenGens;
pub use frame_support::dispatch;
use sp_std::vec::Vec;

pub trait Group<AccountId, BlockNumber, GroupId> {
	fn has_used_nullifier(id: GroupId, nullifier: ScalarData) -> Result<(), dispatch::DispatchError>;
	fn set_stopped(sender: AccountId, group_id: GroupId, stopped: bool) -> Result<(), dispatch::DispatchError>;
	fn set_manager_required(
		sender: AccountId,
		id: GroupId,
		is_manager_required: bool,
	) -> Result<(), dispatch::DispatchError>;
	fn set_manager(sender: AccountId, id: GroupId, new_manager: AccountId) -> Result<(), dispatch::DispatchError>;
	fn create_group(
		sender: AccountId,
		is_manager_required: bool,
		depth: u8,
	) -> Result<GroupId, dispatch::DispatchError>;
	fn add_members(sender: AccountId, id: GroupId, members: Vec<ScalarData>) -> Result<(), dispatch::DispatchError>;
	fn add_nullifier(sender: AccountId, id: GroupId, nullifier: ScalarData) -> Result<(), dispatch::DispatchError>;
	fn verify(id: GroupId, leaf: ScalarData, path: Vec<(bool, ScalarData)>) -> Result<(), dispatch::DispatchError>;
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
