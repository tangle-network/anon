use crate::merkle::keys::{Commitment, Data};
use bulletproofs::{BulletproofGens, PedersenGens};
pub use frame_support::dispatch;
use sp_std::vec::Vec;

pub trait Group<AccountId, BlockNumber, GroupId> {
	fn has_used_nullifier(id: GroupId, nullifier: Data) -> Result<(), dispatch::DispatchError>;
	fn set_manager_required(
		sender: AccountId,
		id: GroupId,
		is_manager_required: bool,
	) -> Result<(), dispatch::DispatchError>;
	fn create_group(
		sender: AccountId,
		is_manager_required: bool,
		depth: u8,
	) -> Result<GroupId, dispatch::DispatchError>;
	fn add_members(
		sender: AccountId,
		id: GroupId,
		members: Vec<Data>,
	) -> Result<(), dispatch::DispatchError>;
	fn add_nullifier(
		sender: AccountId,
		id: GroupId,
		nullifier: Data,
	) -> Result<(), dispatch::DispatchError>;
	fn verify(
		id: GroupId,
		leaf: Data,
		path: Vec<(bool, Data)>,
	) -> Result<(), dispatch::DispatchError>;
	fn verify_zk_membership_proof(
		group_id: GroupId,
		cached_block: BlockNumber,
		cached_root: Data,
		leaf_com: Commitment,
		path: Vec<(Commitment, Commitment)>,
		r_com: Commitment,
		nullifier_com: Commitment,
		nullifier_hash: Data,
		proof_bytes: Vec<u8>,
	) -> Result<(), dispatch::DispatchError>;
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
	) -> Result<(), dispatch::DispatchError>;
}
