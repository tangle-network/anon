use crate::substrate_subxt::system::SystemEventsDecoder;
use codec::{Decode, Encode};
use pallet_merkle::merkle::keys::{Commitment, Data};
use std::marker::PhantomData;
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::System;
use substrate_subxt::{Call, Store};

type GroupId = u32;

#[module]
pub trait Merkle: Balances + System {}

#[derive(Clone, Encode, Decode)]
pub struct GroupTree<T: Merkle> {
	pub fee: T::Balance,
	pub leaf_count: u32,
	pub max_leaves: u32,
	pub root_hash: Data,
	pub edge_nodes: Vec<Data>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CreateGroupCall<T: Merkle> {
	group_id: GroupId,
	_fee: Option<T::Balance>,
	_depth: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct AddMembersCall<T: Merkle> {
	group_id: GroupId,
	data_points: Vec<Data>,
	pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct VerifyZkMembershipProofCall<T: Merkle> {
	group_id: GroupId,
	leaf_com: Commitment,
	path: Vec<(Commitment, Commitment)>,
	s_com: Commitment,
	nullifier: Data,
	proof_bytes: Vec<u8>,
	pub _runtime: PhantomData<T>,
}

#[derive(Encode, Clone, Debug, Hash, PartialEq, Eq, Ord, PartialOrd, Store)]
pub struct GroupsStore<T: Merkle> {
	#[store(returns = Option<GroupTree<T>>)]
	pub group_id: GroupId,
	pub _runtime: PhantomData<T>,
}

/// Transfer event.
#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct NewMemberEvent<T: Merkle> {
	pub group_id: GroupId,
	pub sender: T::AccountId,
	pub members: Vec<Data>,
}
