use crate::substrate_subxt::system::SystemEventsDecoder;
use codec::{Decode, Encode};
use frame_support::traits::Get;
use frame_support::Parameter;
use pallet_merkle::merkle::keys::{Commitment, Data};
use sp_runtime::traits::AtLeast32Bit;
use std::marker::PhantomData;
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::System;
use substrate_subxt::{Call, Store};

type GroupId = u32;
#[derive(Default, Eq, PartialEq, Encode, Decode)]
pub struct MaxTreeDepth;

impl Get<u8> for MaxTreeDepth {
	fn get() -> u8 {
		32
	}
}

#[derive(Default, Eq, PartialEq, Encode, Decode)]
pub struct CacheBlockLength;

impl Get<u32> for CacheBlockLength {
	fn get() -> u32 {
		100
	}
}

#[module]
pub trait Merkle: Balances + System {
	type Data: Encode + Decode + PartialEq + Eq + Default + Send + Sync + 'static;
	type GroupId: Parameter + AtLeast32Bit + Default + Copy + Send + 'static;
	/// The max depth of trees
	type MaxTreeDepth: Get<u8> + Default + Send + Encode + Decode + PartialEq + Eq + Sync + 'static;
	/// The amount of blocks to cache roots over
	type CacheBlockLength: Get<Self::BlockNumber>
		+ Default
		+ Send
		+ Encode
		+ Decode
		+ PartialEq
		+ Eq
		+ Sync
		+ 'static;
}

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
	r_is_mgr: bool,
	_depth: Option<u32>,
	pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct AddMembersCall<T: Merkle> {
	pub group_id: GroupId,
	pub data_points: Vec<Data>,
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

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct NewMemberEvent<T: Merkle> {
	pub group_id: GroupId,
	pub sender: T::AccountId,
	pub members: Data,
}
