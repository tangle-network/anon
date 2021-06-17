use super::*;
use crate as pallet_merkle;
use frame_support::{construct_runtime, parameter_types, weights::Weight};
use frame_system as system;
use pallet_merkle::weights::Weights;
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
	Perbill,
};
use system::mocking::{MockBlock, MockUncheckedExtrinsic};
pub(crate) type Balance = u64;

// Configure a mock runtime to test the pallet.
type UncheckedExtrinsic = MockUncheckedExtrinsic<Test>;
type Block = MockBlock<Test>;

construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: system::{Pallet, Call, Config, Storage, Event<T>},
		Balances: balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		Randomness: pallet_randomness_collective_flip::{Pallet, Call, Storage},
		MerkleTrees: pallet_merkle::{Pallet, Call, Storage, Event<T>},
	}
);

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}

impl frame_system::Config for Test {
	type AccountData = balances::AccountData<u64>;
	type AccountId = u64;
	type BaseCallFilter = ();
	type BlockHashCount = BlockHashCount;
	type BlockLength = ();
	type BlockNumber = u64;
	type BlockWeights = ();
	type Call = Call;
	type DbWeight = ();
	type Event = Event;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type Header = Header;
	type Index = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type OnKilledAccount = ();
	type OnNewAccount = ();
	type OnSetCode = ();
	type Origin = Origin;
	type PalletInfo = PalletInfo;
	type SS58Prefix = Prefix;
	type SystemWeightInfo = ();
	type Version = ();
}

parameter_types! {
	pub const Prefix: u8 = 100;
	pub const ExistentialDeposit: Balance = 0;
	pub const MaxLocks: u32 = 50;
	pub const MaxTreeDepth: u8 = 32;
	pub const CacheBlockLength: u64 = 5;
	pub const MinimumDepositLength: u64 = 10;
}

impl balances::Config for Test {
	type AccountStore = System;
	type Balance = Balance;
	type DustRemoval = ();
	type Event = Event;
	type ExistentialDeposit = ExistentialDeposit;
	type MaxLocks = MaxLocks;
	type WeightInfo = ();
}

impl Config for Test {
	type CacheBlockLength = CacheBlockLength;
	type Event = Event;
	type KeyId = u32;
	type MaxTreeDepth = MaxTreeDepth;
	type Randomness = Randomness;
	type TreeId = u32;
	type WeightInfo = Weights<Self>;
}

pub type MerkleCall = pallet_merkle::Call<Test>;

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	system::GenesisConfig::default().build_storage::<Test>().unwrap().into()
}
