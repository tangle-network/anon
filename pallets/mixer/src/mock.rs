use sp_runtime::ModuleId;
use crate::{Module, Config};
use frame_support::{impl_outer_origin, impl_outer_event, parameter_types, weights::Weight};
use frame_system as system;
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
	Perbill,
};
pub(crate) type Balance = u64;

mod pallet_mixer {
	pub use crate::Event;
}

impl_outer_event! {
	pub enum Event for Test {
		frame_system<T>,
		balances<T>,
		merkle<T>,
		pallet_mixer<T>,
	}
}

impl_outer_origin! {
	pub enum Origin for Test {}
}

// Configure a mock runtime to test the pallet.

#[derive(Clone, Eq, PartialEq)]
pub struct Test;
parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}

impl frame_system::Config for Test {
	type BaseCallFilter = ();
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type Origin = Origin;
	type Index = u64;
	type Call = ();
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = Event;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = ();
	type AccountData = balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
}

parameter_types! {
	pub const ExistentialDeposit: Balance = 0;
	pub const MaxLocks: u32 = 50;
	pub const MaxTreeDepth: u8 = 32;
	pub const CacheBlockLength: u64 = 100;
	// Minimum deposit length is 1 month w/ 6 second blocks
	pub const MinimumDepositLength: u64 = 10 * 60 * 24 * 28;
}

impl balances::Config for Test {
	type Balance = Balance;
	type Event = Event;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type MaxLocks = MaxLocks;
	type WeightInfo = ();
}

impl merkle::Config for Test {
	type Event = Event;
	type GroupId = u32;
	type MaxTreeDepth = MaxTreeDepth;
	type CacheBlockLength = CacheBlockLength;
}

parameter_types! {
	pub const MixerModuleId: ModuleId = ModuleId(*b"py/mixer");
}

impl Config for Test {
	type Event = Event;
	type Currency = Balances;
	type ModuleId = MixerModuleId;
	type Group = MerkleGroups;
	type MaxTreeDepth = MaxTreeDepth;
	type DepositLength = MinimumDepositLength;
}

pub type Balances = balances::Module<Test>;
pub type System = system::Module<Test>;
pub type MerkleGroups = merkle::Module<Test>;
pub type Mixer = Module<Test>;

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	use balances::{GenesisConfig as BalancesConfig};
	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
	BalancesConfig::<Test>{
		// Total issuance will be 200 with treasury account initialized at ED.
		balances: vec![
			(0, 1_000_000_000),
			(1, 1_000_000_000),
			(2, 1_000_000_000),
		],
	}.assimilate_storage(&mut t).unwrap();
	t.into()
}
