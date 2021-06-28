use super::*;

use crate as pallet_mixer;
use frame_benchmarking::whitelisted_caller;
use frame_support::{construct_runtime, parameter_types, weights::Weight, PalletId};
use frame_system::{
	mocking::{MockBlock, MockUncheckedExtrinsic},
	EnsureRoot,
};
use merkle::weights::Weights as MerkleWeights;

use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
	Perbill,
};
use weights::Weights;

pub(crate) type Balance = u64;
pub type Amount = i128;
pub type AssetId = u64;
pub type AccountId = u64;
pub type BlockNumber = u64;

// Configure a mock runtime to test the pallet.
type UncheckedExtrinsic = MockUncheckedExtrinsic<Test>;
type Block = MockBlock<Test>;

construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		MerkleTrees: merkle::{Pallet, Call, Storage, Event<T>},
		Mixer: pallet_mixer::{Pallet, Call, Storage, Event<T>},
		Assets: pallet_assets::{Pallet, Storage, Event<T>},
		Randomness: pallet_randomness_collective_flip::{Pallet, Call, Storage},
	}
);

parameter_types! {
	pub Prefix: u8 = 100;
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}

impl frame_system::Config for Test {
	type AccountData = pallet_balances::AccountData<u64>;
	type AccountId = AccountId;
	type BaseCallFilter = ();
	type BlockHashCount = BlockHashCount;
	type BlockLength = ();
	type BlockNumber = BlockNumber;
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
	pub const ExistentialDeposit: Balance = 0;
	pub const MaxLocks: u32 = 50;
	pub const MaxReserves: u32 = 50;
	pub const MaxTreeDepth: u8 = 32;
	pub const CacheBlockLength: u64 = 5;
	// Minimum deposit length is 1 month w/ 6 second blocks
	pub const MinimumDepositLength: u64 = 10 * 60 * 24 * 28;
}

impl pallet_balances::Config for Test {
	type AccountStore = System;
	type Balance = Balance;
	type DustRemoval = ();
	type Event = Event;
	type ExistentialDeposit = ExistentialDeposit;
	type MaxLocks = MaxLocks;
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = [u8; 8];
	type WeightInfo = ();
}

parameter_types! {
	pub const AssetDeposit: Balance = 0;
	pub const ApprovalDeposit: Balance = 0;
	pub const StringLimit: u32 = 50;
	pub const MetadataDepositBase: Balance = 0;
	pub const MetadataDepositPerByte: Balance = 0;
}

impl pallet_assets::Config for Test {
	type ApprovalDeposit = ApprovalDeposit;
	type AssetDeposit = AssetDeposit;
	type AssetId = AssetId;
	type Balance = u64;
	type Currency = Balances;
	type Event = Event;
	type Extra = ();
	type ForceOrigin = EnsureRoot<AccountId>;
	type Freezer = ();
	type MetadataDepositBase = MetadataDepositBase;
	type MetadataDepositPerByte = MetadataDepositPerByte;
	type StringLimit = StringLimit;
	type WeightInfo = ();
}

impl merkle::Config for Test {
	type CacheBlockLength = CacheBlockLength;
	type Event = Event;
	type KeyId = u32;
	type MaxTreeDepth = MaxTreeDepth;
	type Randomness = Randomness;
	type TreeId = u32;
	type WeightInfo = MerkleWeights<Self>;
}

parameter_types! {
	pub const MixerPalletId: PalletId = PalletId(*b"py/mixer");
	pub const DefaultAdmin: u64 = 4;
	pub MixerSizes: Vec<Balance> = [1_000, 10_000, 100_000, 1_000_000].to_vec();
	pub const DefaultCurrencyId: AssetId = 0;
}

impl Config for Test {
	type AssetSystem = Assets;
	type Currency = Balances;
	type DefaultAdmin = DefaultAdmin;
	type DefaultCurrencyId = DefaultCurrencyId;
	type DepositLength = MinimumDepositLength;
	type Event = Event;
	type MixerSizes = MixerSizes;
	type PalletId = MixerPalletId;
	type Tree = MerkleTrees;
	type WeightInfo = Weights<Self>;
}

impl pallet_randomness_collective_flip::Config for Test {}

pub type MixerCall = pallet_mixer::Call<Test>;

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	use pallet_balances::GenesisConfig as BalancesConfig;
	// use tokens::GenesisConfig as TokensConfig;
	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

	BalancesConfig::<Test> {
		// Total issuance will be 200 with treasury account initialized at ED.
		balances: vec![
			(0, 1_000_000_000_000_000_000),
			(1, 1_000_000_000_000_000_000),
			(2, 1_000_000_000_000_000_000),
			(whitelisted_caller(), 1_000_000_000),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	t.into()
}
