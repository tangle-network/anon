use super::*;
use crate as tokens;
use frame_benchmarking::whitelisted_caller;
use frame_support::{construct_runtime, parameter_types, weights::Weight, PalletId};
use frame_system::mocking::{MockBlock, MockUncheckedExtrinsic};
use basic_currency::BasicCurrencyAdapter;

use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
	Perbill,
};

pub(crate) type Balance = u64;
pub type Amount = i128;
pub type CurrencyId = u64;
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
		Balances: balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		Tokens: tokens::{Pallet, Call, Storage, Event<T>},
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
	type AccountData = balances::AccountData<u64>;
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
	type Origin = Origin;
	type PalletInfo = PalletInfo;
	type SS58Prefix = Prefix;
	type SystemWeightInfo = ();
	type OnSetCode = ();
	type Version = ();
}

parameter_types! {
	pub const ExistentialDeposit: Balance = 0;
	pub const MaxLocks: u32 = 50;
	pub const MaxTreeDepth: u8 = 32;
	pub const CacheBlockLength: u64 = 5;
	// Minimum deposit length is 1 month w/ 6 second blocks
	pub const MinimumDepositLength: u64 = 10 * 60 * 24 * 28;
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

parameter_types! {
	pub const NativeCurrencyId: CurrencyId = 0;
}

parameter_types! {
	pub const TokensPalletId: PalletId = PalletId(*b"py/token");
	pub const CurrencyDeposit: u64 = 1;
	pub const ApprovalDeposit: u64 = 1;
	pub const StringLimit: u32 = 50;
	pub const MetadataDepositBase: u64 = 1;
	pub const MetadataDepositPerByte: u64 = 1;
}

impl Config for Test {
	type PalletId = TokensPalletId;
	type Event = Event;
	type Balance = Balance;
	type Amount = i128;
	type CurrencyId = CurrencyId;
	type NativeCurrency = BasicCurrencyAdapter<Test, Balances, Amount, BlockNumber>;
	type ForceOrigin = frame_system::EnsureRoot<u64>;
	type CurrencyDeposit = CurrencyDeposit;
	type MetadataDepositBase = MetadataDepositBase;
	type MetadataDepositPerByte = MetadataDepositPerByte;
	type ApprovalDeposit = ApprovalDeposit;
	type StringLimit = StringLimit;
	type OnDust = BurnDust<Test>;
	type WeightInfo = ();
	type Extra = ();
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	use balances::GenesisConfig as BalancesConfig;
	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

	BalancesConfig::<Test> {
		// Total issuance will be 200 with treasury account initialized at ED.
		balances: vec![
			(0, 1_000_000_000),
			(1, 1_000_000_000),
			(2, 1_000_000_000),
			(whitelisted_caller(), 1_000_000_000),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	t.into()
}
