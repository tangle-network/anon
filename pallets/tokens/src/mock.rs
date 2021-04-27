use super::*;
use crate as tokens;
use basic_currency::BasicCurrencyAdapter;
use frame_benchmarking::whitelisted_caller;
use frame_support::{construct_runtime, parameter_types, weights::Weight, PalletId};
use frame_system::mocking::{MockBlock, MockUncheckedExtrinsic};
use sp_runtime::Permill;

use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
	AccountId32, Perbill,
};

pub(crate) type Balance = u64;
pub type Amount = i128;
pub type CurrencyId = u64;
pub type AccountId = AccountId32;
pub type BlockNumber = u64;

pub const DOT: CurrencyId = 1;
pub const BTC: CurrencyId = 2;
pub const ETH: CurrencyId = 3;
pub const ALICE: AccountId = AccountId32::new([0u8; 32]);
pub const BOB: AccountId = AccountId32::new([1u8; 32]);
pub const TREASURY_ACCOUNT: AccountId = AccountId32::new([2u8; 32]);
pub const DAVE: AccountId = AccountId::new([4u8; 32]);
pub const ID_1: LockIdentifier = *b"1       ";
pub const ID_2: LockIdentifier = *b"2       ";

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
		Tokens: tokens::{Pallet, Call, Storage, Event<T>},
		Treasury: pallet_treasury::{Pallet, Call, Storage, Config, Event<T>},
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
	type WeightInfo = ();
}

parameter_types! {
	pub const ProposalBond: Permill = Permill::from_percent(5);
	pub const ProposalBondMinimum: u64 = 1;
	pub const SpendPeriod: u64 = 2;
	pub const Burn: Permill = Permill::from_percent(50);
	pub const TreasuryPalletId: PalletId = PalletId(*b"py/trsry");
	pub const GetTokenId: CurrencyId = DOT;
	pub const MaxApprovals: u32 = 100;
}

impl pallet_treasury::Config for Test {
	type ApproveOrigin = frame_system::EnsureRoot<AccountId>;
	type Burn = Burn;
	type BurnDestination = ();
	type Currency = CurrencyAdapter<Test, GetTokenId>;
	type Event = Event;
	type MaxApprovals = MaxApprovals;
	type OnSlash = ();
	type PalletId = TreasuryPalletId;
	type ProposalBond = ProposalBond;
	type ProposalBondMinimum = ProposalBondMinimum;
	type RejectOrigin = frame_system::EnsureRoot<AccountId>;
	type SpendFunds = ();
	type SpendPeriod = SpendPeriod;
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

parameter_types! {
	pub DustAccount: AccountId = PalletId(*b"webb/dst").into_account();
}

impl Config for Test {
	type Amount = i128;
	type ApprovalDeposit = ApprovalDeposit;
	type Balance = Balance;
	type CurrencyDeposit = CurrencyDeposit;
	type CurrencyId = CurrencyId;
	type DustAccount = DustAccount;
	type Event = Event;
	type Extra = ();
	type ForceOrigin = frame_system::EnsureRoot<AccountId>;
	type MetadataDepositBase = MetadataDepositBase;
	type MetadataDepositPerByte = MetadataDepositPerByte;
	type NativeCurrency = BasicCurrencyAdapter<Test, Balances, Amount, BlockNumber>;
	type PalletId = TokensPalletId;
	type StringLimit = StringLimit;
	type WeightInfo = ();
}

pub type TreasuryCurrencyAdapter = <Test as pallet_treasury::Config>::Currency;

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	use pallet_balances::GenesisConfig as BalancesConfig;
	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

	BalancesConfig::<Test> {
		// Total issuance will be 200 with treasury account initialized at ED.
		balances: vec![
			(ALICE, 1_000_000_000_000_000_000),
			(BOB, 1_000_000_000_000_000_000),
			(TREASURY_ACCOUNT, 1_000_000_000_000_000_000),
			(whitelisted_caller(), 1_000_000_000_000_000_000),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	t.into()
}
