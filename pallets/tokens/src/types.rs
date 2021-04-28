use super::*;

#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug)]
pub enum DustHandlerType<AccountId> {
	Burn,
	Transfer(AccountId),
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug)]
pub struct TokenDetails<Balance, AccountId> {
	/// Can change `owner`, `issuer`, `freezer` and `admin` accounts.
	pub(super) owner: AccountId,
	/// Can mint tokens.
	pub(super) issuer: AccountId,
	/// Can thaw tokens, force transfers and burn tokens from any account.
	pub(super) admin: AccountId,
	/// Can freeze tokens.
	pub(super) freezer: AccountId,
	/// The total supply across all accounts.
	pub(super) supply: Balance,
	/// The balance deposited for this currency. This pays for the data stored
	/// here.
	pub(super) deposit: Balance,
	/// The ED for virtual accounts.
	pub(super) min_balance: Balance,
	/// The total number of approvals.
	pub(super) approvals: u32,
	/// Whether the currency is frozen for non-admin transfers.
	pub(super) is_frozen: bool,
	/// The type of handler used to clean up dust
	pub(super) dust_type: DustHandlerType<AccountId>,
}

/// A pair to act as a key for the approval storage map.
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug)]
pub struct ApprovalKey<AccountId> {
	/// The owner of the funds that are being approved.
	pub(super) owner: AccountId,
	/// The party to whom transfer of the funds is being delegated.
	pub(super) delegate: AccountId,
}

/// Data concerning an approval.
#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, Default)]
pub struct Approval<Balance> {
	/// The amount of funds approved for the balance transfer from the owner to
	/// some delegated target.
	pub(super) amount: Balance,
	/// The amount reserved on the owner's account to hold this item in storage.
	pub(super) deposit: Balance,
}

#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, Default)]
pub struct TokenMetadata<Balance> {
	/// The balance deposited for this metadata.
	///
	/// This pays for the data stored in this struct.
	pub(super) deposit: Balance,
	/// The user friendly name of this asset. Limited in length by
	/// `StringLimit`.
	pub(super) name: Vec<u8>,
	/// The ticker symbol for this asset. Limited in length by `StringLimit`.
	pub(super) symbol: Vec<u8>,
	/// The number of decimals this asset uses to represent one unit.
	pub(super) decimals: u8,
	/// Whether the asset metadata may be changed by a non Force origin.
	pub(super) is_frozen: bool,
}

/// Witness data for the destroy transactions.
#[derive(Copy, Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug)]
pub struct DestroyWitness {
	/// The number of accounts holding the asset.
	#[codec(compact)]
	pub(super) accounts: u32,
	/// The number of accounts holding the asset with a self-sufficient
	/// reference.
	#[codec(compact)]
	pub(super) sufficients: u32,
	/// The number of transfer-approvals of the asset.
	#[codec(compact)]
	pub(super) approvals: u32,
}

/// A single lock on a balance. There can be many of these on an account and
/// they "overlap", so the same balance is frozen by multiple locks.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct BalanceLock<Balance> {
	/// An identifier for this lock. Only one lock may be in existence for
	/// each identifier.
	pub id: LockIdentifier,
	/// The amount which the free balance may not drop below when this lock
	/// is in effect.
	pub amount: Balance,
}

/// balance information for an account.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Default, RuntimeDebug)]
pub struct AccountData<Balance> {
	/// Non-reserved part of the balance. There may still be restrictions on
	/// this, but it is the total pool what may in principle be transferred,
	/// reserved.
	///
	/// This is the only balance that matters in terms of most operations on
	/// tokens.
	pub free: Balance,
	/// Balance which is reserved and may not be used at all.
	///
	/// This can still get slashed, but gets slashed last of all.
	///
	/// This balance is a 'reserve' balance that other subsystems use in
	/// order to set aside tokens that are still 'owned' by the account
	/// holder, but which are suspendable.
	pub reserved: Balance,
	/// The amount that `free` may not drop below when withdrawing.
	pub frozen: Balance,
	/// The flag representing if the entire account is frozen
	pub is_frozen: bool,
}

impl<Balance: Saturating + Copy + Ord> AccountData<Balance> {
	/// The amount that this account's free balance may not be reduced
	/// beyond.
	pub(crate) fn frozen(&self) -> Balance {
		self.frozen
	}

	/// The total balance in this account including any that is reserved and
	/// ignoring any frozen.
	pub fn total(&self) -> Balance {
		self.free.saturating_add(self.reserved)
	}
}
