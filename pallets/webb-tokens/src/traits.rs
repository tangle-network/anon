use frame_support::dispatch;

pub trait ExtendedTokenSystem<AccountId, CurrencyId, Balance> {
	fn issue(account_id: AccountId, currency_id: CurrencyId, size: Balance)
		-> Result<(), dispatch::DispatchError>;
}
