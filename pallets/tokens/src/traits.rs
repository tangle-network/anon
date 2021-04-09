use frame_support::dispatch;

pub trait ExtendedTokenSystem<AccountId, CurrencyId, Balance> {
	fn mint(currency_id: CurrencyId, account_id: AccountId, amount: Balance)
		-> Result<(), dispatch::DispatchError>;
	fn burn(currency_id: CurrencyId, account_id: AccountId, amount: Balance)
		-> Result<(), dispatch::DispatchError>;
}
