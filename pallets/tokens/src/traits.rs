use frame_support::dispatch;

pub trait ExtendedTokenSystem<AccountId, CurrencyId, Balance> {
	fn create(
		currency: CurrencyId,
		owner: AccountId,
		admin: AccountId,
		min_balance: Balance,
	) -> Result<(), dispatch::DispatchError>;
	fn mint(currency_id: CurrencyId, account_id: AccountId, amount: Balance) -> Result<(), dispatch::DispatchError>;
	fn burn(currency_id: CurrencyId, account_id: AccountId, amount: Balance) -> Result<(), dispatch::DispatchError>;
	fn handle_dust(currency_id: CurrencyId, account_id: &AccountId, amount: Balance);
}
