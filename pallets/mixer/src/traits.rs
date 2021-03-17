use frame_support::dispatch;

pub trait ExtendedMixer<AccountId, CurrencyId, Balance> {
	fn create_new(account_id: AccountId, currency_id: CurrencyId, size: Balance)
		-> Result<(), dispatch::DispatchError>;
}
