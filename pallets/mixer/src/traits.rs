use frame_support::dispatch;
use merkle::utils::setup::Setup;

pub trait ExtendedMixer<AccountId, CurrencyId, Balance> {
	fn create_new(
		account_id: AccountId,
		currency_id: CurrencyId,
		setup: Setup,
		size: Balance,
	) -> Result<(), dispatch::DispatchError>;
}
