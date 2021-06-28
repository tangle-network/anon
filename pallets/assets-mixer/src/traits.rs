use super::*;
use frame_support::dispatch;
use merkle::utils::setup::Setup;

pub trait ExtendedMixer<T: Config> {
	fn create_new(
		account_id: T::AccountId,
		currency_id: CurrencyIdOf<T>,
		setup: Setup,
		size: BalanceOf<T>,
	) -> Result<T::TreeId, dispatch::DispatchError>;
}
