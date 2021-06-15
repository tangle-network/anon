use super::*;
use frame_support::dispatch;

pub trait ExtendedMixer<T: Config> {
	fn create_new(
		account_id: T::AccountId,
		currency_id: CurrencyIdOf<T>,
		size: BalanceOf<T>,
	) -> Result<T::TreeId, dispatch::DispatchError>;
}
