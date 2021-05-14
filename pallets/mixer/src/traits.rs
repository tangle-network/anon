use frame_support::dispatch;
use merkle::utils::hasher::{Backend, HashFunction};

pub trait ExtendedMixer<AccountId, CurrencyId, Balance> {
	fn create_new(
		account_id: AccountId,
		currency_id: CurrencyId,
		hasher: HashFunction,
		backend: Backend,
		size: Balance,
	) -> Result<(), dispatch::DispatchError>;
}
