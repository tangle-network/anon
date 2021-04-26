use super::*;

/// Info about the mixer and it's leaf data
#[derive(Encode, Decode, PartialEq)]
pub struct AnchorInfo<T: Config> {
	/// Deposit size for the mixer
	pub size: BalanceOf<T>,
	/// Id of the currency in the mixer
	pub currency_id: CurrencyIdOf<T>,
}

impl<T: Config> core::default::Default for AnchorInfo<T> {
	fn default() -> Self {
		Self {
			size: Zero::zero(),
			currency_id: T::NativeCurrencyId::get(),
		}
	}
}

/// Proof data for withdrawal
#[derive(Encode, Decode, PartialEq, Clone)]
pub struct WithdrawProof<T: Config> {
	/// The mixer id this withdraw proof corresponds to
	mixer_id: T::TreeId,
	/// The cached block for the cached root being proven against
	cached_block: T::BlockNumber,
	/// The cached root being proven against
	cached_root: ScalarData,
	/// The individual scalar commitments (to the randomness and nullifier)
	comms: Vec<Commitment>,
	/// The nullifier hash with itself
	nullifier_hash: ScalarData,
	/// The proof in bytes representation
	proof_bytes: Vec<u8>,
	/// The leaf index scalar commitments to decide on which side to hash
	leaf_index_commitments: Vec<Commitment>,
	/// The scalar commitments to merkle proof path elements
	proof_commitments: Vec<Commitment>,
	/// The recipient to withdraw amount of currency to
	recipient: Option<T::AccountId>,
	/// The recipient to withdraw amount of currency to
	relayer: Option<T::AccountId>,
}

impl<T: Config> WithdrawProof<T> {
	pub fn new(
		mixer_id: T::TreeId,
		cached_block: T::BlockNumber,
		cached_root: ScalarData,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
		recipient: Option<T::AccountId>,
		relayer: Option<T::AccountId>,
	) -> Self {
		Self {
			mixer_id,
			cached_block,
			cached_root,
			comms,
			nullifier_hash,
			proof_bytes,
			leaf_index_commitments,
			proof_commitments,
			recipient,
			relayer,
		}
	}
}
