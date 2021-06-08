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
	cached_block: <T as frame_system::Config>::BlockNumber,
	/// The cached root being proven against
	cached_root: ScalarBytes,
	/// The individual scalar commitments (to the randomness and nullifier)
	comms: Vec<ScalarBytes>,
	/// The nullifier hash with itself
	nullifier_hash: ScalarBytes,
	/// The proof in bytes representation
	proof_bytes: Vec<u8>,
	/// The leaf index scalar commitments to decide on which side to hash
	leaf_index_commitments: Vec<ScalarBytes>,
	/// The scalar commitments to merkle proof path elements
	proof_commitments: Vec<ScalarBytes>,
	/// The recipient to withdraw amount of currency to
	recipient: Option<<T as frame_system::Config>::AccountId>,
	/// The recipient to withdraw amount of currency to
	relayer: Option<<T as frame_system::Config>::AccountId>,
}

impl<T: Config> WithdrawProof<T> {
	pub fn new(
		mixer_id: T::TreeId,
		cached_block: <T as frame_system::Config>::BlockNumber,
		cached_root: ScalarBytes,
		comms: Vec<ScalarBytes>,
		nullifier_hash: ScalarBytes,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<ScalarBytes>,
		proof_commitments: Vec<ScalarBytes>,
		recipient: Option<<T as frame_system::Config>::AccountId>,
		relayer: Option<<T as frame_system::Config>::AccountId>,
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
