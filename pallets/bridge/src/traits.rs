use super::*;
use frame_support::dispatch;

pub trait PrivacyBridgeSystem {
	type AccountId;
	type CurrencyId;
	type Balance;
	type TreeId;
	type Scalar;

	fn wrap(account_id: Self::AccountId, currency_id: Self::CurrencyId, amount: Self::Balance)
		-> Result<(), dispatch::DispatchError>;
	fn unwrap(account_id: Self::AccountId, currency_id: Self::CurrencyId, into_currency_id: Self::CurrencyId, amount: Self::Balance)
		-> Result<(), dispatch::DispatchError>;
	fn wrap_and_deposit(account_id: Self::AccountId, currency_id: Self::CurrencyId, tree_id: Self::TreeId, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError>;
	fn deposit(account_id: Self::AccountId, tree_id: Self::TreeId, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError>;
	fn withdraw_zk(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError>;
	fn withdraw_public(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError>;
	fn withdraw_zk_and_unwrap(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError>;
	fn withdraw_public_and_unwrap(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>)
		-> Result<(), dispatch::DispatchError>;
	fn remix_zk(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError>;
	fn remix_public(account_id: Self::AccountId, tree_id: Self::TreeId, proof: Vec<u8>, leaf: Self::Scalar)
		-> Result<(), dispatch::DispatchError>;
}

pub trait GovernableBridgeSystem {
	type AccountId;
	type CurrencyId;
	type Balance;
	type TreeId;
	type ChainId;
	type Scalar;
	type IndividualKeyShare;
	type DistributedPublicKey;
	type Signature;

	fn create_new(account_id: Self::AccountId, currency_id: Self::CurrencyId, size: Self::Balance, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError>;
	fn add_anchor_root(anchor_id: Self::TreeId, chain_id: Self::ChainId, root: Self::Scalar, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError>;
	fn remove_anchor_root(anchor_id: Self::TreeId, chain_id: Self::ChainId, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError>;
	fn set_fee(anchor_id: Self::TreeId, fee: Self::Balance, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError>;
	fn set_multi_party_key(anchor_id: Self::TreeId, new_key: Self::DistributedPublicKey, sig: Self::Signature)
		-> Result<(), dispatch::DispatchError>;
	fn validate_signature(sig: Self::Signature) -> bool;
	fn register(account_id: Self::AccountId, share: Self::IndividualKeyShare)
		-> Result<(), dispatch::DispatchError>;
}

pub trait TrustlessBridgeSystem {
	type AccountId;
	type CurrencyId;
	type Balance;
	type TreeId;
	type ChainId;
	type Scalar;
	type IndividualKeyShare;
	type DistributedPublicKey;
	type InclusionProof;

	fn create_new(account_id: Self::AccountId, currency_id: Self::CurrencyId, size: Self::Balance, proof: Self::InclusionProof)
		-> Result<(), dispatch::DispatchError>;
	fn add_anchor_root(anchor_id: Self::TreeId, chain_id: Self::ChainId, root: Self::Scalar, proof: Self::InclusionProof)
		-> Result<(), dispatch::DispatchError>;
	fn remove_anchor_root(anchor_id: Self::TreeId, chain_id: Self::ChainId, proof: Self::InclusionProof)
		-> Result<(), dispatch::DispatchError>;
	fn set_fee(anchor_id: Self::TreeId, fee: Self::Balance, proof: Self::InclusionProof)
		-> Result<(), dispatch::DispatchError>;
	fn set_multi_party_key(anchor_id: Self::TreeId, new_key: Self::DistributedPublicKey, proof: Self::InclusionProof)
		-> Result<(), dispatch::DispatchError>;
	fn validate_proof(proof: Self::InclusionProof) -> bool;
	fn register(account_id: Self::AccountId, share: Self::IndividualKeyShare)
		-> Result<(), dispatch::DispatchError>;
}