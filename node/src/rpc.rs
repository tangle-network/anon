//! A collection of node-specific RPC methods.

use std::sync::Arc;

use fc_rpc_core::types::{FilterPool, PendingTransactions};
use sc_client_api::{
	backend::{AuxStore, StorageProvider},
	client::BlockchainEvents,
};
use sc_rpc::SubscriptionTaskExecutor;
use sc_rpc_api::DenyUnsafe;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_transaction_pool::TransactionPool;
use std::collections::BTreeMap;
use webb_runtime::{opaque::Block, AccountId, Balance, BlockNumber, Hash, Index};

use fc_rpc::{OverrideHandle, RuntimeApiStorageOverride, SchemaV1Override, StorageOverride};
use jsonrpc_pubsub::manager::SubscriptionManager;
use merkle_rpc::{MerkleApi, MerkleClient};
use pallet_ethereum::EthereumStorageSchema;
use sc_finality_grandpa::{FinalityProofProvider, GrandpaJustificationStream, SharedAuthoritySet, SharedVoterState};
use sc_finality_grandpa_rpc::GrandpaRpcHandler;
use sc_network::NetworkService;
use sp_block_builder::BlockBuilder;
use sp_consensus::SelectChain;

/// Light client extra dependencies.
pub struct LightDeps<C, F, P> {
	/// The client instance to use.
	pub client: Arc<C>,
	/// Transaction pool instance.
	pub pool: Arc<P>,
	/// Remote access to the blockchain (async).
	pub remote_blockchain: Arc<dyn sc_client_api::light::RemoteBlockchain<Block>>,
	/// Fetcher instance.
	pub fetcher: Arc<F>,
}

/// Extra dependencies for GRANDPA
pub struct GrandpaDeps<B> {
	/// Voting round info.
	pub shared_voter_state: SharedVoterState,
	/// Authority set info.
	pub shared_authority_set: SharedAuthoritySet<Hash, BlockNumber>,
	/// Receives notifications about justification events from Grandpa.
	pub justification_stream: GrandpaJustificationStream<Block>,
	/// Executor to drive the subscription manager in the Grandpa RPC handler.
	pub subscription_executor: SubscriptionTaskExecutor,
	/// Finality proof provider.
	pub finality_provider: Arc<FinalityProofProvider<B, Block>>,
}

/// Full client dependencies.
pub struct FullDeps<C, P, SC, B> {
	/// The client instance to use.
	pub client: Arc<C>,
	/// Transaction pool instance.
	pub pool: Arc<P>,
	/// The SelectChain Strategy
	pub select_chain: SC,
	/// The Node authority flag
	pub is_authority: bool,
	/// Whether to enable dev signer
	pub enable_dev_signer: bool,
	/// Network service
	pub network: Arc<NetworkService<Block, Hash>>,
	/// Whether to deny unsafe calls
	pub deny_unsafe: DenyUnsafe,
	/// GRANDPA specific dependencies.
	pub grandpa: GrandpaDeps<B>,
	/// Ethereum pending transactions.
	pub pending_transactions: PendingTransactions,
	/// EthFilterApi pool.
	pub filter_pool: Option<FilterPool>,
	/// Backend.
	pub backend: Arc<fc_db::Backend<Block>>,
	/// Maximum number of logs in a query.
	pub max_past_logs: u32,
}

/// Instantiate all Full RPC extensions.
pub fn create_full<C, P, SC, B>(
	deps: FullDeps<C, P, SC, B>,
	subscription_task_executor: SubscriptionTaskExecutor,
) -> jsonrpc_core::IoHandler<sc_rpc_api::Metadata>
where
	C: ProvideRuntimeApi<Block> + StorageProvider<Block, B> + AuxStore,
	C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
	C: Send + Sync + 'static,
	C: BlockchainEvents<Block>,
	C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Index>,
	C::Api: pallet_contracts_rpc::ContractsRuntimeApi<Block, AccountId, Balance, BlockNumber, Hash>,
	C::Api: BlockBuilder<Block>,
	C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
	C::Api: fp_rpc::EthereumRuntimeRPCApi<Block>,
	C::Api: BlockBuilder<Block>,
	C::Api: merkle::MerkleApi<Block>,
	P: TransactionPool<Block = Block> + 'static,
	SC: SelectChain<Block> + 'static,
	B: sc_client_api::Backend<Block> + Send + Sync + 'static,
	B::State: sc_client_api::backend::StateBackend<sp_runtime::traits::HashFor<Block>>,
{
	use fc_rpc::{
		EthApi, EthApiServer, EthDevSigner, EthFilterApi, EthFilterApiServer, EthPubSubApi, EthPubSubApiServer,
		EthSigner, HexEncodedIdProvider, NetApi, NetApiServer, Web3Api, Web3ApiServer,
	};
	use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApi};
	use substrate_frame_rpc_system::{FullSystem, SystemApi};

	let mut io = jsonrpc_core::IoHandler::default();
	let FullDeps {
		client,
		pool,
		select_chain: _,
		deny_unsafe,
		is_authority,
		network,
		pending_transactions,
		filter_pool,
		backend,
		enable_dev_signer,
		grandpa,
		max_past_logs,
	} = deps;

	let GrandpaDeps {
		shared_voter_state,
		shared_authority_set,
		justification_stream,
		subscription_executor,
		finality_provider,
	} = grandpa;

	io.extend_with(SystemApi::to_delegate(FullSystem::new(
		client.clone(),
		pool.clone(),
		deny_unsafe,
	)));
	io.extend_with(TransactionPaymentApi::to_delegate(TransactionPayment::new(
		client.clone(),
	)));

	let mut signers = Vec::new();
	if enable_dev_signer {
		signers.push(Box::new(EthDevSigner::new()) as Box<dyn EthSigner>);
	}
	let mut overrides_map = BTreeMap::new();
	overrides_map.insert(
		EthereumStorageSchema::V1,
		Box::new(SchemaV1Override::new(client.clone())) as Box<dyn StorageOverride<_> + Send + Sync>,
	);

	let overrides = Arc::new(OverrideHandle {
		schemas: overrides_map,
		fallback: Box::new(RuntimeApiStorageOverride::new(client.clone())),
	});

	io.extend_with(EthApiServer::to_delegate(EthApi::new(
		client.clone(),
		pool.clone(),
		webb_runtime::TransactionConverter,
		network.clone(),
		pending_transactions.clone(),
		signers,
		overrides.clone(),
		backend,
		is_authority,
		max_past_logs,
	)));

	if let Some(filter_pool) = filter_pool {
		io.extend_with(EthFilterApiServer::to_delegate(EthFilterApi::new(
			client.clone(),
			filter_pool.clone(),
			500 as usize, // max stored filters
			overrides.clone(),
			max_past_logs,
		)));
	}

	io.extend_with(NetApiServer::to_delegate(NetApi::new(
		client.clone(),
		network.clone(),
		// Whether to format the `peer_count` response as Hex (default) or not.
		true,
	)));

	io.extend_with(Web3ApiServer::to_delegate(Web3Api::new(client.clone())));

	io.extend_with(EthPubSubApiServer::to_delegate(EthPubSubApi::new(
		pool.clone(),
		client.clone(),
		network.clone(),
		SubscriptionManager::<HexEncodedIdProvider>::with_id_provider(
			HexEncodedIdProvider::default(),
			Arc::new(subscription_task_executor),
		),
		overrides,
	)));

	io.extend_with(MerkleApi::to_delegate(MerkleClient::new(client.clone())));

	io.extend_with(sc_finality_grandpa_rpc::GrandpaApi::to_delegate(
		GrandpaRpcHandler::new(
			shared_authority_set.clone(),
			shared_voter_state,
			justification_stream,
			subscription_executor,
			finality_provider,
		),
	));

	io
}

/// Instantiate all Light RPC extensions.
pub fn create_light<C, P, M, F>(deps: LightDeps<C, F, P>) -> jsonrpc_core::IoHandler<M>
where
	C: sp_blockchain::HeaderBackend<Block>,
	C: Send + Sync + 'static,
	F: sc_client_api::light::Fetcher<Block> + 'static,
	P: TransactionPool + 'static,
	M: jsonrpc_core::Metadata + Default,
{
	use substrate_frame_rpc_system::{LightSystem, SystemApi};

	let LightDeps {
		client,
		pool,
		remote_blockchain,
		fetcher,
	} = deps;
	let mut io = jsonrpc_core::IoHandler::default();
	io.extend_with(SystemApi::<Hash, AccountId, Index>::to_delegate(LightSystem::new(
		client,
		remote_blockchain,
		fetcher,
		pool,
	)));

	io
}
