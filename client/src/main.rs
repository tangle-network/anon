use sp_keyring::AccountKeyring;
use substrate_subxt::system::AccountStoreExt;
use substrate_subxt::{balances::*, ClientBuilder, KusamaRuntime, PairSigner};

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let signer = PairSigner::new(AccountKeyring::Alice.pair());
	let bob = AccountKeyring::Bob.to_account_id();

	let client = ClientBuilder::<KusamaRuntime>::new().build().await?;
	let bob_account = client.account(&bob, None).await?;
	println!("{}", bob_account.data.free);

	let hash = client
		.transfer(&signer, &bob.clone().into(), 10u128)
		.await?;

	let bob_account = client.account(&bob, None).await?;
	println!("{}", bob_account.data.free);

	println!("Balance transfer extrinsic submitted: {}", hash);

	Ok(())
}
