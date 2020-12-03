#[macro_use]
extern crate substrate_subxt;
extern crate pallet_merkle;

mod merkle;
use merkle::{AddMembersCallExt, CreateGroupCallExt, Merkle, VerifyZkMembershipProofCallExt};
use pallet_merkle::merkle::helper::prove;
use pallet_merkle::merkle::keys::Data;
use pallet_merkle::merkle::poseidon::Poseidon;
use sp_keyring::AccountKeyring;
use std::time::Instant;
use substrate_subxt::{ClientBuilder, NodeTemplateRuntime, PairSigner};

impl Merkle for NodeTemplateRuntime {
	type Data = Data;
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let signer = PairSigner::new(AccountKeyring::Alice.pair());
	let client = ClientBuilder::<NodeTemplateRuntime>::new().build().await?;

	let h = Poseidon::new(4);
	let group_id = 23;

	let start = Instant::now();
	client
		.create_group_and_watch(&signer, group_id, None, None)
		.await?;
	let elapsed = start.elapsed();
	println!("create group {:?}", elapsed);

	let (leaf, _, leaf_com, path, s_com, nullifier, proof_bytes) = prove(&h);

	let start = Instant::now();
	client
		.add_members_and_watch(&signer, group_id, vec![leaf])
		.await?;

	let elapsed = start.elapsed();
	println!("add member {:?}", elapsed);

	let start = Instant::now();
	client
		.verify_zk_membership_proof_and_watch(
			&signer,
			group_id,
			leaf_com,
			path,
			s_com,
			nullifier,
			proof_bytes,
		)
		.await?;
	let elapsed = start.elapsed();
	println!("verify {:?}", elapsed);

	Ok(())
}
