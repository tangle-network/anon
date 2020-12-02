#[macro_use]
extern crate substrate_subxt;
extern crate pallet_merkle;

mod merkle;
use merkle::{
	AddMembersCallExt, CreateGroupCallExt, GroupsStoreExt, Merkle, NewMemberEventExt,
	VerifyZkMembershipProofCallExt,
};
use pallet_merkle::merkle::helper::prove;
use pallet_merkle::merkle::poseidon::Poseidon;
use sp_keyring::AccountKeyring;
use substrate_subxt::system::AccountStoreExt;
use substrate_subxt::{ClientBuilder, NodeTemplateRuntime, PairSigner};

impl Merkle for NodeTemplateRuntime {}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let signer = PairSigner::new(AccountKeyring::Alice.pair());
	let client = ClientBuilder::<NodeTemplateRuntime>::new().build().await?;

	let h = Poseidon::new(4);
	let group_id = 6;

	let _ = client
		.create_group_and_watch(&signer, group_id, None, None)
		.await?;

	let (leaf, _, leaf_com, path, s_com, nullifier, proof_bytes) = prove(&h);
	let res2 = client
		.add_members_and_watch(&signer, group_id, vec![leaf])
		.await?;

	// let res3 = client
	// 	.verify_zk_membership_proof_and_watch(
	// 		&signer,
	// 		group_id,
	// 		leaf_com,
	// 		path,
	// 		s_com,
	// 		nullifier,
	// 		proof_bytes,
	// 	)
	// 	.await?;
	let res4 = res2.new_member()?;

	println!("group: {:?}", res4);

	Ok(())
}
