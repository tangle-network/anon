#[macro_use]
extern crate substrate_subxt;
extern crate pallet_merkle;

mod merkle;
use crate::substrate_subxt::sp_runtime::traits::Hash;
use merkle::{
	AddMembersCallExt, CacheBlockLength, CreateGroupCallExt, MaxTreeDepth, Merkle,
	VerifyZkMembershipProofCallExt,
};
use pallet_merkle::merkle::helper::prove;
use pallet_merkle::merkle::keys::Data;
use pallet_merkle::merkle::poseidon::Poseidon;
use sp_keyring::AccountKeyring;
use std::collections::HashSet;
use std::time::Instant;
use substrate_subxt::system::System;
use substrate_subxt::{ClientBuilder, NodeTemplateRuntime, PairSigner};

impl Merkle for NodeTemplateRuntime {
	type Data = Data;
	type GroupId = u32;
	type MaxTreeDepth = MaxTreeDepth;
	type CacheBlockLength = CacheBlockLength;
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut signer = PairSigner::new(AccountKeyring::Alice.pair());
	let client = ClientBuilder::<NodeTemplateRuntime>::new().build().await?;

	let h = Poseidon::new(4);
	let num_groups: u32 = 15;

	// Create group
	let start = Instant::now();
	signer.set_nonce(0);
	for _ in 0..num_groups {
		client.create_group(&signer, false, None).await?;
		signer.increment_nonce();
	}
	client.create_group_and_watch(&signer, false, None).await?;
	signer.increment_nonce();
	let elapsed = start.elapsed();
	println!("create group {:?}", elapsed);
	println!("");

	let (leaf, _, zk_proof) = prove(&h);

	// Add members
	let start = Instant::now();
	for group_id in 0..num_groups {
		client.add_members(&signer, group_id, vec![leaf]).await?;
		signer.increment_nonce();
	}
	let res_am = client
		.add_members_and_watch(&signer, num_groups, vec![leaf])
		.await?;
	signer.increment_nonce();
	let elapsed = start.elapsed();
	println!("add member {:?}, block: {:?}", elapsed, res_am.block);
	println!("");

	// Zk verify
	let start = Instant::now();
	let mut verify_zk_txs = HashSet::new();
	for group_id in 0..num_groups {
		let r = client
			.verify_zk_membership_proof(
				&signer,
				group_id,
				zk_proof.leaf_com,
				zk_proof.path.clone(),
				zk_proof.r_com,
				zk_proof.nullifier,
				zk_proof.bytes.clone(),
			)
			.await?;
		signer.increment_nonce();
		verify_zk_txs.insert(format!("{:?}", r));
	}
	let res_zk = client
		.verify_zk_membership_proof_and_watch(
			&signer,
			num_groups,
			zk_proof.leaf_com,
			zk_proof.path,
			zk_proof.r_com,
			zk_proof.nullifier,
			zk_proof.bytes,
		)
		.await?;
	verify_zk_txs.insert(format!("{:?}", res_zk.extrinsic));
	let elapsed = start.elapsed();
	println!("");
	println!(
		"verify {:?}, block: {:?}, extrinsic: {:?}",
		elapsed, res_zk.block, res_zk.extrinsic
	);
	println!("");
	let sb = client.block(Some(res_zk.block)).await?;
	let signed_block = sb.unwrap();
	println!("all extrinsic from the lats block {:?}:", res_zk.block);
	let mut count = 0;
	for ext in signed_block.block.extrinsics {
		let exth = format!(
			"{:?}",
			<NodeTemplateRuntime as System>::Hashing::hash_of(&ext)
		);
		let label = if verify_zk_txs.contains(&exth) {
			count += 1;
			"<--- verify zk ext"
		} else {
			""
		};
		println!("{} {}", exth, label);
	}

	println!("");
	println!("total zk calls in one block: {}", count);

	Ok(())
}
