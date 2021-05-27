use super::*;
use crate::{mock::*, utils::keys::slice_to_bytes_32};
use ark_serialize::CanonicalSerialize;
use arkworks_gadgets::{
	ark_std::UniformRand,
	prelude::{
		ark_bls12_381::{Bls12_381, Fr as Bls381},
		ark_ff::{to_bytes, BigInteger, PrimeField},
		ark_groth16::Groth16,
		webb_crypto_primitives::{
			crh::{poseidon::PoseidonParameters, CRH},
			to_field_elements, SNARK,
		},
	},
	setup::mixer::{prove_groth16, setup_arbitrary_data, setup_circuit, setup_leaf, setup_params_5, setup_tree},
};
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use bulletproofs_gadgets::{
	fixed_deposit_tree::builder::FixedDepositTreeBuilder,
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		PoseidonSbox,
	},
	smt::gen_zero_tree,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use frame_support::{assert_err, assert_ok, traits::UnfilteredDispatchable};
use frame_system::RawOrigin;
use merlin::Transcript;
use rand_core::OsRng;
use sp_runtime::traits::BadOrigin;

fn key_bytes(x: u8) -> [u8; 32] {
	[
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, x,
	]
}

fn default_hasher(num_gens: usize) -> Poseidon {
	let width = 6;
	PoseidonBuilder::new(width)
		.bulletproof_gens(BulletproofGens::new(num_gens, 1))
		.sbox(PoseidonSbox::Exponentiation3)
		.build()
}

#[test]
fn can_create_tree() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(3),
		));
	});
}

#[test]
fn can_update_manager_when_required() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			hasher,
			backend,
			Some(3),
		));

		assert_ok!(MerkleTrees::set_manager(Origin::signed(1), 0, 2,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);
	});
}

#[test]
fn can_update_manager_when_not_required() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(3),
		));

		assert_ok!(MerkleTrees::set_manager(Origin::signed(1), 0, 2,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);
	});
}

#[test]
fn cannot_update_manager_as_not_manager() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(3),
		));

		assert_err!(MerkleTrees::set_manager(Origin::signed(2), 0, 2,), BadOrigin);
	});
}

#[test]
fn can_update_manager_required_manager() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(3),
		));

		assert_ok!(MerkleTrees::set_manager_required(Origin::signed(1), 0, true,));

		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.required, true);
	});
}

#[test]
fn cannot_update_manager_required_as_not_manager() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(3),
		));

		assert_err!(
			MerkleTrees::set_manager_required(Origin::signed(2), 0, true,),
			Error::<Test>::ManagerIsRequired
		);
	});
}

#[test]
fn can_add_member() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(3),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
	});
}

#[test]
fn can_add_member_as_manager() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			hasher,
			backend,
			Some(3),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
	});
}

#[test]
fn cannot_add_member_as_not_manager() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			hasher,
			backend,
			Some(3),
		));
		assert_err!(
			MerkleTrees::add_members(Origin::signed(2), 0, vec![key.clone()]),
			Error::<Test>::ManagerIsRequired
		);
	});
}

#[test]
fn should_be_able_to_set_stopped_merkle() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			hasher,
			backend,
			Some(1),
		));
		assert_ok!(MerkleTrees::set_stopped(Origin::signed(1), 0, true));

		// stopping merkle, stopped == true
		let stopped = MerkleTrees::stopped(0);
		assert!(stopped);

		assert_ok!(MerkleTrees::set_stopped(Origin::signed(1), 0, false));

		// starting merkle again, stopped == false
		let stopped = MerkleTrees::stopped(0);
		assert!(!stopped);
	});
}

#[test]
fn should_be_able_to_change_manager_with_root() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			true,
			hasher,
			backend,
			Some(3),
		));
		let call = Box::new(MerkleCall::set_manager(0, 2));
		let res = call.dispatch_bypass_filter(RawOrigin::Root.into());
		assert_ok!(res);
		let mng = MerkleTrees::get_manager(0).unwrap();
		assert_eq!(mng.account_id, 2);

		let call = Box::new(MerkleCall::set_manager(0, 3));
		let res = call.dispatch_bypass_filter(RawOrigin::Signed(0).into());
		assert_err!(res, BadOrigin);
	})
}

#[test]
fn should_not_have_0_depth() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_err!(
			MerkleTrees::create_tree(Origin::signed(1), false, hasher, backend, Some(0)),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_min_depth() {
	new_test_ext().execute_with(|| {
		let key = key_bytes(1).to_vec();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(1),
		));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]));
		assert_err!(
			MerkleTrees::add_members(Origin::signed(1), 0, vec![key.clone()]),
			Error::<Test>::ExceedsMaxLeaves,
		);
	});
}

#[test]
fn should_have_max_depth() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(32),
		));
	});
}

#[test]
fn should_not_have_more_than_max_depth() {
	new_test_ext().execute_with(|| {
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_err!(
			MerkleTrees::create_tree(Origin::signed(1), false, hasher, backend, Some(33),),
			Error::<Test>::InvalidTreeDepth,
		);
	});
}

#[test]
fn should_have_correct_root_hash_after_insertion() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let key0 = key_bytes(0).to_vec();
		let key1 = key_bytes(1).to_vec();
		let key2 = key_bytes(2).to_vec();
		let zero_h0 = zero_tree[0].to_vec();
		let zero_h1 = zero_tree[1].to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(2),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![key0.clone()]));

		let keyh1 = setup.hash(&key0, &zero_h0).unwrap();
		let keyh2 = setup.hash(&keyh1, &zero_h1).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleTrees::add_members(Origin::signed(2), 0, vec![key1.clone()]));

		let keyh1 = setup.hash(&key0, &key1).unwrap();
		let keyh2 = setup.hash(&keyh1, &zero_h1).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, keyh2, "Invalid root hash");

		assert_ok!(MerkleTrees::add_members(Origin::signed(3), 0, vec![key2.clone()]));

		let keyh1 = setup.hash(&key0, &key1).unwrap();
		let keyh2 = setup.hash(&key2, &zero_h0).unwrap();
		let keyh3 = setup.hash(&keyh1, &keyh2).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, keyh3, "Invalid root hash");
	});
}

#[test]
fn should_have_correct_root_hash() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(key_bytes(i as u8).to_vec());
		}
		let zero_h0 = zero_tree[0].to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(4),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, keys.clone()));

		let key1_1 = setup.hash(&keys[0], &keys[1]).unwrap();
		let key1_2 = setup.hash(&keys[2], &keys[3]).unwrap();
		let key1_3 = setup.hash(&keys[4], &keys[5]).unwrap();
		let key1_4 = setup.hash(&keys[6], &keys[7]).unwrap();
		let key1_5 = setup.hash(&keys[8], &keys[9]).unwrap();
		let key1_6 = setup.hash(&keys[10], &keys[11]).unwrap();
		let key1_7 = setup.hash(&keys[12], &keys[13]).unwrap();
		let key1_8 = setup.hash(&keys[14], &zero_h0).unwrap();

		let key2_1 = setup.hash(&key1_1, &key1_2).unwrap();
		let key2_2 = setup.hash(&key1_3, &key1_4).unwrap();
		let key2_3 = setup.hash(&key1_5, &key1_6).unwrap();
		let key2_4 = setup.hash(&key1_7, &key1_8).unwrap();

		let key3_1 = setup.hash(&key2_1, &key2_2).unwrap();
		let key3_2 = setup.hash(&key2_3, &key2_4).unwrap();

		let root_hash = setup.hash(&key3_1, &key3_2).unwrap();

		let tree = MerkleTrees::trees(0).unwrap();

		assert_eq!(tree.root_hash, root_hash, "Invalid root hash");
	});
}

#[test]
fn should_be_unable_to_pass_proof_path_with_invalid_length() {
	new_test_ext().execute_with(|| {
		let key0 = key_bytes(0).to_vec();
		let key1 = key_bytes(1).to_vec();
		let key2 = key_bytes(2).to_vec();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(2),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, vec![
			key0.clone(),
			key1.clone(),
			key2.clone()
		]));

		let path = vec![(true, key0.clone())];
		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0.clone(), path),
			Error::<Test>::InvalidPathLength,
		);

		let path = vec![(true, key0.clone()), (false, key1), (true, key2)];
		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidPathLength,
		);
	});
}

#[test]
fn should_not_verify_invalid_proof() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let key0 = key_bytes(0).to_vec();
		let key1 = key_bytes(1).to_vec();
		let key2 = key_bytes(2).to_vec();
		let zero_h0 = zero_tree[0].to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(2),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![
			key0.clone(),
			key1.clone(),
			key2.clone()
		]));

		let keyh1 = setup.hash(&key0, &key1).unwrap();
		let keyh2 = setup.hash(&key2, &zero_h0).unwrap();
		let _root_hash = setup.hash(&keyh1, &keyh2).unwrap();

		let path = vec![(false, key1.clone()), (true, keyh2.clone())];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0.clone(), path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key1), (false, keyh2)];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0.clone(), path),
			Error::<Test>::InvalidMembershipProof,
		);

		let path = vec![(true, key2), (true, keyh1)];

		assert_err!(
			MerkleTrees::verify(Origin::signed(2), 0, key0, path),
			Error::<Test>::InvalidMembershipProof,
		);
	});
}

#[test]
fn should_verify_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let h = default_hasher(4096);
		let zero_tree = gen_zero_tree(h.width, &h.sbox);
		let mut keys = Vec::new();
		for i in 0..15 {
			keys.push(key_bytes(i as u8).to_vec());
		}
		let zero_h0 = zero_tree[0].to_vec();

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		let setup = Setup::new(hasher.clone(), backend.clone());
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(4),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(0), 0, keys.clone()));

		let key1_1 = setup.hash(&keys[0], &keys[1]).unwrap();
		let key1_2 = setup.hash(&keys[2], &keys[3]).unwrap();
		let key1_3 = setup.hash(&keys[4], &keys[5]).unwrap();
		let key1_4 = setup.hash(&keys[6], &keys[7]).unwrap();
		let key1_5 = setup.hash(&keys[8], &keys[9]).unwrap();
		let key1_6 = setup.hash(&keys[10], &keys[11]).unwrap();
		let key1_7 = setup.hash(&keys[12], &keys[13]).unwrap();
		let key1_8 = setup.hash(&keys[14], &zero_h0).unwrap();

		let key2_1 = setup.hash(&key1_1, &key1_2).unwrap();
		let key2_2 = setup.hash(&key1_3, &key1_4).unwrap();
		let key2_3 = setup.hash(&key1_5, &key1_6).unwrap();
		let key2_4 = setup.hash(&key1_7, &key1_8).unwrap();

		let key3_1 = setup.hash(&key2_1, &key2_2).unwrap();
		let key3_2 = setup.hash(&key2_3, &key2_4).unwrap();

		let _root_hash = setup.hash(&key3_1, &key3_2).unwrap();

		let path = vec![
			(true, keys[1].clone()),
			(true, key1_2),
			(true, key2_2),
			(true, key3_2.clone()),
		];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[0].clone(), path));

		let path = vec![(true, keys[5].clone()), (true, key1_4), (false, key2_1), (true, key3_2)];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[4].clone(), path));

		let path = vec![
			(true, keys[11].clone()),
			(false, key1_5),
			(true, key2_4),
			(false, key3_1.clone()),
		];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[10].clone(), path));

		let path = vec![(true, zero_h0), (false, key1_7), (false, key2_3), (false, key3_1)];
		assert_ok!(MerkleTrees::verify(Origin::signed(2), 0, keys[14].clone(), path));
	});
}

#[test]
fn should_verify_simple_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(1),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf.to_vec()]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root,
			comms,
			nullifier_hash.to_bytes().to_vec(),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			key_bytes(0).to_vec(),
			key_bytes(0).to_vec(),
		));
	});
}

#[test]
fn should_not_verify_invalid_commitments_for_leaf_creation() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(1),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf.to_vec()]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let mut comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut rng = OsRng::default();
		comms[0] = RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::ZkVerificationFailed
		);
	});
}

#[test]
fn should_not_verify_invalid_private_inputs() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(1),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf.to_vec()]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let mut comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();

		let mut rng = OsRng::default();
		comms.push(RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec());

		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::InvalidPrivateInputs
		);
	});
}

#[test]
fn should_not_verify_invalid_path_commitments_for_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(1),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf.to_vec()]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut leaf_index_comms: Vec<ScalarBytes> =
			leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let mut rng = OsRng::default();
		leaf_index_comms[0] = RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec();
		proof_comms[0] = RistrettoPoint::random(&mut rng).compress().to_bytes().to_vec();
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::ZkVerificationFailed
		);
	});
}

#[test]
fn should_not_verify_invalid_transcript() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let label = b"zk_membership_proof_invalid";
		let mut prover_transcript = Transcript::new(label);
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(1).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(1),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf.to_vec()]));
		let root = MerkleTrees::get_merkle_root(0).unwrap();

		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_err!(
			MerkleTrees::verify_zk(
				0,
				0,
				root,
				comms,
				nullifier_hash.to_bytes().to_vec(),
				proof.to_bytes(),
				leaf_index_comms,
				proof_comms,
				key_bytes(0).to_vec(),
				key_bytes(0).to_vec(),
			),
			Error::<Test>::ZkVerificationFailed
		);
	});
}

#[test]
fn should_verify_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);
		let h = default_hasher(4096);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(h).depth(3).build();

		let leaf0 = ftree.generate_secrets();
		let leaf1 = ftree.generate_secrets();
		let leaf2 = ftree.generate_secrets();
		let leaf3 = ftree.generate_secrets();
		let leaf4 = ftree.generate_secrets();
		let leaf5 = ftree.generate_secrets();
		let leaf6 = ftree.generate_secrets();
		let keys = vec![
			leaf0.to_bytes(),
			leaf1.to_bytes(),
			leaf2.to_bytes(),
			leaf3.to_bytes(),
			leaf4.to_bytes(),
			leaf5.to_bytes(),
			leaf6.to_bytes(),
		];
		ftree.tree.add_leaves(keys.clone(), None);
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(3),
		));
		let keys_vec = keys.iter().map(|x| x.to_vec()).collect();
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, keys_vec));

		let root = MerkleTrees::get_merkle_root(0).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			leaf5,
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root,
			comms,
			nullifier_hash.to_bytes().to_vec(),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			key_bytes(0).to_vec(),
			key_bytes(0).to_vec(),
		));
	});
}

#[test]
fn should_verify_large_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let pc_gens = PedersenGens::default();

		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);
		let poseidon = default_hasher(40960);
		let mut ftree = FixedDepositTreeBuilder::new().hash_params(poseidon).depth(32).build();

		let leaf = ftree.generate_secrets().to_bytes();
		ftree.tree.add_leaves(vec![leaf], None);

		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Bulletproofs(Curve::Curve25519);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(32),
		));
		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf.to_vec()]));

		let root = MerkleTrees::get_merkle_root(0).unwrap();
		let (proof, (comms_cr, nullifier_hash, leaf_index_comms_cr, proof_comms_cr)) = ftree.prove_zk(
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&root)),
			Scalar::from_bytes_mod_order(slice_to_bytes_32(&leaf)),
			Scalar::zero(),
			Scalar::zero(),
			&ftree.hash_params.bp_gens,
			prover,
		);

		let comms: Vec<ScalarBytes> = comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let leaf_index_comms: Vec<ScalarBytes> = leaf_index_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		let proof_comms: Vec<ScalarBytes> = proof_comms_cr.iter().map(|x| x.to_bytes().to_vec()).collect();
		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root,
			comms,
			nullifier_hash.to_bytes().to_vec(),
			proof.to_bytes(),
			leaf_index_comms,
			proof_comms,
			key_bytes(0).to_vec(),
			key_bytes(0).to_vec(),
		));
	});
}

#[test]
fn should_verify_simple_arkworks_zk_proof_of_membership() {
	new_test_ext().execute_with(|| {
		let mut rng = OsRng::default();
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let leaves = Vec::new();
		let roots = Vec::new();
		let (circuit, leaf, nullifier, root, _) =
			setup_circuit(chain_id, &leaves, 0, &roots, recipient, relayer, fee, &mut rng);

		let leaf_bytes = to_bytes![leaf].unwrap();
		let hasher = HashFunction::PoseidonDefault;
		let backend = Backend::Arkworks(Curve::Bls381, Snark::Groth16);
		assert_ok!(MerkleTrees::create_tree(
			Origin::signed(1),
			false,
			hasher,
			backend,
			Some(30),
		));

		assert_ok!(MerkleTrees::add_members(Origin::signed(1), 0, vec![leaf_bytes]));

		let other_root = to_bytes![root].unwrap();
		let root_bytes = MerkleTrees::get_merkle_root(0).unwrap();
		assert_eq!(other_root, root_bytes);
		let recipient_bytes = to_bytes![recipient].unwrap();
		let relayer_bytes = to_bytes![relayer].unwrap();
		let nullifier_bytes = to_bytes![nullifier].unwrap();

		let tree = MerkleTrees::get_tree(0).unwrap();
		let proving_key = tree.setup.get_default_proving_key().unwrap();
		let proof = prove_groth16(&proving_key, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();

		assert_ok!(MerkleTrees::verify_zk(
			0,
			0,
			root_bytes,
			Vec::new(),
			nullifier_bytes,
			proof_bytes,
			Vec::new(),
			Vec::new(),
			recipient_bytes,
			relayer_bytes,
		));
	});
}
