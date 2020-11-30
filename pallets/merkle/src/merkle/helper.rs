use crate::merkle::hasher::Hasher;
use crate::merkle::keys::{Commitment, Data};
use bulletproofs::r1cs::{
	ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, OsRng, RngCore};
use sp_std::prelude::*;

pub fn leaf_data<H: Hasher, C: CryptoRng + RngCore>(rng: &mut C, h: &H) -> (Scalar, Scalar, Data) {
	let s = Scalar::random(rng);
	let nullifier = Scalar::random(rng);
	let leaf = Data::hash(Data(s), Data(nullifier), h);
	(s, nullifier, leaf)
}

pub fn commit_leaf<H: Hasher, C: CryptoRng + RngCore>(
	rng: &mut C,
	prover: &mut Prover,
	leaf: Data,
	s: Scalar,
	nullifier: Scalar,
	h: &H,
) -> (CompressedRistretto, CompressedRistretto, Variable) {
	let (leaf_com1, leaf_var1) = prover.commit(leaf.0, Scalar::random(rng));
	let (s_com, s_var) = prover.commit(s, Scalar::random(rng));
	let leaf_com = Data::constrain_prover(prover, s_var.into(), nullifier.into(), h);
	prover.constrain(leaf_com - leaf_var1);
	(s_com, leaf_com1, leaf_var1)
}

pub fn commit_path_level<H: Hasher, C: CryptoRng + RngCore>(
	rng: &mut C,
	prover: &mut Prover,
	pair: Data,
	hash: LinearCombination,
	bit: u8,
	h: &H,
) -> (CompressedRistretto, CompressedRistretto, LinearCombination) {
	let (com_bit, var_bit) = prover.commit(Scalar::from(bit), Scalar::random(rng));
	let (com_pair, var_pair) = prover.commit(pair.0, Scalar::random(rng));

	let (_, _, var_temp) = prover.multiply(var_bit.into(), var_pair - hash.clone());
	let left = hash.clone() + var_temp;
	let right = var_pair + hash - left.clone();

	let hash_con = Data::constrain_prover(prover, left, right, h);
	(com_bit, com_pair, hash_con)
}

pub fn prove<H: Hasher>(
	h: &H,
) -> (
	Data,
	Commitment,
	Vec<(Commitment, Commitment)>,
	Commitment,
	Data,
	Vec<u8>,
) {
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(4096, 1);

	let mut prover_transcript = Transcript::new(b"zk_membership_proof");
	let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

	let mut test_rng = OsRng;
	let (s, nullifier, leaf) = leaf_data(&mut test_rng, h);

	let (s_com, leaf_com1, leaf_var1) =
		commit_leaf(&mut test_rng, &mut prover, leaf, s, nullifier, h);

	let mut lh = leaf;
	let mut lh_lc: LinearCombination = leaf_var1.into();
	let mut path = Vec::new();
	for _ in 0..32 {
		let (bit_com, leaf_com, node_con) =
			commit_path_level(&mut test_rng, &mut prover, lh, lh_lc, 1, h);
		lh_lc = node_con;
		lh = Data::hash(lh, lh, h);
		path.push((Commitment(bit_com), Commitment(leaf_com)));
	}
	prover.constrain(lh_lc - lh.0);

	let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

	(
		lh,
		Commitment(leaf_com1),
		path,
		Commitment(s_com),
		Data(nullifier),
		proof.to_bytes(),
	)
}

pub fn verify<H: Hasher>(
	h: &H,
	root_hash: Data,
	leaf_com: Commitment,
	path: &Vec<(Commitment, Commitment)>,
	s_com: Commitment,
	nullifier: Data,
	proof_bytes: &Vec<u8>,
) {
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(4096, 1);

	let mut verifier_transcript = Transcript::new(b"zk_membership_proof");
	let mut verifier = Verifier::new(&mut verifier_transcript);

	let var_leaf = verifier.commit(leaf_com.0);
	let var_s = verifier.commit(s_com.0);
	let leaf_lc =
		Data::constrain_verifier(&mut verifier, &pc_gens, var_s.into(), nullifier.0.into(), h);
	verifier.constrain(leaf_lc - var_leaf);

	let mut hash: LinearCombination = var_leaf.into();
	for (bit, pair) in path {
		let var_bit = verifier.commit(bit.0);
		let var_pair = verifier.commit(pair.0);

		let (_, _, var_temp) = verifier.multiply(var_bit.into(), var_pair - hash.clone());
		let left = hash.clone() + var_temp;
		let right = var_pair + hash - left.clone();

		hash = Data::constrain_verifier(&mut verifier, &pc_gens, left, right, h);
	}
	verifier.constrain(hash - root_hash.0);
	let proof = R1CSProof::from_bytes(&proof_bytes).unwrap();

	let mut rng = OsRng;
	verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut rng)
		.unwrap();
}
