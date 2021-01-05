use crate::merkle::hasher::Hasher;
use crate::merkle::keys::{Commitment, Data};
use bulletproofs::r1cs::{
	ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Variable, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, OsRng, RngCore};
use sp_std::prelude::*;

#[derive(Clone)]
pub struct ZkProof {
	pub leaf_com: Commitment,
	pub path: Vec<(Commitment, Commitment)>,
	pub r_com: Commitment,
	pub nullifier_com: Commitment,
	pub nullifier_hash: Data,
	pub bytes: Vec<u8>,
}

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(cs: &mut CS, lc: LinearCombination, scalar: &Scalar) {
	cs.constrain(lc - LinearCombination::from(*scalar));
}

/// A leaf in our system represents a commitment to a random number `r` and a random number `nullifier`
pub fn leaf_data<H: Hasher, C: CryptoRng + RngCore>(rng: &mut C, h: &H) -> (Scalar, Scalar, Data, Data) {
	let r = Scalar::random(rng);
	let nullifier = Scalar::random(rng);
	let nullifier_hash = Data::hash(Data(nullifier), Data(nullifier), h);
	let leaf = Data::hash(Data(r), Data(nullifier), h);
	(r, nullifier, nullifier_hash, leaf)
}

pub fn commit_leaf<H: Hasher, C: CryptoRng + RngCore>(
	rng: &mut C,
	prover: &mut Prover,
	leaf: Data,
	r: Scalar,
	nullifier: Scalar,
	nullifier_hash: Data,
	h: &H,
) -> (CompressedRistretto, CompressedRistretto, CompressedRistretto, Variable) {
	// commit to leaf
	let (leaf_com1, leaf_var1) = prover.commit(leaf.0, Scalar::random(rng));
	// commit to randomness
	let (r_com, r_var) = prover.commit(r, Scalar::random(rng));
	// commit to nullifier
	let (nullifier_com, nullifier_var) = prover.commit(nullifier, Scalar::random(rng));
	// constrain prover with generated leaf commitment
	let leaf_com = Data::constrain_prover(
		prover,
		r_var.into(),
		nullifier_var.into(),
		h
	);
	// constrain leaf commitment by computed leaf on commitments
	prover.constrain(leaf_com - leaf_var1);
	// constrain nullifier by computed nullifier hash
	let nullifier_hash_alloc = Data::constrain_prover(
		prover,
		nullifier_var.into(),
		nullifier_var.into(),
		h
	);
	constrain_lc_with_scalar::<Prover>(prover, nullifier_hash_alloc, &nullifier_hash.0);

	// return commitments and leaf variable
	(r_com, nullifier_com, leaf_com1, leaf_var1)
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

pub fn prove_with_random_leaf<H: Hasher>(h: &H) -> (Data, Data, ZkProof) {
	let mut test_rng = OsRng;
	let (r, nullifier, nullifier_hash, leaf) = leaf_data(&mut test_rng, h);
	let mut path = Vec::new();
	let mut hash = leaf;
	for _ in 0..32 {
		path.push((true, hash));
		hash = Data::hash(hash, hash, h);
	}
	let zk_proof = prove_with_path(hash, leaf, nullifier_hash, nullifier, r, path, h).unwrap();

	(leaf, hash, zk_proof)
}

pub fn prove_with_path<H: Hasher>(
	root: Data,
	leaf: Data,
	nullifier_hash: Data,
	nullifier: Scalar,
	r: Scalar,
	path: Vec<(bool, Data)>,
	h: &H,
) -> Result<ZkProof, R1CSError> {
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(4096, 1);

	let mut prover_transcript = Transcript::new(b"zk_membership_proof");
	let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

	let mut test_rng = OsRng;
	let (r_com, nullifier_com, leaf_com, leaf_var) =
		commit_leaf(&mut test_rng, &mut prover, leaf, r, nullifier, nullifier_hash, h);

	let mut hash_lc: LinearCombination = leaf_var.into();
	let mut zk_path = Vec::new();
	for (side, node) in path {
		let (bit_com, node_com, node_con) =
			commit_path_level(&mut test_rng, &mut prover, node, hash_lc, side as u8, h);
		hash_lc = node_con;
		zk_path.push((Commitment(bit_com), Commitment(node_com)));
	}
	prover.constrain(hash_lc - root.0);

	let proof = prover.prove_with_rng(&bp_gens, &mut test_rng)?;

	Ok(ZkProof {
		leaf_com: Commitment(leaf_com),
		path: zk_path,
		r_com: Commitment(r_com),
		nullifier_com: Commitment(nullifier_com),
		nullifier_hash: nullifier_hash,
		bytes: proof.to_bytes(),
	})
}

pub fn verify<H: Hasher>(root_hash: Data, zk_proof: ZkProof, h: &H) -> Result<(), R1CSError> {
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(4096, 1);

	let mut verifier_transcript = Transcript::new(b"zk_membership_proof");
	let mut verifier = Verifier::new(&mut verifier_transcript);

	let var_leaf = verifier.commit(zk_proof.leaf_com.0);
	let var_s = verifier.commit(zk_proof.r_com.0);
	let var_nullifier = verifier.commit(zk_proof.nullifier_com.0);
	let leaf_lc = Data::constrain_verifier(
		&mut verifier,
		&pc_gens,
		var_s.into(),
		var_nullifier.into(),
		h,
	);
	verifier.constrain(leaf_lc - var_leaf);

	let nullifier_hash_lc = Data::constrain_verifier(
		&mut verifier,
		&pc_gens,
		var_nullifier.into(),
		var_nullifier.into(),
		h
	);
	constrain_lc_with_scalar::<Verifier>(&mut verifier, nullifier_hash_lc, &zk_proof.nullifier_hash.0);


	let mut hash: LinearCombination = var_leaf.into();
	for (bit, pair) in zk_proof.path {
		let var_bit = verifier.commit(bit.0);
		let var_pair = verifier.commit(pair.0);

		let (_, _, var_temp) = verifier.multiply(var_bit.into(), var_pair - hash.clone());
		let left = hash.clone() + var_temp;
		let right = var_pair + hash - left.clone();

		hash = Data::constrain_verifier(&mut verifier, &pc_gens, left, right, h);
	}
	verifier.constrain(hash - root_hash.0);
	let proof = R1CSProof::from_bytes(&zk_proof.bytes).unwrap();

	let mut rng = OsRng;
	let res = verifier.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut rng);
	res
}
