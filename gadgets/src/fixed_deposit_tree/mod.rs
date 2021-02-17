pub mod builder;

#[cfg(test)]
pub mod tests;

use bulletproofs::r1cs::Verifier;
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::{
	poseidon::{builder::Poseidon, Poseidon_hash_2_constraints},
	smt::smt::vanilla_merkle_merkle_tree_verif_gadget,
	utils::{constrain_lc_with_scalar, AllocatedScalar},
};
use alloc::vec::Vec;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use curve25519_dalek::scalar::Scalar;

pub fn fixed_deposit_tree_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	depth: usize,
	root: &Scalar,
	nullifier_hash: &Scalar,
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	leaf_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	proof_nodes: Vec<AllocatedScalar>,
	statics: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	let statics_lc: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();
	// use hash constraints to generate leaf and constrain by passed in leaf
	let leaf = Poseidon_hash_2_constraints::<CS>(
		cs,
		r.variable.into(),
		nullifier.variable.into(),
		statics_lc.clone(),
		poseidon_params,
	)?;
	let leaf_lc: LinearCombination = leaf_val.variable.into();
	cs.constrain(leaf - leaf_lc);
	// use hash to ensure nullifier_hash is properly taken
	let computed_nullifier_hash = Poseidon_hash_2_constraints::<CS>(
		cs,
		nullifier.variable.into(),
		nullifier.variable.into(),
		statics_lc.clone(),
		poseidon_params,
	)?;
	constrain_lc_with_scalar::<CS>(cs, computed_nullifier_hash, nullifier_hash);
	// if all is successful, constrain gadget by merkle root construction with
	// merkle proof path
	vanilla_merkle_merkle_tree_verif_gadget(
		cs,
		depth,
		root,
		leaf_val,
		leaf_index_bits,
		proof_nodes,
		statics,
		poseidon_params,
	)?;
	Ok(())
}

pub struct Transaction {
	root: Scalar,
	nullifier_hash: Scalar,
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	leaf_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	proof_nodes: Vec<AllocatedScalar>,
}

pub fn batched_fixed_deposit_tree_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	depth: usize,
	txes: Vec<Transaction>,
	statics: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	for i in 0..txes.len() {
		fixed_deposit_tree_verif_gadget(
			cs,
			depth,
			&txes[i].root,
			&txes[i].nullifier_hash,
			txes[i].r,
			txes[i].nullifier,
			txes[i].leaf_val,
			txes[i].leaf_index_bits.clone(),
			txes[i].proof_nodes.clone(),
			statics.clone(),
			poseidon_params,
		)?;
	}
	Ok(())
}

pub struct TransactionCommitment {
	root: Scalar,
	nullifier_hash: Scalar,
	r: CompressedRistretto,
	nullifier: CompressedRistretto,
	leaf_val: CompressedRistretto,
	leaf_index_bits: Vec<CompressedRistretto>,
	proof_nodes: Vec<CompressedRistretto>,
}

pub fn batched_commit_for_verifier(
	verifier: &mut Verifier,
	txes: Vec<TransactionCommitment>,
) -> Vec<Transaction> {
	let mut tx_allocs: Vec<Transaction> = vec![];
	for i in 0..txes.len() {
		let r_val = verifier.commit(txes[i].r);
		let nullifier_val = verifier.commit(txes[i].nullifier);
		let r_alloc = AllocatedScalar {
			variable: r_val,
			assignment: None,
		};
		let nullifier_alloc = AllocatedScalar {
			variable: nullifier_val,
			assignment: None,
		};

		let var_leaf = verifier.commit(txes[i].leaf_val);
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: None,
		};

		let mut leaf_index_alloc_scalars = vec![];
		for l in &txes[i].leaf_index_bits {
			let v = verifier.commit(*l);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let mut proof_alloc_scalars = vec![];
		for p in &txes[i].proof_nodes {
			let v = verifier.commit(*p);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		tx_allocs.push(Transaction {
			root: txes[i].root,
			nullifier_hash: txes[i].nullifier_hash,
			r: r_alloc,
			nullifier: nullifier_alloc,
			leaf_val: leaf_alloc_scalar,
			leaf_index_bits: leaf_index_alloc_scalars,
			proof_nodes: proof_alloc_scalars,
		});
	}

	return tx_allocs;
}