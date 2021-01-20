pub mod builder;

#[cfg(test)]
pub mod tests;

use crate::{
	poseidon::{builder::Poseidon, Poseidon_hash_2_constraints},
	smt::smt::vanilla_merkle_merkle_tree_verif_gadget,
	utils::{constrain_lc_with_scalar, AllocatedScalar},
};
use alloc::vec::Vec;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use curve25519_dalek::scalar::Scalar;

pub const TREE_DEPTH: usize = 30;

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
