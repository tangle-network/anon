#[cfg(test)]
pub mod tests;

pub mod builder;

use crate::{
	poseidon::{builder::Poseidon, Poseidon_hash_2_gadget, Poseidon_hash_4_constraints, Poseidon_hash_4_gadget},
	smt::smt::vanilla_merkle_merkle_tree_verif_gadget,
	utils::AllocatedScalar,
	zero_nonzero::is_nonzero_gadget,
};
use alloc::vec::Vec;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use curve25519_dalek::scalar::Scalar;

#[derive(Clone)]
pub struct AllocatedInputCoin {
	// private
	inv_value: AllocatedScalar,
	value: AllocatedScalar,
	rho: AllocatedScalar,
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	leaf_cm_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	leaf_proof_nodes: Vec<AllocatedScalar>,
	sn: Scalar,
}

#[derive(Clone)]
pub struct AllocatedOutputCoin {
	// private
	inv_value: AllocatedScalar,
	value: AllocatedScalar,
	rho: AllocatedScalar,
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	leaf_cm: Scalar,
}

#[derive(Clone)]
pub struct Transaction {
	pub inputs: Vec<AllocatedInputCoin>,
	pub outputs: Vec<AllocatedOutputCoin>,
	pub statics_2: Vec<AllocatedScalar>,
	pub statics_4: Vec<AllocatedScalar>,
}

impl Transaction {
	fn hash_constraints<CS: ConstraintSystem>(&self, cs: &mut CS, poseidon_params: &Poseidon) -> Result<(), R1CSError> {
		// check inputs
		for i in 0..self.inputs.len() {
			Poseidon_hash_2_gadget(
				cs,
				self.inputs[i].r,
				self.inputs[i].nullifier,
				self.statics_2.clone(),
				poseidon_params,
				&self.inputs[i].sn,
			)?;

			// use the poseidon 4 constraint gadget
			let statics: Vec<LinearCombination> = self.statics_4.iter().map(|s| s.variable.into()).collect();
			let input_arr: [LinearCombination; 4] = [
				self.inputs[i].value.variable.into(),
				self.inputs[i].rho.variable.into(),
				self.inputs[i].r.variable.into(),
				self.inputs[i].nullifier.variable.into(),
			];
			let leaf_cm_lc = Poseidon_hash_4_constraints::<CS>(cs, input_arr, statics, poseidon_params)?;
			let leaf_cm_val_lc: LinearCombination = self.inputs[i].leaf_cm_val.variable.into();
			cs.constrain(leaf_cm_val_lc - leaf_cm_lc);
		}

		// check output commitment
		for i in 0..self.outputs.len() {
			Poseidon_hash_4_gadget(
				cs,
				[
					self.outputs[i].value,
					self.outputs[i].rho,
					self.outputs[i].r,
					self.outputs[i].nullifier,
				]
				.to_vec(),
				self.statics_4.clone(),
				poseidon_params,
				&self.outputs[i].leaf_cm,
			)?;
		}

		Ok(())
	}

	fn non_zero_constraints<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), R1CSError> {
		for i in 0..self.inputs.len() {
			is_nonzero_gadget(cs, self.inputs[i].value, self.inputs[i].inv_value)?;
		}

		for i in 0..self.outputs.len() {
			is_nonzero_gadget(cs, self.outputs[i].value, self.outputs[i].inv_value)?;
		}

		Ok(())
	}

	fn input_amount(&self) -> LinearCombination {
		let mut sum_inputs = LinearCombination::from(Scalar::zero());
		for i in 0..self.inputs.len() {
			sum_inputs = sum_inputs + self.inputs[i].value.variable;
		}

		sum_inputs
	}

	fn output_amount(&self) -> LinearCombination {
		let mut sum_outputs = LinearCombination::from(Scalar::zero());
		for i in 0..self.outputs.len() {
			sum_outputs = sum_outputs + self.outputs[i].value.variable;
		}

		sum_outputs
	}
}

pub fn variable_deposit_tree_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	depth: usize,
	root: &Scalar,
	txes: Vec<Transaction>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	let mut sum_inputs = LinearCombination::from(Scalar::zero());
	let mut sum_outputs = LinearCombination::from(Scalar::zero());

	for i in 0..txes.len() {
		let tx = txes[i].clone();
		// ensure all hashes are properly created/formatted
		// checks both inputs AND outputs
		tx.hash_constraints(cs, poseidon_params)?;
		// ensure all amounts are non-zero
		tx.non_zero_constraints(cs)?;
		// ensure all inputs are accumulated correcly in the merkle root
		for j in 0..tx.inputs.len() {
			// if all is successful, constrain gadget by merkle root construction with
			// merkle proof path
			vanilla_merkle_merkle_tree_verif_gadget(
				cs,
				depth,
				root,
				tx.inputs[j].leaf_cm_val.clone(),
				tx.inputs[j].leaf_index_bits.clone(),
				tx.inputs[j].leaf_proof_nodes.clone(),
				// TODO: Do we need to use different statics here for each tx input?
				tx.statics_2.clone(),
				poseidon_params,
			)?;

			sum_inputs = sum_inputs + tx.inputs[j].value.variable;
		}

		sum_outputs = sum_outputs + tx.output_amount();
	}

	// total inputs and outputs should be equal and the difference should be zero
	cs.constrain(sum_inputs - sum_outputs);

	Ok(())
}
