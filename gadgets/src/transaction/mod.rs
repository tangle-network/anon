#[cfg(test)]
pub mod tests;

pub mod builder;

use crate::{
	poseidon::{builder::Poseidon, Poseidon_hash_2_gadget, Poseidon_hash_4_gadget},
	utils::AllocatedScalar,
	zero_nonzero::is_nonzero_gadget,
};
use alloc::vec::Vec;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use curve25519_dalek::scalar::Scalar;

pub enum HashSize {
	Two,
	Four,
}

pub struct AllocatedCoin {
	// private
	inv_value: AllocatedScalar,
	value: AllocatedScalar,
	rho: AllocatedScalar,
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	// public
	sn: Option<Scalar>,
	cm: Scalar,
}

impl AllocatedCoin {
	pub fn new_for_input(
		inv_value: AllocatedScalar,
		value: AllocatedScalar,
		rho: AllocatedScalar,
		r: AllocatedScalar,
		nullifier: AllocatedScalar,
		sn: Scalar,
		cm: Scalar,
	) -> Self {
		Self {
			inv_value,
			value,
			rho,
			r,
			nullifier,
			sn: Some(sn),
			cm,
		}
	}

	pub fn new_for_output(
		inv_value: AllocatedScalar,
		value: AllocatedScalar,
		rho: AllocatedScalar,
		r: AllocatedScalar,
		nullifier: AllocatedScalar,
		cm: Scalar,
	) -> Self {
		Self {
			inv_value,
			value,
			rho,
			r,
			nullifier,
			sn: None,
			cm,
		}
	}
}

pub struct Transaction {
	pub inputs: Vec<AllocatedCoin>,
	pub outputs: Vec<AllocatedCoin>,
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
				&self.inputs[i].sn.unwrap(),
			)?;

			Poseidon_hash_4_gadget(
				cs,
				[
					self.inputs[i].value,
					self.inputs[i].rho,
					self.inputs[i].r,
					self.inputs[i].nullifier,
				]
				.to_vec(),
				self.statics_4.clone(),
				poseidon_params,
				&self.inputs[i].cm,
			)?;
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
				&self.outputs[i].cm,
			)?;
		}

		Ok(())
	}

	fn non_zero_constraints<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), R1CSError> {
		for i in 0..2 {
			let elt = if i == 0 { &self.inputs } else { &self.outputs };
			for i in 0..elt.len() {
				// verify amounts are non-zero
				is_nonzero_gadget(cs, elt[i].value, elt[i].inv_value)?;
			}
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

pub fn transaction_preimage_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	transactions: Vec<Transaction>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	let mut sum_inputs = LinearCombination::from(Scalar::zero());
	let mut sum_outputs = LinearCombination::from(Scalar::zero());

	// each individual transaction has to be valid w.r.t its own inputs/outputs
	for i in 0..transactions.len() {
		let tx = &transactions[i];
		tx.hash_constraints(cs, poseidon_params)?;
		// ensure all amounts are non-zero
		tx.non_zero_constraints(cs)?;
		// TODO: ensure all amounts are less than MAX number

		sum_inputs = sum_inputs + tx.input_amount();
		sum_outputs = sum_outputs + tx.output_amount();
	}

	// total inputs and outputs should be equal and the difference should be
	// zero
	cs.constrain(sum_inputs - sum_outputs);
	Ok(())
}
