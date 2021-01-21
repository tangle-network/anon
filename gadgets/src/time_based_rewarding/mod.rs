#[cfg(test)]
pub mod tests;

#[cfg(feature = "std")]
pub mod builder;

use crate::{
	fixed_deposit_tree::fixed_deposit_tree_verif_gadget,
	poseidon::{Poseidon_hash_2_constraints, Poseidon_hash_4_gadget},
	zero_nonzero::is_nonzero_gadget,
};
use alloc::vec::Vec;

use crate::poseidon::builder::Poseidon;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use curve25519_dalek::scalar::Scalar;

use crate::utils::AllocatedScalar;
use bulletproofs::r1cs::LinearCombination;

#[derive(Clone)]
pub struct AllocatedInputCoin {
	// private
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	leaf_cm_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	leaf_proof_nodes: Vec<AllocatedScalar>,
	// public
	sn: Scalar,
}

#[derive(Clone)]
pub struct AllocatedTimedDeposit {
	time_root: Scalar,
	multiplier: Scalar,
	current_time: Scalar,
	deposit_time: AllocatedScalar,
	deposit_time_cm_val: AllocatedScalar,
	deposit_time_index_bits: Vec<AllocatedScalar>,
	deposit_time_proof_nodes: Vec<AllocatedScalar>,
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
	pub depth: usize,
	pub deposit_root: Scalar,
	pub input: AllocatedInputCoin,
	pub timed_deposit: AllocatedTimedDeposit,
	pub outputs: Vec<AllocatedOutputCoin>,
	pub statics_2: Vec<AllocatedScalar>,
	pub statics_4: Vec<AllocatedScalar>,
}

impl Transaction {
	fn hash_constraints<CS: ConstraintSystem>(&self, cs: &mut CS, poseidon_params: &Poseidon) -> Result<(), R1CSError> {
		// check deposit in 2-elt commitment merkle tree
		fixed_deposit_tree_verif_gadget(
			cs,
			self.depth,
			&self.deposit_root,
			&self.input.sn,
			self.input.r,
			self.input.nullifier,
			self.input.leaf_cm_val,
			self.input.leaf_index_bits.clone(),
			self.input.leaf_proof_nodes.clone(),
			self.statics_2.clone(),
			&poseidon_params,
		)?;

		// check deposit
		let statics_lc: Vec<LinearCombination> = self.statics_2.iter().map(|s| s.variable.into()).collect();
		let computed_deposit_time_cm = Poseidon_hash_2_constraints::<CS>(
			cs,
			self.input.leaf_cm_val.variable.into(),
			self.timed_deposit.deposit_time.variable.into(),
			statics_lc.clone(),
			poseidon_params,
		)?;
		let deposit_time_cm_lc: LinearCombination = self.timed_deposit.deposit_time_cm_val.variable.into();
		cs.constrain(computed_deposit_time_cm - deposit_time_cm_lc);
		let deposit_time_length = self.timed_deposit.current_time - self.timed_deposit.deposit_time.variable;
		// check output commitment is properly formed and reward calculation is properly
		// formed
		let mut summed_outputs: LinearCombination = LinearCombination::from(Scalar::zero());
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
			// check if nonzero
			is_nonzero_gadget(cs, self.outputs[i].value, self.outputs[i].inv_value)?;
			// sum the outputs for later checking
			summed_outputs = summed_outputs + self.outputs[i].value.variable;
		}
		// TODO: Add better reward calculation
		// basic reward calculation
		let reward = self.timed_deposit.multiplier * (deposit_time_length);
		cs.constrain(summed_outputs - reward);
		Ok(())
	}
}

pub fn time_based_reward_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	txes: Vec<Transaction>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	for t in txes {
		t.hash_constraints(cs, poseidon_params)?;
	}
	Ok(())
}
