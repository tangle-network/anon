use crate::zero_nonzero::is_nonzero_gadget;
use crate::utils::AllocatedCompressedRistretto;
use crate::poseidon::Poseidon_hash_2_constraints;
use crate::poseidon::Poseidon_hash_4_constraints;
use crate::utils::constrain_lc_with_scalar;
use crate::poseidon::builder::Poseidon;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable, Prover, Verifier};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::LinearCombination;
use crate::utils::{AllocatedScalar};

pub enum HashSize {
	Two,
	Four,
}

pub struct Coin {
	// private
	inv_value: AllocatedScalar,
	value: AllocatedScalar,
	rho: AllocatedScalar,
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	// public
	sn: Scalar,
	cm: Scalar,
}

impl Coin {
	fn hash<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		h_type: HashSize,
		statics: Vec<LinearCombination>,
		inputs: Vec<LinearCombination>,
		params: &Poseidon
	) -> LinearCombination {
		assert!(inputs.len() == 4 || inputs.len() == 2);
		match h_type {
			HashSize::Two => Poseidon_hash_2_constraints::<CS>(
				cs,
				inputs[0].clone(),
				inputs[1].clone(),
				statics.clone(),
				params
			).unwrap(),
			HashSize::Four => Poseidon_hash_4_constraints::<CS>(
				cs,
				[ inputs[0].clone(), inputs[1].clone(), inputs[2].clone(), inputs[3].clone() ],
				statics.clone(),
				params
			).unwrap(),
		}
	}
}

pub struct Transaction {
	input: Coin,
	output: Coin,
}

pub fn transaction_preimage_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	transactions: Vec<Transaction>,
	statics: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon
) -> Result<(), R1CSError> {
	let mut sum_inputs = LinearCombination::from(Scalar::zero());
	let mut sum_outputs = LinearCombination::from(Scalar::zero());

	let statics: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();

	for i in 0..transactions.len() {
		let tx = &transactions[i];
		// ensure transactions are properly formatted
		for j in 0..2 {
			let elt = if j == 1 { &tx.input } else { &tx.output };

			let serial_no_hash = elt.hash(
				cs,
				HashSize::Two,
				statics.clone(),
				vec![
					LinearCombination::from(elt.r.variable),
					LinearCombination::from(elt.nullifier.variable),
				],
				poseidon_params,
			);

			constrain_lc_with_scalar::<CS>(cs, serial_no_hash, &elt.sn);
			// calculate coin commitment
			let input_hash = elt.hash(
				cs,
				HashSize::Four,
				statics.clone(),
				vec![
					LinearCombination::from(elt.value.variable),
					LinearCombination::from(elt.rho.variable),
					LinearCombination::from(elt.r.variable),
					LinearCombination::from(elt.nullifier.variable),
				],
				poseidon_params,
			);
			// constrain input coin commitment hash
			constrain_lc_with_scalar::<CS>(cs, input_hash, &elt.cm);
		}

		// verify amounts are non-zero
		is_nonzero_gadget(cs, tx.output.value, tx.output.inv_value)?;

		sum_inputs = sum_inputs + tx.input.value.variable;
		sum_outputs = sum_outputs + tx.output.value.variable;
	}

	// inputs and outputs should be equal
	cs.constrain(sum_inputs - sum_outputs);
	Ok(())
}
