use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::LinearCombination;
use crate::utils::{AllocatedScalar};

#[cfg(test)]
pub mod tests;

/// if x == 0 then y = 0 else y = 1
/// if x != 0 then inv = x^-1 else inv = 0
/// x*(1-y) = 0
/// x*inv = y
/// The idea is described in the Pinocchio paper and i first saw it in https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/isnonzero.cpp

/// Enforces that x is 0.
pub fn is_zero_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	x: AllocatedScalar
) -> Result<(), R1CSError> {
	let y: u32 = 0;
	let inv: u32 = 0;

	let x_lc: LinearCombination = vec![(x.variable, Scalar::one())].iter().collect();
	let one_minus_y_lc: LinearCombination = vec![(Variable::One(), Scalar::from(1-y))].iter().collect();
	let y_lc: LinearCombination = vec![(Variable::One(), Scalar::from(y))].iter().collect();
	let inv_lc: LinearCombination = vec![(Variable::One(), Scalar::from(inv))].iter().collect();

	// x * (1-y) = 0
	let (_, _, o1) = cs.multiply(x_lc.clone(), one_minus_y_lc);
	cs.constrain(o1.into());

	// x * inv = y
	let (_, _, o2) = cs.multiply(x_lc, inv_lc);
	// Output wire should have value `y`
	cs.constrain(o2 - y_lc);

	Ok(())
}

/// Enforces that x is 0. Takes x and the inverse of x.
pub fn is_nonzero_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	x: AllocatedScalar,
	x_inv: AllocatedScalar,
) -> Result<(), R1CSError> {
	let x_lc = LinearCombination::from(x.variable);
	let y_lc = LinearCombination::from(Scalar::one());
	let one_minus_y_lc = LinearCombination::from(Variable::One()) - y_lc.clone();

	// x * (1-y) = 0
	let (_, _, o1) = cs.multiply(x_lc.clone(), one_minus_y_lc);
	cs.constrain(o1.into());

	// x * x_inv = y
	let inv_lc: LinearCombination = vec![(x_inv.variable, Scalar::one())].iter().collect();
	let (_, _, o2) = cs.multiply(x_lc.clone(), inv_lc.clone());
	// Output wire should have value `y`
	cs.constrain(o2 - y_lc);

	Ok(())
}
